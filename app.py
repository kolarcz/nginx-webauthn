"""
WebAuthn / passkey authentication for nginx auth_request.

One file, three dependencies, no state on disk - credentials are read from
environment variables.

Configuration:
  REALM_www.example.com=iPhone|<credId>|<publicKey>;MacBook|<credId>|<publicKey>
  COOKIE_LIFETIME=7d         # s / m / h / d, or "session"
  PORT=8080

Register a key:  https://<host>/auth/register?name=iPhone
"""

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from flask import Flask, Response, jsonify, make_response, request

COOKIE_TOKEN = "token"
COOKIE_CHALLENGE = "challenge_id"
CHALLENGE_TTL = 300
HARD_CAP = 30 * 86400

app = Flask(__name__)


# --- configuration ----------------------------------------------------------

def parse_lifetime(value):
    """'session' -> None, otherwise 30s / 15m / 12h / 7d -> seconds."""
    value = value.strip()
    if value.lower() == "session":
        return None

    m = re.fullmatch(r"(\d+)\s*([smhd])", value, re.IGNORECASE)
    if not m:
        raise SystemExit(
            f"COOKIE_LIFETIME='{value}' could not be parsed. "
            "Use something like 30m, 12h, 7d or session."
        )

    n, unit = int(m.group(1)), m.group(2).lower()
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


@dataclass(frozen=True)
class Credential:
    name: str
    cred_id: str
    public_key: str


def parse_credentials(host, raw):
    """'iPhone|<credId>|<publicKey>;MacBook|<credId>|<publicKey>'"""
    creds = []

    for entry in (e.strip() for e in raw.split(";")):
        if not entry:
            continue

        parts = [p.strip() for p in entry.split("|")]
        if len(parts) != 3 or not parts[1] or not parts[2]:
            raise SystemExit(
                f"REALM_{host}: '{entry}' does not match <name>|<credId>|<publicKey>"
            )

        name = parts[0] or f"credential-{len(creds) + 1}"
        creds.append(Credential(name, parts[1], parts[2]))

    return creds


def load_realms():
    """REALM_<hostname> -> list of credentials."""
    realms = {}
    for key, value in os.environ.items():
        if key.startswith("REALM_"):
            host = key[len("REALM_"):].lower()
            realms[host] = parse_credentials(host, value)
    return realms


# None means the cookie lives until the browser is closed
COOKIE_LIFETIME = parse_lifetime(os.environ.get("COOKIE_LIFETIME", "1d"))
# Idle window. Sessions always slide, so this is a timeout on inactivity.
IDLE_WINDOW = COOKIE_LIFETIME if COOKIE_LIFETIME is not None else HARD_CAP
REALMS = load_realms()


# --- in-memory state --------------------------------------------------------

@dataclass
class Session:
    credential: str
    host: str
    expiry: float
    hard_expiry: float


_lock = threading.Lock()
_tokens: dict[str, Session] = {}
_challenges: dict[str, tuple[bytes, float]] = {}


def new_challenge(response):
    challenge = secrets.token_bytes(32)
    cid = secrets.token_hex(16)

    with _lock:
        now = time.time()
        for k, (_, exp) in list(_challenges.items()):
            if now >= exp:
                del _challenges[k]
        _challenges[cid] = (challenge, now + CHALLENGE_TTL)

    response.set_cookie(
        COOKIE_CHALLENGE, cid,
        httponly=True, secure=True, samesite="Lax", path="/auth",
    )
    return challenge


def take_challenge(cid):
    """Challenges are single use."""
    if not cid:
        return None
    with _lock:
        entry = _challenges.pop(cid, None)
    if not entry:
        return None
    challenge, expiry = entry
    return challenge if time.time() < expiry else None


# --- helpers ----------------------------------------------------------------

def b64d(value):
    """Accepts standard base64 and base64url, padded or not."""
    value = value.replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4))


def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def origin_host():
    """Returns (origin, host) from the Origin header, or (None, None)."""
    origin = request.headers.get("Origin", "")
    if not origin.startswith("https://"):
        return None, None
    host = origin[len("https://"):].split("/")[0]
    return origin, host.lower()


def sanitize_name(name):
    if not name:
        return "unnamed"
    clean = "".join(c for c in name if c.isalnum() or c in "-_. ").strip()
    return clean[:32] or "unnamed"


def safe_rd(value):
    """Guard against open redirects - relative paths only."""
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/"


def client_data_ok(encoded, challenge, origin):
    try:
        data = json.loads(b64d(encoded))
    except (ValueError, TypeError):
        return False

    if data.get("type") != "webauthn.get":
        return False
    if not secrets.compare_digest(data.get("challenge", ""), b64url(challenge)):
        return False
    return data.get("origin") == origin


def auth_data_ok(auth_data, host):
    """Verify rpIdHash and the UP/UV flags.

    Without the rpIdHash check a signature from another domain would pass;
    without the UV flag, userVerification: required would guarantee nothing.
    """
    if len(auth_data) < 37:
        return False
    if not secrets.compare_digest(auth_data[:32], hashlib.sha256(host.encode()).digest()):
        return False

    flags = auth_data[32]
    user_present = bool(flags & 0x01)
    user_verified = bool(flags & 0x04)
    return user_present and user_verified


def signature_ok(public_key_b64, signature, signed_data):
    try:
        key = load_der_public_key(b64d(public_key_b64))

        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed_data)
        else:
            return False

        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- endpoints --------------------------------------------------------------

@app.get("/auth/check")
def check():
    token = request.cookies.get(COOKIE_TOKEN)
    now = time.time()

    with _lock:
        session = _tokens.get(token) if token else None

        if not session or now >= session.expiry or now >= session.hard_expiry:
            _tokens.pop(token, None)
            return "", 401

        # Note: nginx does not forward Set-Cookie from an auth_request
        # subrequest to the client, so sliding extends the server-side
        # session only, never the cookie expiry.
        session.expiry = min(now + IDLE_WINDOW, session.hard_expiry)

    return "", 200


@app.get("/auth/logout")
def logout():
    token = request.cookies.get(COOKIE_TOKEN)
    with _lock:
        _tokens.pop(token, None)

    response = make_response("", 302)
    response.headers["Location"] = "/"
    response.delete_cookie(COOKIE_TOKEN, path="/")
    return response


@app.get("/auth/login")
def login():
    rd = safe_rd(request.args.get("rd"))
    return Response(PAGE.format(mode="login", name="", rd=rd), mimetype="text/html")


@app.get("/auth/register")
def register():
    name = sanitize_name(request.args.get("name"))
    return Response(PAGE.format(mode="register", name=name, rd="/"), mimetype="text/html")


@app.post("/auth/get_challenge_for_new_key")
def challenge_new():
    origin, host = origin_host()
    if not host:
        return "", 400

    name = sanitize_name(request.args.get("name"))
    response = jsonify({})
    challenge = new_challenge(response)

    response.set_data(json.dumps({
        "publicKey": {
            "challenge": base64.b64encode(challenge).decode(),
            "rp": {"id": host, "name": "nginx auth"},
            # Random user.id, otherwise the authenticator replaces the
            # existing passkey instead of adding a second one.
            "user": {
                "id": base64.b64encode(secrets.token_bytes(16)).decode(),
                "name": name,
                "displayName": name,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},     # ES256
                {"type": "public-key", "alg": -8},     # Ed25519
                {"type": "public-key", "alg": -257},   # RS256
            ],
            "authenticatorSelection": {
                "userVerification": "required",        # forces Face ID / Touch ID / PIN
                "residentKey": "preferred",
            },
            "timeout": 60000,
        }
    }))
    return response


@app.post("/auth/get_challenge_for_existing_key")
def challenge_existing():
    origin, host = origin_host()
    if not host:
        return "", 400

    creds = REALMS.get(host)
    if not creds:
        return jsonify({"error": "not_configured"})

    response = jsonify({})
    challenge = new_challenge(response)

    response.set_data(json.dumps({
        "publicKey": {
            "challenge": base64.b64encode(challenge).decode(),
            "rpId": host,
            "allowCredentials": [
                {"type": "public-key", "id": c.cred_id} for c in creds
            ],
            "userVerification": "required",
            "timeout": 60000,
        }
    }))
    return response


@app.post("/auth/complete_challenge_for_existing_key")
def complete():
    origin, host = origin_host()
    if not host:
        return "", 400

    creds = REALMS.get(host)
    if not creds:
        return "", 401

    challenge = take_challenge(request.cookies.get(COOKIE_CHALLENGE))
    if not challenge:
        return "", 401

    data = request.get_json(silent=True) or {}
    try:
        cred_id = data["id"]
        client_data_json = data["clientDataJSON"]
        auth_data = b64d(data["authenticatorData"])
        signature = b64d(data["signature"])
    except (KeyError, ValueError, TypeError):
        return "", 400

    match = next((c for c in creds if secrets.compare_digest(c.cred_id, cred_id)), None)
    if not match:
        return "", 401

    if not client_data_ok(client_data_json, challenge, origin):
        return "", 401

    if not auth_data_ok(auth_data, host):
        return "", 401

    signed = auth_data + hashlib.sha256(b64d(client_data_json)).digest()
    if not signature_ok(match.public_key, signature, signed):
        return "", 401

    now = time.time()
    token = secrets.token_urlsafe(32)

    with _lock:
        for k, s in list(_tokens.items()):
            if now >= s.expiry or now >= s.hard_expiry:
                del _tokens[k]

        _tokens[token] = Session(
            credential=match.name,
            host=host,
            expiry=now + IDLE_WINDOW,
            hard_expiry=now + HARD_CAP,
        )

    app.logger.info("sign-in: %s on %s", match.name, host)

    response = make_response("", 200)
    response.set_cookie(
        COOKIE_TOKEN, token,
        # No max_age means a session cookie, dropped when the browser closes
        max_age=COOKIE_LIFETIME,
        httponly=True, secure=True, samesite="Lax", path="/",
    )
    response.delete_cookie(COOKIE_CHALLENGE, path="/auth")
    return response


# --- frontend ---------------------------------------------------------------

PAGE = """<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1">
<body style="font-family:system-ui;max-width:40rem;margin:20vh auto;padding:0 1.5rem">
<div id="out" data-mode="{mode}" data-name="{name}" data-rd="{rd}">Waiting for authenticator...</div>
<script>
const out = document.getElementById('out');
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function register() {{
  const name = out.dataset.name;
  const res = await fetch('/auth/get_challenge_for_new_key?name=' + encodeURIComponent(name),
    {{method: 'POST'}});
  const opts = await res.json();
  opts.publicKey.challenge = unb64(opts.publicKey.challenge);
  opts.publicKey.user.id = unb64(opts.publicKey.user.id);

  const cred = await navigator.credentials.create(opts);
  const line = name + '|' + b64(cred.rawId) + '|' + b64(cred.response.getPublicKey());

  out.innerHTML = 'Append this to REALM_' + location.host
    + ' with a semicolon, then recreate the container:'
    + '<textarea style="width:100%;height:7rem;margin-top:1rem" onclick="this.select()">'
    + line + '</textarea>';
}}

async function login() {{
  const res = await fetch('/auth/get_challenge_for_existing_key', {{method: 'POST'}});
  const opts = await res.json();

  if (opts.error === 'not_configured') {{
    out.innerHTML = 'No key is configured for this domain. '
      + '<a href="/auth/register?name=device">Register one</a>.';
    return;
  }}

  opts.publicKey.challenge = unb64(opts.publicKey.challenge);
  opts.publicKey.allowCredentials.forEach(c => c.id = unb64(c.id));

  const assertion = await navigator.credentials.get(opts);
  const done = await fetch('/auth/complete_challenge_for_existing_key', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{
      id: b64(assertion.rawId),
      authenticatorData: b64(assertion.response.authenticatorData),
      clientDataJSON: b64(assertion.response.clientDataJSON),
      signature: b64(assertion.response.signature),
    }}),
  }});

  if (!done.ok) throw new Error('verification failed (' + done.status + ')');
  location.href = out.dataset.rd;
}}

(async () => {{
  try {{
    await (out.dataset.mode === 'register' ? register() : login());
  }} catch (e) {{
    out.innerHTML = 'Error: ' + e
      + '<br><br><a href="' + location.pathname + location.search + '">Try again</a>';
  }}
}})();
</script>
</body>
"""


if __name__ == "__main__":
    from waitress import serve

    for host, creds in REALMS.items():
        app.logger.warning("realm %s: %s", host, ", ".join(c.name for c in creds) or "(no keys)")
    if not REALMS:
        app.logger.warning("no REALM_* variables set - every request will return 401")

    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), threads=4)
