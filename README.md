# nginx-webauthn

Passkey authentication (Face ID, Touch ID, Windows Hello, YubiKey) in front of
any web app, via nginx `auth_request`. One Python file, three dependencies, no
state on disk — credentials are read from environment variables.

## How it works

For every request, nginx issues a subrequest to `/auth/check` to ask whether the
session is valid. If it isn't, the service returns 401 and nginx redirects to
`/auth/login`, where WebAuthn verification happens. The protected application
never sees any of this and needs no changes.

nginx cannot do Face ID itself, and never could — biometrics stay on the device.
The private key lives in the Secure Enclave (or iCloud Keychain) and Face ID only
unlocks it. The server only ever receives a cryptographic signature.

## Requirements

- a public domain and a **valid certificate** (Safari on iOS rejects self-signed
  certs for WebAuthn)
- nginx with the `auth_request` module (`nginx -V | grep auth_request`)
- Docker Compose

## 1. Build

Put `app.py`, `requirements.txt` and `Dockerfile` into a subdirectory, for
example `./webauthn`.

## 2. docker-compose.yml

```yaml
services:
  webauthn:
    build: ./webauthn
    container_name: webauthn
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      - COOKIE_LIFETIME=7d
      # Commented out at first - filled in after registering a key (step 4)
      # - "REALM_www.example.com=iPhone|<credId>|<publicKey>"
```

No `ports:` — the container should only be reachable from the outside through the
proxy. If your proxy lives in a different compose project, put both services on a
shared network.

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `REALM_<hostname>` | — | Credentials for that domain, see below |
| `COOKIE_LIFETIME` | `1d` | `30s`, `15m`, `12h`, `7d`, or `session` |
| `PORT` | `8080` | Port the service listens on |

`COOKIE_LIFETIME=session` issues a cookie without `MaxAge`, so it is dropped when
the browser closes. A 30 day cap still applies server-side so tokens don't
accumulate in memory.

An unparseable value makes the container exit at startup with an explanation,
rather than quietly falling back to a default.

Sessions always slide: `COOKIE_LIFETIME` acts as an idle timeout that is refreshed
on every request, with a hard 30 day ceiling. One caveat — nginx does not forward
`Set-Cookie` from an `auth_request` subrequest to the client, so sliding extends
the server-side session only, never the cookie expiry. Set `COOKIE_LIFETIME` to
the span the cookie should survive; the sliding behaviour then applies within that
window.

### Credential format

```
REALM_<hostname>=<name>|<credId>|<publicKey>;<name>|<credId>|<publicKey>
```

- the variable key is the **hostname without `https://` and without a port**
- entries are separated by semicolons, fields by pipes (a pipe never appears in
  base64, so it cannot collide with a key)
- the name is for you — it shows up in the log at startup and on every sign-in
- one variable per protected domain

Example with two domains and three devices:

```yaml
    environment:
      - "REALM_www.example.com=iPhone|BASE64ID|BASE64KEY;MacBook|BASE64ID|BASE64KEY"
      - "REALM_code.example.com=iPhone|BASE64ID|BASE64KEY"
```

## 3. nginx

Protected domains get their own `server` block. The rest of your configuration
stays as it is.

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name www.example.com code.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # WebAuthn service: /auth/login, /auth/check, /auth/logout,
    # /auth/register and the challenge endpoints
    location /auth {
        set $webauthn http://webauthn:8080;
        proxy_pass $webauthn;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Do NOT override the Origin header - the service compares it
        # against clientDataJSON from the browser
    }

    location / {
        auth_request /auth/check;
        error_page 401 = @login;

        proxy_pass http://app:8080;         # your upstream here
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }

    location @login {
        return 302 https://$host/auth/login?rd=$request_uri;
    }
}
```

For websockets, this belongs above the `server` blocks (in the `http` context):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

### `proxy_pass` with a variable

Without a variable, nginx resolves `webauthn` to an IP once at startup. If the
container isn't running, nginx refuses to start at all (`host not found in
upstream`); if it restarts with a different IP, nginx keeps hitting the old one
and you get 502s. Hence the `set $webauthn`. That requires a resolver in the
`http` context:

```nginx
resolver 127.0.0.11 valid=30s ipv6=off;
```

`127.0.0.11` is Docker's embedded DNS.

### Watch out for `default_server`

If you already have a catch-all `server` block with no `server_name`, it only
worked because it came first on port 443. Adding the block above makes the new
one the default server, and **every other domain will fall into authentication.**
Mark the catch-all explicitly:

```nginx
server {
    listen 443 ssl default_server;
    server_name _;
    ...
}
```

`default_server` may only appear on one block per port.

### Watch out for `proxy_intercept_errors`

If `proxy_intercept_errors on;` is combined with `error_page 401 /401.html;`
anywhere in your config, it must not apply to `location /auth`. The service uses
401 as part of the protocol, and nginx would replace the response with HTML.

### Watch out for caching

Responses from `/auth` must not be cached. Don't enable `proxy_cache` in that
block.

## 4. Registering a key

```bash
docker compose up -d webauthn
docker compose exec proxy nginx -t && docker compose exec proxy nginx -s reload
```

On the device you want to sign in with, open:

```
https://www.example.com/auth/register?name=iPhone
```

Face ID runs and the page prints a string like `iPhone|<credId>|<publicKey>`. Put
it into `REALM_www.example.com` in your compose file and recreate the service:

```bash
docker compose up -d webauthn
```

`docker compose restart` is **not enough** — it won't pick up new environment
variables, because it only stops and starts the same container. Verify with:

```bash
docker compose exec webauthn env | grep REALM
docker compose logs webauthn | tail -5
```

At startup the log prints what it loaded:

```
realm www.example.com: iPhone, MacBook
```

### Additional devices

Same procedure with a different `?name=`. Append the resulting string to the
existing value with a semicolon. On Apple devices passkeys sync through iCloud
Keychain, so one registration covers an iPhone and a Mac on the same Apple ID.

### Removing a device

Delete its entry from the variable and run `docker compose up -d webauthn`. The
names in the log exist precisely so you don't have to guess which base64 blob
belonged to the lost phone.

## Limitations

- **Tokens live in memory.** Restarting the container signs everyone out. That is
  expected behaviour, not a misconfiguration.
- **Registration is not verified.** The attestation object is never sent to the
  server; the browser prints the public key and you paste it into the config.
  Trust rests on you having access to the compose file.
- **Sliding only extends the server-side session.** nginx does not forward
  `Set-Cookie` from an `auth_request` subrequest, so the cookie expiry cannot be
  pushed out.
- **The RP ID is the hostname.** A passkey only works on the domain it was
  registered on. Each protected domain needs its own registration.
- **APIs and non-browser clients** can't do WebAuthn. They need a separate
  `location` without `auth_request`, or a different mechanism entirely.
- This is not an IdP. No users, groups, permissions or SSO. If you need those,
  look at [Authelia](https://www.authelia.com) or
  [Pocket ID](https://github.com/pocket-id/pocket-id).

## Security checks

On verification the service checks:

- the signature against the stored public key (ES256, RS256 or Ed25519, via the
  `cryptography` library)
- `type == "webauthn.get"` in clientDataJSON
- the challenge in constant time; challenges are single use and expire after
  5 minutes
- `origin` against the Origin header
- `rpIdHash` in authenticatorData against the hostname
- the User Present and User Verified flags — without them
  `userVerification: required` would guarantee nothing

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Redirect loop on `/auth/login` | `location /auth` is missing or sits under `auth_request` |
| "No key is configured for this domain" | `REALM_<hostname>` missing, or the hostname includes a port |
| 502 on `/auth` | container not running, or `proxy_pass` without a variable and resolver |
| Face ID never appears | no valid HTTPS, or you're connecting by IP instead of hostname |
| "verification failed (401)" | wrong `publicKey` in the config, or the challenge expired |
| Auth fires on unrelated domains | catch-all block is missing `default_server` |
