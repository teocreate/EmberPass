# Dynamic Pass

A self-hosted access pass that lives on a phone. The holder opens a PWA and sees a
barcode that is signed, expires in 30 seconds and works exactly once. Staff open a
second PWA, scan it with the camera, and get a full-screen allow or deny.

Node.js with no framework, PostgreSQL for storage, vanilla JS on both front ends.
The QR and PDF417 encoders are implemented in this repository — the only bundled
third-party code is a WebAssembly decoder used by the staff app on browsers without
`BarcodeDetector`.

```
   Holder                                        Staff
   ──────                                        ─────
   PWA  public/                                  PWA  public/staff/
     │                                             ▲
     │ POST /api/pass/token   (every 12 s)         │ camera scan
     ▼                                             │
   Backend  server/  ──── Ed25519 signature ──► barcode on screen
     │                    88 bytes → 118 chars     │
     │                                             │ POST /api/staff/verify
     ▼                                             ▼
   PostgreSQL   users · passes · sessions · pass_scans (UNIQUE jti)
```

## What it does

- **Accounts.** Email + password with scrypt hashing, httpOnly session cookies,
  rate-limited sign-in — or single sign-on against any OIDC provider.
- **Rotating pass.** The server issues a token signed with Ed25519 that lives 30
  seconds; the holder app redraws the code every 12. A screenshot is useless within
  half a minute.
- **Single use.** Each token carries a random `jti` written to `pass_scans` under a
  UNIQUE index. A second scan of the same code is denied as `already_used` and shows
  where and when it was first used.
- **Offline verification.** The public key is served as a JWK, so a staff device with
  no network verifies format, expiry and signature locally through WebCrypto and
  queues the scan for the server.
- **Two formats.** QR by default. PDF417, for turnstiles with laser scanners, is
  enabled with `PASS_PDF417=true`; while it is off, its encoder is never downloaded
  and the scanner will not accept one.

## Quick start

```bash
npm install
cp .env.example .env        # set DATABASE_URL
npm run seed                # demo accounts
npm start
```

- `http://localhost:3000/` — holder app, `holder@example.com`
- `http://localhost:3000/staff/` — staff app, `staff@example.com`
- password for both: `demo-password-123`

The schema is applied on start, idempotently. The Ed25519 signing key is generated on
first run into `data/signing-key.json`; back it up and keep it out of version control.

Without `DATABASE_URL` the server runs on an in-memory store — useful for a look
around, but everything is lost on restart.

The camera needs a secure context: `https://` or `http://localhost`. A LAN address
like `http://192.168.x.x` will not get camera permission.

## Configuration

Every variable has a working default except `DATABASE_URL`. See `.env.example` for
the full list.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | — | PostgreSQL connection string; in-memory store when unset |
| `SIGNING_KEY` | — | Ed25519 key as base64 (`npm run genkey`); required on read-only filesystems |
| `SIGNING_KEY_FILE` | `data/signing-key.json` | Where the key is stored otherwise |
| `PASS_TOKEN_TTL` | `30` | Token lifetime, seconds |
| `PASS_TOKEN_REFRESH` | `12` | How often the holder app requests a new code |
| `SESSION_TTL` | `43200` | Session lifetime, seconds |
| `SECURE_COOKIES` | `false` | `Secure` flag on session cookies; on by default on serverless |
| `CLOCK_SKEW` | `5` | Tolerance between phone, gate and server, seconds |
| `PASS_PDF417` | `false` | Offer PDF417 alongside QR |
| `REGISTRATION_OPEN` | `true` | Public sign-up |
| `CHECK_EMAIL_MX` | `true` | Require the address's domain to accept mail |
| `DATABASE_SSL` | `auto` | `auto`, `require`, `no-verify`, `verify-full`, `disable` |
| `DATABASE_CA_CERT` | — | Provider CA as PEM or base64, to keep verification on |
| `DATABASE_POOL_MAX` | `10` (2 on serverless) | Connection pool size |
| `AUTH_MODE` | `local` | `local`, `oidc`, or `both` |
| `OIDC_*` | — | Single sign-on, see below |

## Token format

```
byte  0      format version (1)
byte  1      signing key id
bytes 2-5    pass id      (uint32 BE)
bytes 6-9    holder id    (uint32 BE)
bytes 10-13  issued at    (uint32 BE, unix seconds)
bytes 14-15  lifetime     (uint16 BE, seconds)
bytes 16-23  jti          (8 random bytes, replay protection)
bytes 24-87  Ed25519 signature over bytes 0-23
```

88 bytes → 118 base64url characters, which fits a version 7 QR symbol. The signature
is asymmetric on purpose: `GET /api/verify/key` hands out the public key so anything
downstream — a turnstile controller, another service, an offline device — can verify a
pass without talking to this server and without holding a secret.

## API

| Method | Path | Who | Purpose |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | anyone | sign up, issues a pass |
| POST | `/api/auth/login` | anyone | sign in, sets the session cookie |
| POST | `/api/auth/logout` | anyone | sign out |
| POST | `/api/auth/check-email` | anyone | validate an address before submit |
| GET | `/api/auth/oidc/start` | anyone | begin single sign-on |
| GET | `/api/auth/oidc/callback` | anyone | provider return, issues a session |
| GET | `/api/auth/me` | anyone | current session |
| GET | `/api/pass` | holder | pass and recent entries |
| POST | `/api/pass/token` | holder | issue a short-lived token |
| GET | `/api/pass/history` | holder | entry history |
| GET | `/api/verify/key` | anyone | public key as JWK |
| POST | `/api/staff/verify` | staff | verify a scanned code |
| GET | `/api/staff/scans` | staff | scan log |

`POST /api/staff/verify` answers with `{ granted, reason, holder, pass }`. Denials:

| Reason | Meaning |
| --- | --- |
| `malformed`, `unsupported_version` | not a pass token |
| `bad_signature` | signature does not match — forged or signed with another key |
| `unknown_key` | signed with a key id this server does not know |
| `expired`, `not_yet_valid` | outside the token's lifetime |
| `already_used` | this `jti` was scanned before; the response names where and when |
| `pass_suspended`, `pass_revoked`, `pass_expired`, `pass_not_active_yet` | pass status |
| `holder_suspended` | holder blocked |
| `unknown_pass`, `unknown_holder`, `pass_mismatch` | pass or holder not found |

Roles are `user`, `staff` and `admin`. Local registration always creates a `user`;
elevate through `scripts/seed.js`, SQL, or provider groups when SSO is on.

## Using the pieces separately

The parts are deliberately decoupled, so a project can adopt one without the rest.

- **Barcode encoders.** `public/lib/qrcode.js` and `public/lib/pdf417.js` are
  dependency-free ES modules: `encodeQR` / `encodePDF417` turn a string into a symbol, and
  `qrToSvg` / `pdf417ToSvg` draw it. They run
  in a browser or in Node and are not tied to anything else here.
- **Verifying passes elsewhere.** Fetch the JWK from `/api/verify/key` and check the
  88-byte token against the layout above. No shared secret, no call back to this
  service. `public/staff/lib/passtoken.js` is a working WebCrypto implementation.
- **Issuing passes from another system.** `server/lib/token.js` exposes `PassSigner`
  and `verifyPassToken`; the pass and holder ids are plain integers, so an existing
  directory (HR system, CRM, 1C) can own identity while this service owns the code.
- **Identity.** With `AUTH_MODE=oidc` this app keeps no passwords at all — accounts,
  groups and sign-out live in the provider.
- **Storage.** `server/db/pg.js` and `server/db/memory.js` implement the same
  repository interface; a third backend only has to match it.

## Single sign-on

An OIDC relying party built on `node:crypto` and `fetch` (`server/lib/oidc.js`):
authorization code with PKCE, ID token verified against the provider's JWKS, `state`
and `nonce` in a short-lived httpOnly cookie, RP-initiated logout. Tested against
VoidAuth; any conformant provider works.

```bash
OIDC_ISSUER=https://auth.example.com/oidc     # VoidAuth: APP_URL + /oidc
OIDC_CLIENT_ID=pass-app
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=https://pass.example.com/api/auth/oidc/callback
OIDC_STAFF_GROUPS=pass-staff
OIDC_ADMIN_GROUPS=pass-admins
```

Endpoints are read from `<issuer>/.well-known/openid-configuration`. `OIDC_REDIRECT_URI`
must match the provider's redirect URL character for character.

Roles are recomputed from the `groups` claim on every sign-in, so removing someone from
`pass-staff` removes their scanner access at their next login. Accounts are linked by
`sub` first, then by email — and only when the provider reports the address as
verified, otherwise the login is refused with `email_conflict`. Access and refresh
tokens are never stored; after a successful login the app issues its own session
cookie so the gate does not depend on the provider being reachable.

`compose.voidauth.yml` brings up a provider and its database for local work.

## Database

Any PostgreSQL instance. Four tables in the `public` schema — `users`, `passes`,
`sessions`, `pass_scans` — created on first start from `server/db/schema.sql`.

```bash
DATABASE_URL="postgres://..." npm run dbcheck
```

prints the host, user, TLS mode and server version, or names the reason it failed.

`DATABASE_SSL=auto` enables TLS for every host except localhost. On providers that
present a private CA (Supabase among them), supply `DATABASE_CA_CERT` to keep chain
verification on, or set `DATABASE_SSL=no-verify` to encrypt without verifying.

On Supabase the schema additionally revokes grants from the `anon` and `authenticated`
roles and enables row level security on its four tables, so password hashes and the
entry log are not readable through PostgREST with the project's public key. The block
is skipped where those roles do not exist.

## Deployment

**Node.** `npm start` behind any reverse proxy that terminates TLS. Set
`SECURE_COOKIES=true`.

**Render.** `render.yaml` is a ready blueprint. Set `DATABASE_URL` and `SIGNING_KEY` —
the filesystem is wiped on every deploy, so a generated key would change under the
passes already in circulation.

**Vercel or other serverless.** `api/index.js` is the entry point; `vercel.json` serves
`public/` statically and routes `/api/*` to the function. No build step. `SIGNING_KEY`
is required, since the filesystem is read-only.

Without a database and a key the app still starts, on the in-memory store with a
throwaway key, and shows a "demo mode" banner.

## Layout

```
api/index.js          serverless entry point
render.yaml           Render blueprint
compose.voidauth.yml  local OIDC provider
server/
  index.js            router, static files, security headers
  config.js           environment, signing key
  lib/token.js        pass token issue and verify
  lib/oidc.js         OIDC client: discovery, PKCE, JWKS
  lib/crypto.js       scrypt, random tokens, constant-time compare
  lib/email.js        address validation: syntax, reserved domains, MX
  lib/http.js         json, cookies, static, errors
  lib/ratelimit.js    request throttling
  db/schema.sql       tables
  db/pg.js            PostgreSQL repository
  db/memory.js        the same interface in memory
  routes/             auth, oidc, pass, staff
public/
  lib/qrcode.js       QR encoder, versions 1-40, levels L/M/Q/H
  lib/pdf417.js       PDF417 encoder, text/byte modes, EC 0-8
  lib/render.js       SVG rendering
  staff/              staff app, including the vendored zxing-wasm decoder
scripts/              seed, genkey, dbcheck
test/                 node:test
```

## Tests

```bash
npm test
```

71 tests, no database required — they run against the in-memory store. Coverage:
encoders against reference vectors, tokens (signature, expiry, every byte flipped,
foreign key), the API path from registration through issue, entry, replay and denial,
roles, rate limits, email validation, the serverless entry point, and single sign-on
against a stub OIDC provider in `test/helpers/oidc-provider.js`.

The QR encoder was validated module-for-module against `python-qrcode` across 168
combinations of version, error correction level and mask; PDF417 symbols were decoded
back with `zxing-cpp`.

## Security

In place: scrypt password hashing with `timingSafeEqual` comparison; session tokens
stored only as SHA-256; Ed25519 pass tokens that expire in 30 seconds and work once;
the private key never leaves the server; rate limits on sign-in, registration, token
issue and scanning; CSP without `unsafe-inline`, `X-Frame-Options: DENY`, `nosniff`;
the service worker never caches API responses.

Not in place: signing key rotation (the `kid` byte is reserved for it), second factor,
email confirmation, a shared rate-limit store for multi-instance deployments, and an
admin UI — suspending a pass is a SQL update. `SECURE_COOKIES=true` and HTTPS are
required in production.

## Third-party code

`public/staff/lib/vendor/zxing/` — zxing-wasm 3.1.3, MIT, used to read barcodes on
browsers without `BarcodeDetector` (Safari). Everything else is written here on the
Node standard library, with `pg` as the only runtime dependency.
