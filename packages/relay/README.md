# @dshn/relay

The server half of [dshn](../../README.md). It sits on your machine behind
Cloudflare, terminates public `*.ds.hn` requests, gates them with a login, and
bridges each one over a single WebSocket to the matching device's `dshn-agent`.

The relay never speaks dsh's protocol — it moves bytes. The one thing it enforces
is authentication, because the far end is a shell.

## Modules

- `server.ts` — the bridge: public HTTP + upgrade handling, subdomain routing,
  request/WebSocket multiplexing over each agent's control socket, agent
  registration and heartbeat sweep.
- `claims.ts` — the claim store: trust-on-first-use subdomain ownership. The
  first agent to present a free subdomain claims it with a scrypt-hashed
  password; later connects and browser logins verify against it. Persisted with
  atomic writes. The seam an account-backed control plane later replaces.
- `auth.ts` — the login page and the HMAC-signed, host-scoped session cookie
  (constant-time checks); the password itself is verified against `claims.ts`.
- `index.ts` — env-driven entry point; refuses to start without a cookie secret.

## Run

```sh
DSHN_COOKIE_SECRET=$(openssl rand -hex 32) DSHN_CLAIMS=./claims.json \
  node lib/index.js
```

| env | meaning | default |
|---|---|---|
| `DSHN_COOKIE_SECRET` | HMAC secret for session cookies (**required**) | — |
| `DSHN_APEX` | tunnel apex | `ds.hn` |
| `DSHN_RELAY_PORT` | plain HTTP port behind Cloudflare | `8787` |
| `DSHN_CLAIMS` | path to the claims JSON (auto-created) | `./claims.json` |
| `DSHN_TLS_CERT`/`DSHN_TLS_KEY` | serve HTTPS directly (CF "Full") | — |

## Deploying behind Cloudflare

Proxy `*.ds.hn` (orange cloud) to this origin. Then lock the origin down so the
login gate can't be bypassed by hitting the origin IP directly: firewall to
[Cloudflare's IP ranges](https://www.cloudflare.com/ips/) and enable
Authenticated Origin Pulls. Cloudflare's ~100s WebSocket idle timeout is covered
by the built-in 25s heartbeat.
