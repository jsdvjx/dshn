# dshn — DeepSeek Harness Network

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![dsh-plugin](https://img.shields.io/badge/dsh-plugin-6aa84f.svg)](https://awesome-dsh-plugin.com/)

Expose a locally-running **DeepSeek Harness** (`dsh`) web UI to the public
internet under a `*.ds.hn` subdomain, gated by a login. Install the plugin, open
dsh locally, and a form in Settings asks for a **subdomain prefix** and a
**password** — those two *are* the credential. No tokens, no env vars, no
provisioning. An optional **end-to-end password** encrypts the traffic so even
the relay operator sees only ciphertext.

> ⚠️ **dsh ships bash and filesystem tools. A publicly reachable dsh UI is a
> remote shell.** The relay's login gate is not optional; do not disable it. Use
> a strong password, and prefer end-to-end encryption for anything sensitive.

## Features

- **Zero-config credential.** `(subdomain, password)` set once in dsh's Settings
  → the plugin claims the subdomain and connects. Persists to dsh's own
  `~/.dsh/settings.yaml` and reconnects on restart.
- **Trust-on-first-use claim.** The first agent to present a free subdomain sets
  its password (scrypt-hashed on the relay). Later connects and every browser
  login must match it — squatting-protected.
- **Optional end-to-end encryption** (off by default). A *separate* e2e password,
  never sent to the relay, encrypts `/api` bodies and the event stream:
  PBKDF2-SHA256 (210k) → AES-256-GCM. Visitors enter it once in the browser; it
  can be remembered per-device in `localStorage` (never transmitted).
- **Native UI.** Config lives in dsh's own Settings ("公网转发" / *Public
  forwarding*); a footer row shows live latency and links to it.
- **Self-hosted data plane.** Traffic rides Cloudflare's edge to *your* server —
  no per-user Cloudflare account, no NS delegation.

## Architecture

```
browser  alice.ds.hn
  │  HTTPS
  ▼
Cloudflare edge  (*.ds.hn proxied / orange-cloud)     free DDoS, WAF, TLS,
  │  origin pull                                        anycast, hidden origin
  ▼
relay  (your server, @dshn/relay)                      login gate + subdomain
  │  one WSS per device (multiplexed)                   claim store; moves bytes
  ▼
dshn  (the dsh plugin, on the user's machine)    replays HTTP + WS to dsh,
  │  http://127.0.0.1:<dsh port>                        Host/Origin rewritten to loopback
  ▼
dsh  (local web server)                                fence sees a loopback request
```

- **No trustedHosts patch.** The agent rewrites each forwarded request's
  Host/Origin to loopback, so dsh's `/api` browser-trust fence accepts it as a
  local same-origin request for *any* runtime-chosen subdomain — which is what
  lets the subdomain come from a form instead of the composition. Access is gated
  by the relay login, not the fence.
- **End-to-end mode** seals request/response bodies at the agent and opens them
  in the browser; the relay stays a blind byte-mover. The app shell and plugin
  bundles are left in the clear so the browser can bootstrap and show the unlock
  gate. It defeats a passive/curious relay and a data-at-rest breach — not an
  actively malicious relay that tampers with the served JS.

## Packages

| package | what it is | runs where |
|---|---|---|
| `@dshn/protocol` | the WSS frame contract both ends compile against | shared |
| `dshn` | the dsh plugin: setup form + outbound tunnel + status widget + e2e | user's machine, inside dsh |
| `@dshn/relay` | login gate + claim store + subdomain router + HTTP/WS bridge | your server, behind Cloudflare |

The claim store (`packages/relay/src/claims.ts`) is trust-on-first-use for now;
an account-backed control plane replaces it later.

## Install the agent (user's machine)

From npm (recommended — one command, fully self-contained):

```sh
dsh plugin --profile web add @dshn/agent
dsh --profile web
```

Or a prebuilt tarball from the latest GitHub release:

```sh
curl -L -o dshn.tgz \
  https://github.com/jsdvjx/dshn/releases/latest/download/dshn.tgz
dsh plugin --profile web add ./dshn.tgz
```

Or build from source:

```sh
pnpm install && node scripts/build-dist.mjs
dsh plugin --profile web add ./dist/dshn
dsh --profile web
```

Then open dsh locally, go to **Settings → 公网转发 (Public forwarding)**, pick a
subdomain prefix and a password (optionally an end-to-end password), and click
**Connect**. Use the same access password to log in from a phone. Run at most
**one** agent per subdomain — two agents with the same credential fight over it.

Agent environment (all optional; sensible defaults):

| var | default | purpose |
|---|---|---|
| `DSHN_ENABLED` | `1` | set `0` to load the plugin inert |
| `DSHN_RELAY_HOST` | `relay.ds.hn` | relay authority; `wss://origin.ds.hn:8787` for a direct off-Cloudflare path |
| `DSHN_ORIGIN_CA` | — | PEM to pin a self-signed direct-origin cert |
| `DSHN_STATE` | `~/.dsh/dshn-agent.json` | legacy state file (creds now live in `settings.yaml`) |
| `DSH_HOME` | `~/.dsh` | dsh home directory |

## Self-host your own network

You don't have to use `ds.hn` — run the whole thing on your own domain. The relay
ships as **`@dshn/relay`** (npm) and a Docker image; your agents point at it with
`DSHN_RELAY_HOST`. Full guide, including DNS + TLS options: **[SELF-HOSTING.md](./SELF-HOSTING.md)**.

```sh
# your server
DSHN_APEX=tunnel.example.com DSHN_COOKIE_SECRET=$(openssl rand -hex 32) npx @dshn/relay
# your dsh
DSHN_RELAY_HOST=wss://tunnel.example.com dsh --profile web
```

Or from source:

```sh
pnpm install && pnpm build
DSHN_COOKIE_SECRET=$(openssl rand -hex 32) \
DSHN_APEX=ds.hn \
DSHN_RELAY_PORT=8787 \
DSHN_CLAIMS=./claims.json \
DSHN_TLS_CERT=./cert.pem DSHN_TLS_KEY=./key.pem \
  node packages/relay/lib/index.js
```

| var | required | purpose |
|---|---|---|
| `DSHN_COOKIE_SECRET` | ✅ | HMAC secret for session cookies (rotating it logs everyone out) |
| `DSHN_APEX` | — (`ds.hn`) | apex domain the wildcard hangs off |
| `DSHN_RELAY_PORT` | — (`8787`) | listen port |
| `DSHN_CLAIMS` | — | JSON file the relay creates/maintains (subdomain → scrypt hash) |
| `DSHN_TLS_CERT` / `DSHN_TLS_KEY` | — | PEM paths to serve HTTPS directly (else plain HTTP behind CF) |
| `DSHN_SITE` | — | apex landing-page HTML |

Cloudflare: proxy `*.ds.hn` (orange cloud) to the relay's origin. Harden the
origin to accept only Cloudflare — firewall to the
[Cloudflare IP ranges](https://www.cloudflare.com/ips/) and enable Authenticated
Origin Pulls (mTLS). Because Cloudflare closes a proxied WebSocket after ~100s
idle, both ends heartbeat every 25s — already built in. For a direct
(off-Cloudflare) tunnel that survives sustained heavy throughput, add a
grey-cloud (DNS-only) `origin.ds.hn` A record and point agents at it with
`DSHN_RELAY_HOST` + `DSHN_ORIGIN_CA`.

## Status

Working end-to-end. Known gaps: an occasional tunnel-socket drop fails that
connection's in-flight requests (no request replay yet); Cloudflare can reset the
tunnel under sustained heavy throughput (use the direct-origin option); the CF
free-plan 100 MB request cap can clip large dsh image uploads; the claim store is
trust-on-first-use with no account layer; and the relay origin should be locked
to Cloudflare IPs + Authenticated Origin Pulls in production.

## License

[MIT](./LICENSE)
