# Self-hosting dshn

Run your own **DeepSeek Harness Network** on your own domain — the relay
(`@dshn/relay`) on your server, your own `*.your-apex` wildcard, no dependency on
`ds.hn`. Your dsh instances install the same `@dshn/agent` plugin and point it at
your relay.

> ⚠️ **A publicly reachable dsh UI is a remote shell** (dsh ships bash + filesystem
> tools). The relay's login gate is the only thing between the internet and that
> shell — set a strong `DSHN_COOKIE_SECRET`, use strong per-tunnel passwords, and
> prefer end-to-end encryption. Don't expose a relay you don't control the access
> policy of.

## What you need

- A server with a public IP (the relay is one small Node process; ~30 MB RAM).
- A domain you can add DNS records to — call it the **apex**, e.g. `tunnel.example.com`.
- Two DNS records pointing at the relay's IP:
  - `A  tunnel.example.com        → <relay IP>`  (the apex — agents dial it, and it's the login host)
  - `A  *.tunnel.example.com      → <relay IP>`  (the wildcard — every tunnel lives here)
- TLS for `*.apex` (three options below). Universal/most wildcard certs cover **one
  label deep**, so keep tunnel names flat (`alice.tunnel.example.com`, not
  `a.b.tunnel.example.com`) — the relay enforces this too.

## 1. Run the relay

### Option A — npm (Node ≥ 20)

```sh
DSHN_APEX=tunnel.example.com \
DSHN_RELAY_PORT=8787 \
DSHN_COOKIE_SECRET=$(openssl rand -hex 32) \
DSHN_CLAIMS=/var/lib/dshn/claims.json \
  npx @dshn/relay
```

Install it as a long-running service (systemd):

```ini
# /etc/systemd/system/dshn-relay.service
[Unit]
Description=dshn relay
After=network.target

[Service]
Environment=DSHN_APEX=tunnel.example.com
Environment=DSHN_RELAY_PORT=8787
Environment=DSHN_COOKIE_SECRET=<hex-from-openssl-rand-hex-32>
Environment=DSHN_CLAIMS=/var/lib/dshn/claims.json
ExecStart=/usr/bin/npx --yes @dshn/relay
Restart=always
DynamicUser=yes
StateDirectory=dshn

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now dshn-relay
```

### Option B — Docker

```sh
docker run -d --name dshn-relay --restart unless-stopped \
  -p 8787:8787 \
  -e DSHN_APEX=tunnel.example.com \
  -e DSHN_COOKIE_SECRET=$(openssl rand -hex 32) \
  -e DSHN_CLAIMS=/data/claims.json \
  -v dshn-data:/data \
  ghcr.io/jsdvjx/dshn-relay:latest
```

Or use the provided [`docker-compose.yml`](./docker-compose.yml) (`docker compose up -d`).
The image is built from [`Dockerfile`](./Dockerfile) and just runs `@dshn/relay`.

## 2. TLS — pick one

The relay speaks WebSocket, which needs `wss://` (TLS) end-to-end.

- **Behind Cloudflare (simplest, hides your origin).** Proxy `*.apex` and the apex
  (orange cloud) to the relay. The relay serves plain HTTP; Cloudflare terminates
  TLS. Set SSL mode to *Full*. Cloudflare closes idle WebSockets after ~100 s —
  the relay heartbeats every 25 s, so tunnels stay up. Harden the origin to accept
  only [Cloudflare IPs](https://www.cloudflare.com/ips/) + Authenticated Origin
  Pulls, since the origin trusts `cf-connecting-ip`.

- **Standalone with a real cert (no Cloudflare).** Get a wildcard cert for
  `*.apex` (+ the apex) via Let's Encrypt DNS-01 (`certbot --preferred-challenges dns`),
  then point the relay at it and serve 443 directly:

  ```sh
  DSHN_APEX=tunnel.example.com DSHN_RELAY_PORT=443 \
  DSHN_COOKIE_SECRET=… DSHN_CLAIMS=/var/lib/dshn/claims.json \
  DSHN_TLS_CERT=/etc/letsencrypt/live/tunnel.example.com/fullchain.pem \
  DSHN_TLS_KEY=/etc/letsencrypt/live/tunnel.example.com/privkey.pem \
    npx @dshn/relay
  ```

  (Binding 443 needs root or `CAP_NET_BIND_SERVICE`.) Agents connect with the
  public CA — no extra config.

- **Self-signed (private/internal).** Serve HTTPS with a self-signed cert whose SAN
  covers `*.apex`, and pin it on the agent side with `DSHN_ORIGIN_CA` (below).

## 3. Point your dsh agents at your relay

Install the plugin as usual, then set the relay host in the environment when you
launch dsh (per machine, or baked into your profile's composition):

```sh
dsh plugin --profile web add @dshn/agent
DSHN_RELAY_HOST=wss://tunnel.example.com dsh --profile web
```

- `DSHN_RELAY_HOST` — `wss://<host-that-reaches-your-relay>`. The apex works; a
  reserved `relay.<apex>` subdomain does too (users can't claim it). Include the
  port if not 443 (`wss://tunnel.example.com:8787`).
- `DSHN_ORIGIN_CA` — only for a **self-signed** relay: the path to the relay's
  cert PEM, which the agent pins as its sole CA.

Then open dsh → **Settings → 公网转发 / Public forwarding**, pick a subdomain
prefix + password, and connect. The first agent to claim a free subdomain sets
its password (trust-on-first-use); it's scrypt-hashed on your relay.

## Relay environment reference

| var | required | default | purpose |
|---|---|---|---|
| `DSHN_COOKIE_SECRET` | ✅ | — | HMAC secret for login-session cookies (rotating it logs everyone out) |
| `DSHN_APEX` | — | `ds.hn` | the apex your wildcard hangs off |
| `DSHN_RELAY_PORT` | — | `8787` | listen port |
| `DSHN_CLAIMS` | — | `./claims.json` | JSON file the relay creates/maintains: subdomain → scrypt hash |
| `DSHN_TLS_CERT` / `DSHN_TLS_KEY` | — | — | PEM paths to serve HTTPS directly (omit to serve plain HTTP behind a TLS-terminating proxy) |
| `DSHN_SITE` | — | — | optional landing-page `index.html` for the bare apex (flat sibling `.html`/`.css`/… served too) |
| `DSHN_DEBUG` | — | — | set to log connection lifecycle to stderr |

The relay refuses to start without `DSHN_COOKIE_SECRET` — a misconfigured relay
fails closed rather than coming up unauthenticated. Back up `claims.json`: it's
the only record of who owns which subdomain (losing it frees every name to
re-claim). It's written atomically and `chmod 600`.

## Devices per subdomain

Several agents (devices) may hold one subdomain at a time with the same
credential; the relay tells them apart by a per-install device id and offers a
device picker/switcher in the browser when two or more are online. Only a
reconnect of the SAME device replaces its previous connection. Legacy agents
that predate device ids all share one slot, so among them the old rule still
applies: a second one replaces the first.
