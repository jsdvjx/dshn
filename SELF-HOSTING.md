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

The only thing you have to pass is your apex. The cookie secret is
**auto-generated and saved** on first run (no `openssl rand`), and the claims
file + secret live together in `--data-dir`:

```sh
npx @dshn/relay --apex tunnel.example.com --data-dir /var/lib/dshn
```

`--help` lists every flag. Each flag also has an env var (e.g. `DSHN_APEX`) if you
prefer those. Install it as a long-running service (systemd):

```ini
# /etc/systemd/system/dshn-relay.service
[Unit]
Description=dshn relay
After=network.target

[Service]
ExecStart=/usr/bin/npx --yes @dshn/relay --apex tunnel.example.com --data-dir /var/lib/dshn
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
  -v dshn-data:/data \
  ghcr.io/jsdvjx/dshn-relay:latest
```

The image defaults `--data-dir` to `/data`, so the auto-generated secret and the
claims file persist on the `dshn-data` volume — nothing else to set. Or use the
provided [`docker-compose.yml`](./docker-compose.yml) (`DSHN_APEX=tunnel.example.com docker compose up -d`).

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
  npx @dshn/relay --apex tunnel.example.com --data-dir /var/lib/dshn --port 443 \
    --tls-cert /etc/letsencrypt/live/tunnel.example.com/fullchain.pem \
    --tls-key  /etc/letsencrypt/live/tunnel.example.com/privkey.pem
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

## Configuration reference

Every setting is a CLI flag (`--flag value`) or the matching env var; **flags win**.
Run `npx @dshn/relay --help` for the live list.

| flag | env | default | purpose |
|---|---|---|---|
| `--apex` | `DSHN_APEX` | `ds.hn` | the apex your wildcard hangs off |
| `--data-dir` | `DSHN_DATA_DIR` | `./dshn-data` | holds `claims.json` + the auto-generated `cookie-secret` |
| `--port` | `DSHN_RELAY_PORT` | `8787` | listen port |
| `--secret` | `DSHN_COOKIE_SECRET` | *(auto-generated)* | cookie HMAC secret; set one only if you want to pin it |
| `--claims` | `DSHN_CLAIMS` | `<data-dir>/claims.json` | JSON file the relay creates/maintains: subdomain → scrypt hash |
| `--tls-cert` / `--tls-key` | `DSHN_TLS_CERT` / `DSHN_TLS_KEY` | — | PEM paths to serve HTTPS directly (omit to serve plain HTTP behind a TLS-terminating proxy) |
| `--site` | `DSHN_SITE` | — | optional landing-page `index.html` for the bare apex (flat sibling `.html`/`.css`/… served too) |
| `--admin-password` | `DSHN_ADMIN_PASSWORD` | — | enable the operator admin panel at `https://<apex>/__admin` (unset = no panel, all its paths 404) |
| — | `DSHN_DEBUG` | — | set to log connection lifecycle to stderr |

You don't have to set a cookie secret: on first run the relay generates a strong
random one and saves it to `<data-dir>/cookie-secret` (`chmod 600`), reusing it on
restart so sessions survive. **Back up your `--data-dir`** — `claims.json` is the
only record of who owns which subdomain, and deleting the secret logs everyone out.

## Admin panel

Set `--admin-password` (or `DSHN_ADMIN_PASSWORD`) and the bare apex serves an
operator dashboard at `/__admin`: platform totals (claims, live devices,
per-subdomain traffic since the relay started) and per-claim management —
**Kick** (drop the live connections; agents may reconnect), **Release** (delete
the claim so the name is free to claim again — note an auto-reconnecting agent
can immediately re-claim it), and **Ban** (kick + delete + block the label from
being claimed until unbanned; bans persist in `claims.json`). Sessions last 12
hours; wrong guesses hit the same per-IP lockout as tunnel logins. Without a
configured password the panel does not exist: every `/__admin` path is a 404.

## Devices per subdomain

Several agents (devices) may hold one subdomain at a time with the same
credential; the relay tells them apart by a per-install device id and offers a
device picker/switcher in the browser when two or more are online. Only a
reconnect of the SAME device replaces its previous connection. Legacy agents
that predate device ids all share one slot, so among them the old rule still
applies: a second one replaces the first.

## Premium route (an accelerator in front of one tunnel)

Some tunnels want a faster path than the default CDN — e.g. a user on a network
where the CDN's anycast is slow. The **premium route** lets the operator move a
single claim onto a dedicated accelerator node, from the admin panel, without
touching anyone else.

How it works: the accelerator terminates TLS for the apex wildcard and reverse-
proxies to the relay. Enabling premium for `alice` creates one **un-proxied**
`A alice.<apex> → <accelerator IP>` record that shadows the CDN'd wildcard for
just that name; the relay also tells `alice`'s agent to dial that same hostname,
so the uplink takes the fast path too. Disabling removes the record and the name
falls back to the wildcard. It is **default-off**: every tunnel is standard until
the operator flips it, and an agent never chooses its own route.

### 1. Point the relay at an accelerator

```sh
dshn-relay --apex ds.hn --tls-cert … --tls-key … \
  --admin-password "$ADMIN_PW" \
  --premium-host 203.0.113.9 \          # the accelerator's public IP
  --cf-token "$CF_DNS_TOKEN" --cf-zone "$CF_ZONE_ID"   # optional: managed DNS
```

- `--premium-host` (env `DSHN_PREMIUM_HOST`) turns the feature on and is the IP
  the dedicated records point at.
- `--cf-token` + `--cf-zone` (env `DSHN_CF_TOKEN` / `DSHN_CF_ZONE`) let the relay
  create and remove each premium record itself (a Cloudflare **Zone → DNS → Edit**
  token, scoped to the apex's zone). Omit them for **manual DNS**: the panel then
  tells you exactly which record to add or remove.
- `--trusted-proxies a,b` (env `DSHN_TRUSTED_PROXIES`) — extra proxy IPs whose
  `X-Forwarded-For` the login rate-limiter believes. The accelerator itself is
  always trusted; add others only if a further hop sits in front of it.

### 2. Run the accelerator

Any TLS reverse proxy with a wildcard cert for `*.<apex>` works. With Caddy and a
Cloudflare DNS-01 wildcard:

```
*.ds.hn {
  tls { dns cloudflare {env.CF_API_TOKEN} }
  encode gzip
  reverse_proxy https://<relay-origin>:8787 {
    header_up Host {host}
    transport http { tls_insecure_skip_verify }   # relay uses a self-signed cert
  }
}
```

The accelerator forwards the real client IP as `X-Forwarded-For`; the relay reads
the last hop from its trusted proxy, so per-IP login lockout still works.

The accelerator must present a **publicly trusted** certificate for the apex
wildcard: an agent that pins a self-signed CA for the default relay (`--relay CA`
in its panel, or `DSHN_ORIGIN_CA`) applies that pin to the default relay only —
the premium host is verified against the system CAs like any public site.

How the agent moves: on being told it is premium it **probes** the premium host
(a plain WebSocket handshake, no HELLO) beside its live socket and only redials
through it once the host answered — a working tunnel is never dropped for a host
that is down or whose DNS record is still propagating. Three failed probes in a
row leave the host alone for 5 minutes, then 10, 20, … up to an hour, while the
control socket stays on the default relay; the panel keeps showing *premium*
(browsers reach the accelerator by DNS regardless). A successful switch resets
the schedule.

With managed DNS the relay only creates, retargets, or removes **its own**
records (matched by target or by the comment it stamps on them). If the name
already has an `A` record you set by hand, enabling fails with a message naming
it — remove that record first rather than letting two answers round-robin.

### 3. Flip it in the admin panel

Open `https://<apex>/__admin`, find the claim, and click **Premium**. With managed
DNS the record appears immediately; with manual DNS a toast tells you what to add.
The agent's own panel then shows **premium route (accelerated)** on its Link row.
Clicking **Standard** reverses everything.
