# dshn-agent

The dsh plugin half of [dshn](../../README.md). It opens one outbound WebSocket
to the relay, claims a subdomain with the (subdomain, password) the user typed in
the setup dialog, and replays whatever the relay forwards against the local dsh
web server — HTTP over `node:http`, dsh's own `/api/events.*` downlink sockets
over a tunnelled `ws` client.

Two halves:

- **Host** (`src/index.ts` → `lib/index.js`): the tunnel client, the replay
  engine, the reconnect/heartbeat loop, credential persistence, and the
  `/dshn/status` · `/dshn/configure` · `/dshn/disconnect` routes.
- **Browser** (`client.js`, hand-authored factory format): a `shell.overlay`
  pill that opens the **setup dialog** when unconfigured (subdomain + password),
  or the live status + public URL when connected.

## Why no `trustedHosts` patch

The agent rewrites each forwarded request's `Host`/`Origin` to the local loopback
authority before replaying it to dsh. dsh's `/api` browser-trust fence then
accepts it as a loopback, same-origin request — for *any* subdomain, with no
composition-time trusted-host entry. That is what lets the subdomain be chosen at
runtime in the dialog; access is gated by the relay's login instead of the fence.

## Config

Credentials (subdomain + password) are **not** configured here — the user sets
them in the dialog (`POST /dshn/configure`, loopback-only) and they persist to
`DSHN_STATE`. Only infrastructure is env-configured:

| env | meaning | default |
|---|---|---|
| `DSHN_RELAY_HOST` | host the tunnel dials | `relay.ds.hn` |
| `DSHN_ORIGIN_CA` | PEM cert to pin when dialing a direct grey-cloud origin | — |
| `DSHN_STATE` | file the chosen credentials persist to | `~/.dshn-agent.json` |
| `DSHN_LOCAL_PORT` | local dsh port to replay against | the web server's port |
| `DSHN_ENABLED` | `0` loads the plugin inert | `1` |
