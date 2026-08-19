#!/usr/bin/env node
/**
 * Relay entry point. Configuration comes from CLI flags OR env vars (flags win),
 * with sane defaults so self-hosting is one short command — the ONLY thing you
 * really have to pass is your apex:
 *
 *   npx @dshn/relay --apex tunnel.example.com            # behind Cloudflare / a TLS proxy
 *   npx @dshn/relay --apex tunnel.example.com --port 443 \
 *                   --tls-cert fullchain.pem --tls-key privkey.pem   # standalone HTTPS
 *
 * The cookie secret is auto-generated and persisted on first run (no more
 * `openssl rand`), and the claims file + secret live together in one --data-dir.
 * The old env vars (DSHN_APEX, DSHN_COOKIE_SECRET, DSHN_CLAIMS, …) all still work.
 */
import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { ClaimStore } from './claims.js'
import { RelayServer, type RelayOptions } from './server.js'

/** Minimal arg parser: `--k v`, `--k=v`, bare `--flag`, and `-h`/`--help`. */
function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '-h' || a === '--help') { out.help = true; continue }
    if (!a.startsWith('--')) continue
    const eq = a.indexOf('=')
    if (eq >= 0) { out[a.slice(2, eq)] = a.slice(eq + 1); continue }
    const next = argv[i + 1]
    if (next !== undefined && !next.startsWith('-')) { out[a.slice(2)] = next; i++ } else out[a.slice(2)] = true
  }
  return out
}

const HELP = `dshn-relay — self-hostable ds.hn-style tunnel relay

Usage:
  dshn-relay --apex <domain> [options]

The only setting you really need is your apex (the wildcard domain). The cookie
secret is auto-generated + persisted on first run; claims + secret live in one
--data-dir. Flags override env vars.

Options (env var in parens):
  --apex <domain>     wildcard apex, e.g. tunnel.example.com  (DSHN_APEX, default ds.hn)
  --port <n>          listen port                             (DSHN_RELAY_PORT, default 8787)
  --data-dir <dir>    holds claims.json + cookie-secret       (DSHN_DATA_DIR, default ./dshn-data)
  --claims <file>     claims JSON path                        (DSHN_CLAIMS, default <data-dir>/claims.json)
  --secret <hex>      cookie HMAC secret (else auto-generated)(DSHN_COOKIE_SECRET)
  --tls-cert <file>   PEM cert to serve HTTPS directly        (DSHN_TLS_CERT)
  --tls-key <file>    PEM key to serve HTTPS directly         (DSHN_TLS_KEY)
  --site <file>       index.html to serve on the bare apex    (DSHN_SITE)
  -h, --help          show this help

Examples:
  dshn-relay --apex tunnel.example.com
  dshn-relay --apex tunnel.example.com --port 443 --tls-cert fullchain.pem --tls-key privkey.pem
`

const args = parseArgs(process.argv.slice(2))
if (args.help) { console.log(HELP); process.exit(0) }

/** Flag value, else env value, else undefined. Flags always win. */
const val = (flag: string, env: string): string | undefined => {
  const v = args[flag]
  return typeof v === 'string' ? v : process.env[env]
}

const dataDir = val('data-dir', 'DSHN_DATA_DIR') ?? './dshn-data'
const apex = val('apex', 'DSHN_APEX') ?? 'ds.hn'
const port = Number(val('port', 'DSHN_RELAY_PORT') ?? 8787)
const claimsPath = val('claims', 'DSHN_CLAIMS') ?? join(dataDir, 'claims.json')
const tlsCert = val('tls-cert', 'DSHN_TLS_CERT') ?? ''
const tlsKey = val('tls-key', 'DSHN_TLS_KEY') ?? ''
const sitePath = val('site', 'DSHN_SITE') || undefined

/**
 * Cookie secret: an explicit --secret / DSHN_COOKIE_SECRET wins; otherwise load a
 * persisted one, or generate + persist a strong random one on first run. This
 * removes the `openssl rand` step and the "must set a secret or it won't start"
 * friction, while still never coming up with a weak/empty secret. A generated
 * secret survives restarts (deleting it logs everyone out).
 */
function loadOrCreateSecret(path: string): string {
  try { const s = readFileSync(path, 'utf8').trim(); if (s.length >= 32) return s } catch { /* first run */ }
  const secret = randomBytes(32).toString('hex')
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, secret + '\n', { mode: 0o600 })
  console.error(`dshn-relay: generated a cookie secret at ${path} (keep it — deleting it logs everyone out)`)
  return secret
}
let cookieSecret = val('secret', 'DSHN_COOKIE_SECRET') ?? ''
if (cookieSecret === '') cookieSecret = loadOrCreateSecret(join(dataDir, 'cookie-secret'))

let tls: RelayOptions['tls']
if (tlsCert !== '' && tlsKey !== '') {
  try {
    tls = { cert: readFileSync(tlsCert), key: readFileSync(tlsKey) }
  } catch (err) {
    console.error(`dshn-relay: cannot read TLS material: ${(err as Error).message}`)
    process.exit(1)
  }
}

mkdirSync(dirname(claimsPath), { recursive: true }) // ensure the claims dir exists before first write
const claims = ClaimStore.fromFile(claimsPath)

const server = new RelayServer({ apex, port, cookieSecret, claims, tls, sitePath })
server.listen(() => console.log(`dshn-relay listening on :${port} (${tls ? 'https' : 'http'}) for *.${apex}  [data-dir: ${dataDir}]`))
