#!/usr/bin/env node
/**
 * Relay entry point. Reads its configuration from the environment (12-factor,
 * so the same build runs under a process manager or a container) and starts the
 * bridge. Everything security-relevant — the cookie secret and the tunnel
 * registry — is required, not defaulted, so a misconfigured relay fails to
 * start rather than coming up wide open.
 *
 * Env:
 *   DSHN_APEX            tunnel apex (default ds.hn)
 *   DSHN_RELAY_PORT      plain HTTP port behind Cloudflare (default 8787)
 *   DSHN_COOKIE_SECRET   HMAC secret for session cookies (REQUIRED)
 *   DSHN_CLAIMS          path to the claims JSON file (default ./claims.json)
 *   DSHN_TLS_CERT        path to a TLS cert (PEM) to serve HTTPS directly
 *   DSHN_TLS_KEY         path to the matching TLS key (PEM)
 *   DSHN_SITE            path to the site index.html served on the bare apex
 *                        (optional; flat sibling .html/.css assets served too)
 */
import { readFileSync } from 'node:fs'
import { ClaimStore } from './claims.js'
import { RelayServer, type RelayOptions } from './server.js'

const apex = process.env.DSHN_APEX ?? 'ds.hn'
const port = Number(process.env.DSHN_RELAY_PORT ?? 8787)
const cookieSecret = process.env.DSHN_COOKIE_SECRET ?? ''
const claimsPath = process.env.DSHN_CLAIMS ?? './claims.json'
const tlsCert = process.env.DSHN_TLS_CERT ?? ''
const tlsKey = process.env.DSHN_TLS_KEY ?? ''
const sitePath = process.env.DSHN_SITE || undefined

if (cookieSecret === '') {
  console.error('dshn-relay: DSHN_COOKIE_SECRET is required')
  process.exit(1)
}

let tls: RelayOptions['tls']
if (tlsCert !== '' && tlsKey !== '') {
  try {
    tls = { cert: readFileSync(tlsCert), key: readFileSync(tlsKey) }
  } catch (err) {
    console.error(`dshn-relay: cannot read TLS material: ${(err as Error).message}`)
    process.exit(1)
  }
}

const claims = ClaimStore.fromFile(claimsPath)

const server = new RelayServer({ apex, port, cookieSecret, claims, tls, sitePath })
server.listen(() => console.log(`dshn-relay listening on :${port} (${tls ? 'https' : 'http'}) for *.${apex}`))
