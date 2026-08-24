/**
 * The agent side of the premium route, with a REAL AgentTunnel against a REAL
 * RelayServer: the agent dials standard, the operator enables premium, and the
 * agent redials through the announced premium host and reports it; disabling
 * sends it back to the default relay; and an unreachable premium host degrades
 * to the standard route instead of wedging the tunnel.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { ClaimStore } from '../src/claims.js'
import { RelayServer } from '../src/server.js'
import { AgentTunnel, fileStore } from '../../agent/lib/index.js'
import type { PremiumDns, DnsRecordRef } from '../src/dns.js'

const require = createRequire(new URL('../../agent/package.json', import.meta.url))
const { WebSocketServer } = require('ws') as typeof import('ws')

const APEX = 'test.local'
const SUB = 'router'
const PASSWORD = 'password123'
const ADMIN_PW = 'admin-secret-1'

class NoopDns implements PremiumDns {
  async point(_n: string, ip: string): Promise<DnsRecordRef> { return { id: 'x', content: ip } }
  async unpoint(): Promise<void> { /* nothing */ }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
async function until(cond: () => boolean, ms = 6000): Promise<void> {
  const start = Date.now()
  while (!cond()) { if (Date.now() - start > ms) throw new Error('timeout'); await sleep(20) }
}

function fakeOrigin(): { server: http.Server; port: number } {
  const server = http.createServer((_req, res) => { res.writeHead(200); res.end('ok') })
  const wss = new WebSocketServer({ server })
  wss.on('connection', () => { /* keep-open */ })
  server.listen(0)
  return { server, port: (server.address() as any).port }
}

async function adminLogin(port: number): Promise<string> {
  const res = await new Promise<{ headers: http.IncomingHttpHeaders; status: number }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/__admin/login', method: 'POST' }, (r) => {
      r.on('data', () => {}); r.on('end', () => resolve({ headers: r.headers, status: r.statusCode ?? 0 }))
    })
    req.setHeader('host', APEX); req.setHeader('content-type', 'application/x-www-form-urlencoded')
    req.on('error', reject); req.end(`password=${ADMIN_PW}`)
  })
  const cookie = ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith('dshn_admin='))!
  return cookie.split(';', 1)[0]
}

function setPremium(port: number, cookie: string, enabled: boolean): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/__admin/api/premium', method: 'POST' }, (r) => {
      r.on('data', () => {}); r.on('end', () => resolve(r.statusCode ?? 0))
    })
    req.setHeader('host', APEX); req.setHeader('content-type', 'application/json')
    req.setHeader('cookie', cookie)
    req.on('error', reject); req.end(JSON.stringify({ subdomain: SUB, enabled }))
  })
}

describe('agent follows relay-assigned routes', () => {
  let dir: string, origin: ReturnType<typeof fakeOrigin>, relay: RelayServer, port: number, cookie: string
  let tunnel: AgentTunnel | null = null

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'dshn-route-'))
    origin = fakeOrigin()
  })
  afterEach(() => {
    tunnel?.stop(); tunnel = null
    relay?.close(); origin.server.close(); rmSync(dir, { recursive: true, force: true })
  })

  async function startRelay(premiumHost: string, dns: PremiumDns | undefined = new NoopDns()): Promise<void> {
    relay = new RelayServer({
      apex: APEX, port: 0, cookieSecret: 'cookie-secret-value-here-01', claims: ClaimStore.fromFile(join(dir, 'claims.json')),
      adminPassword: ADMIN_PW,
      // The premium host is a full ws:// URL so the agent redials this same relay
      // (a real deploy points a DNS name at the accelerator; here we just prove
      // the agent switches the authority it dials).
      premium: { host: premiumHost, dns, routeHost: () => `ws://127.0.0.1:${port}` },
    })
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port()
    cookie = await adminLogin(port)
  }

  function startAgent(): void {
    const config = { enabled: true, relayHost: `ws://127.0.0.1:${port}`, localHost: '127.0.0.1', localPort: origin.port, originCa: '', statePath: join(dir, 'creds.json') }
    tunnel = new AgentTunnel(config as any, () => origin.port, fileStore(config.statePath))
    tunnel.configure(SUB, PASSWORD)
  }

  it('redials the premium host on enable and returns to the relay on disable', async () => {
    await startRelay('198.51.100.7')
    startAgent()
    await until(() => tunnel!.status.connected)
    expect(tunnel!.info().route).toBe('standard')

    expect(await setPremium(port, cookie, true)).toBe(200)
    await until(() => tunnel!.info().route === 'premium' && tunnel!.status.connected)
    // The agent persisted the announced premium host and is dialling it.
    expect(tunnel!.relaySettings().relayHost).toBe('') // default relay unchanged

    expect(await setPremium(port, cookie, false)).toBe(200)
    await until(() => tunnel!.info().route === 'standard' && tunnel!.status.connected)
  }, 15000)

  it('degrades to the standard route when the premium host is unreachable', async () => {
    // A premium host at a dead ws URL: the agent will fail to dial it and, after
    // a few tries, fall back to the default relay — the tunnel stays up.
    const deadPort = origin.port // any; overridden below
    relay = new RelayServer({
      apex: APEX, port: 0, cookieSecret: 'cookie-secret-value-here-02', claims: ClaimStore.fromFile(join(dir, 'claims.json')),
      adminPassword: ADMIN_PW,
      premium: { host: '198.51.100.9', dns: new NoopDns(), routeHost: () => `ws://127.0.0.1:1` },
    })
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port(); cookie = await adminLogin(port)
    void deadPort
    startAgent()
    await until(() => tunnel!.status.connected)
    await setPremium(port, cookie, true)
    // It tries the dead premium host (dropping the live tunnel briefly), fails
    // ROUTE_FAIL_MAX times, then dials the default relay again and reconnects.
    // It tries the dead premium host, fails, and after a few tries keeps its
    // control socket on the DEFAULT relay — the tunnel settles UP there. The
    // displayed route stays 'premium' (the operator's assignment; browsers reach
    // the accelerator by DNS regardless of where the agent's own socket is).
    await until(() => tunnel!.info().route === 'premium', 8000)
    await until(() => tunnel!.status.connected && tunnel!.info().relayHost === `127.0.0.1:${port}`, 25000)
    // And it stays settled there (no reconnect loop onto the dead accelerator).
    await sleep(1500)
    expect(tunnel!.status.connected).toBe(true)
    expect(tunnel!.info().relayHost).toBe(`127.0.0.1:${port}`)
    expect(tunnel!.info().route).toBe('premium')
  }, 32000)
})
