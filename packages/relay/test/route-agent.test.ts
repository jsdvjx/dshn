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
const { WebSocket, WebSocketServer } = require('ws') as typeof import('ws')

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

function fakeOrigin(): { server: http.Server; port: number; live: Set<InstanceType<typeof WebSocket>> } {
  const server = http.createServer((_req, res) => { res.writeHead(200); res.end('ok') })
  const wss = new WebSocketServer({ server })
  // Every browser socket the agent replays to this origin, while it is open.
  const live = new Set<InstanceType<typeof WebSocket>>()
  wss.on('connection', (ws) => { live.add(ws); ws.on('close', () => live.delete(ws)) })
  server.listen(0)
  return { server, port: (server.address() as any).port, live }
}

/** Log in to the tunnel as a visitor and return the session cookie. */
function visitorLogin(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/__dshn/login', method: 'POST' }, (r) => {
      r.on('data', () => {})
      r.on('end', () => {
        const cookie = ([] as string[]).concat(r.headers['set-cookie'] ?? []).find((c) => c.startsWith('dshn_sess='))
        cookie === undefined ? reject(new Error(`login ${r.statusCode}: no session cookie`)) : resolve(cookie.split(';', 1)[0])
      })
    })
    req.setHeader('host', `${SUB}.${APEX}`); req.setHeader('content-type', 'application/x-www-form-urlencoded')
    req.on('error', reject); req.end(`password=${PASSWORD}`)
  })
}

/** Open a browser-side WebSocket through the tunnel (relay → agent → origin). */
function visitorSocket(port: number, cookie: string): Promise<InstanceType<typeof WebSocket>> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/events`, { headers: { host: `${SUB}.${APEX}`, cookie } })
    ws.on('open', () => resolve(ws))
    ws.on('error', reject)
  })
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
      premium: { host: premiumHost, dns, routeHost: () => `ws://localhost:${port}` }, // a DIFFERENT authority for the same relay, so the agent really moves
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
    // The agent persisted the announced premium host and moved its control socket onto it.
    await until(() => tunnel!.info().relayHost === `localhost:${port}`)
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
    const since = tunnel!.info().connectedSince
    await setPremium(port, cookie, true)
    // The dead premium host is PROBED beside the live socket, never blindly
    // dialled in its place: the control socket stays on the DEFAULT relay the
    // whole time and the tunnel never drops. The displayed route is 'premium'
    // (the operator's assignment; browsers reach the accelerator by DNS
    // regardless of where the agent's own socket is).
    await until(() => tunnel!.info().route === 'premium', 8000)
    await sleep(1500)
    expect(tunnel!.status.connected).toBe(true)
    expect(tunnel!.info().connectedSince).toBe(since) // the same connection — it was never dropped
    expect(tunnel!.info().relayHost).toBe(`127.0.0.1:${port}`)
    expect(tunnel!.info().route).toBe('premium')
    expect(tunnel!.info().routeHost).toBe('ws://127.0.0.1:1')
  }, 15000)

  it('tears down the streams of the abandoned connection when it moves route', async () => {
    await startRelay('198.51.100.7')
    startAgent()
    await until(() => tunnel!.status.connected)
    const session = await visitorLogin(port)
    const browser = await visitorSocket(port, session)
    await until(() => origin.live.size === 1)

    let browserClosed = false
    browser.on('close', () => { browserClosed = true })
    expect(await setPremium(port, cookie, true)).toBe(200)
    await until(() => tunnel!.info().route === 'premium' && tunnel!.status.connected && tunnel!.info().routeHost !== null)
    // The agent redialled through the premium host. The origin-side socket of
    // the OLD connection must be gone — the new connection numbers its streams
    // from 1 again, and a survivor would answer to a stranger's id.
    await until(() => origin.live.size === 0 && browserClosed, 4000)

    // A fresh visitor socket over the new connection works. The redial leaves a
    // brief window with no live device (old socket gone, new not yet READY), so
    // retry the open until the agent has settled on the premium path.
    let browser2: InstanceType<typeof WebSocket> | null = null
    for (let i = 0; i < 50 && browser2 === null; i += 1) {
      try { browser2 = await visitorSocket(port, session) } catch { await sleep(50) }
    }
    if (browser2 === null) throw new Error('could not reopen a visitor socket after the redial')
    await until(() => origin.live.size === 1)
    browser2.close()
    await until(() => origin.live.size === 0)
  }, 15000)

  it('forgets a remembered premium host when the relay stops announcing routes', async () => {
    await startRelay('198.51.100.7')
    startAgent()
    await until(() => tunnel!.status.connected)
    expect(await setPremium(port, cookie, true)).toBe(200)
    await until(() => tunnel!.info().route === 'premium' && tunnel!.status.connected && tunnel!.info().routeHost !== null)

    // The operator restarts the relay WITHOUT the premium feature (same port,
    // same claims). Its READY carries no route: the agent must drop the stale
    // premium host instead of dialling it forever.
    relay.close()
    relay = new RelayServer({
      apex: APEX, port, cookieSecret: 'cookie-secret-value-here-01', claims: ClaimStore.fromFile(join(dir, 'claims.json')),
      adminPassword: ADMIN_PW,
    })
    await new Promise<void>((r) => relay.listen(r))
    await until(() => tunnel!.status.connected && tunnel!.info().routeHost === null, 12000)
    expect(tunnel!.info().route).toBe('standard')
    expect(tunnel!.info().relayHost).toBe(`127.0.0.1:${port}`)
  }, 20000)
})
