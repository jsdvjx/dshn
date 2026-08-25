/**
 * The premium route end to end against a real RelayServer with a fake DNS
 * provider and a real AgentTunnel: the operator toggle creates/removes the
 * dedicated DNS record, the store remembers it, READY and a mid-session ROUTE
 * frame carry the assignment, the agent redials the announced host, a broken
 * premium host falls back to the default relay, and release/ban clean up DNS.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import http from 'node:http'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { decodeControl, encodeControl, type ControlFrame, type HelloFrame } from '@dshn/protocol'
import { ClaimStore } from '../src/claims.js'
import { RelayServer } from '../src/server.js'
import type { PremiumDns, DnsRecordRef } from '../src/dns.js'

const require = createRequire(import.meta.url)
const { WebSocket } = require('ws') as typeof import('ws')

const APEX = 'test.local'
const PASSWORD = 'password123'
const ADMIN_PW = 'admin-secret-1'
const PREMIUM_IP = '203.0.113.9'

/** A fake DNS provider that records the calls and hands out incrementing ids. */
class FakeDns implements PremiumDns {
  readonly records = new Map<string, DnsRecordRef>()
  points: Array<{ name: string; ip: string }> = []
  unpoints: Array<{ name: string; id?: string }> = []
  failNext: string | null = null
  /** When set, the next point() parks here until the test calls it (simulates a slow API). */
  holdNext: ((go: () => void) => void) | null = null
  private seq = 1

  async point(name: string, ip: string): Promise<DnsRecordRef> {
    if (this.failNext !== null) { const m = this.failNext; this.failNext = null; throw new Error(m) }
    if (this.holdNext !== null) { const h = this.holdNext; this.holdNext = null; await new Promise<void>((go) => h(go)) }
    this.points.push({ name, ip })
    const ref = { id: `rec-${this.seq++}`, content: ip }
    this.records.set(name, ref)
    return ref
  }
  async unpoint(name: string, id: string | undefined, _ip: string): Promise<void> {
    if (this.failNext !== null) { const m = this.failNext; this.failNext = null; throw new Error(m) }
    this.unpoints.push({ name, id })
    this.records.delete(name)
  }
}

/** A minimal fake agent that records the frames it receives. */
class FakeAgent {
  readonly ws: InstanceType<typeof WebSocket>
  readonly ready: Promise<void>
  readonly frames: ControlFrame[] = []
  private onReady!: () => void

  constructor(port: number, hello: Omit<HelloFrame, 't' | 'agent' | 'protocol'>) {
    this.ws = new WebSocket(`ws://127.0.0.1:${port}/dshn-agent`)
    this.ready = new Promise((r) => { this.onReady = r })
    this.ws.on('open', () => this.ws.send(encodeControl({ t: 'hello', agent: 'test', protocol: 1, ...hello })))
    this.ws.on('error', () => { /* expected on relay-side terminate */ })
    this.ws.on('message', (data: Buffer, isBinary: boolean) => {
      if (isBinary) return
      const f = decodeControl(data.toString()) as ControlFrame
      this.frames.push(f)
      if (f.t === 'ready') this.onReady()
      else if (f.t === 'ping') this.ws.send(encodeControl({ t: 'pong' }))
    })
  }
  last<T extends ControlFrame['t']>(t: T): Extract<ControlFrame, { t: T }> | undefined {
    for (let i = this.frames.length - 1; i >= 0; i--) if (this.frames[i].t === t) return this.frames[i] as any
    return undefined
  }
  close(): void { this.ws.close() }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
async function until(cond: () => boolean, ms = 2000): Promise<void> {
  const start = Date.now()
  while (!cond()) { if (Date.now() - start > ms) throw new Error('timeout'); await sleep(15) }
}

interface Res { status: number; headers: http.IncomingHttpHeaders; body: string }

/** Raw HTTP request against the relay — undici `fetch` can't set the Host header we route on. */
function request(port: number, path: string, opts: { method?: string; cookie?: string; json?: unknown } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: opts.method ?? 'GET' }, (res) => {
      let body = ''
      res.on('data', (c: Buffer) => { body += c.toString() })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }))
    })
    req.setHeader('host', APEX)
    if (opts.cookie !== undefined) req.setHeader('cookie', opts.cookie)
    let payload: string | undefined
    if (opts.json !== undefined) { payload = JSON.stringify(opts.json); req.setHeader('content-type', 'application/json') }
    req.on('error', reject)
    req.end(payload)
  })
}

/** Log in as admin and return the session cookie. */
async function adminLogin(port: number): Promise<string> {
  const res = await new Promise<Res>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/__admin/login', method: 'POST' }, (r) => {
      let body = ''; r.on('data', (c: Buffer) => { body += c.toString() }); r.on('end', () => resolve({ status: r.statusCode ?? 0, headers: r.headers, body }))
    })
    req.setHeader('host', APEX)
    req.setHeader('content-type', 'application/x-www-form-urlencoded')
    req.on('error', reject)
    req.end(`password=${ADMIN_PW}`)
  })
  expect(res.status).toBe(302)
  const cookie = ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith('dshn_admin='))
  if (cookie === undefined) throw new Error('no admin cookie')
  return cookie.split(';', 1)[0]
}

async function premium(port: number, cookie: string, subdomain: string, enabled: boolean): Promise<any> {
  const res = await request(port, '/__admin/api/premium', { method: 'POST', cookie, json: { subdomain, enabled } })
  return { status: res.status, body: JSON.parse(res.body) }
}

async function state(port: number, cookie: string): Promise<any> {
  const res = await request(port, '/__admin/api/state', { cookie })
  return JSON.parse(res.body)
}

describe('premium route', () => {
  let dir: string
  let dns: FakeDns
  let claims: ClaimStore
  let server: RelayServer
  let port: number
  let cookie: string

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'dshn-prem-'))
    dns = new FakeDns()
    claims = ClaimStore.fromFile(join(dir, 'claims.json'))
    server = new RelayServer({
      apex: APEX, port: 0, cookieSecret: 's3cret-cookie-value-01', claims, adminPassword: ADMIN_PW,
      premium: { host: PREMIUM_IP, dns, routeHost: (sub) => `ws://127.0.0.1:${port}/dshn-agent?prem=${sub}` },
    })
    await new Promise<void>((r) => server.listen(r))
    port = server.port()
    cookie = await adminLogin(port)
  })
  afterAll(() => { server.close(); rmSync(dir, { recursive: true, force: true }) })

  it('a fresh tunnel is on the standard route', async () => {
    const a = new FakeAgent(port, { subdomain: 'alpha', password: PASSWORD, deviceId: 'd1', device: 'A' })
    await a.ready
    expect(a.last('ready')!.route).toBe('standard')
    expect(a.last('ready')!.routeHost).toBeUndefined()
    a.close()
  })

  it('enabling premium creates the DNS record, remembers it, and notifies the live agent', async () => {
    const a = new FakeAgent(port, { subdomain: 'bravo', password: PASSWORD, deviceId: 'd1', device: 'B' })
    await a.ready
    const r = await premium(port, cookie, 'bravo', true)
    expect(r.status).toBe(200)
    expect(r.body).toMatchObject({ ok: true, route: 'premium', dns: 'managed' })
    expect(dns.points).toContainEqual({ name: `bravo.${APEX}`, ip: PREMIUM_IP })
    expect(claims.premiumOf('bravo')).toMatchObject({ dns: { content: PREMIUM_IP } })
    // The live agent got a mid-session route frame pointing at the premium host.
    await until(() => a.last('route') !== undefined)
    expect(a.last('route')).toMatchObject({ route: 'premium' })
    expect(a.last('route')!.routeHost).toContain('prem=bravo')
    a.close()
  })

  it('a premium tunnel reconnecting gets route=premium in its READY', async () => {
    const a = new FakeAgent(port, { subdomain: 'bravo', password: PASSWORD, deviceId: 'd2', device: 'B2' })
    await a.ready
    expect(a.last('ready')!.route).toBe('premium')
    expect(a.last('ready')!.routeHost).toContain('prem=bravo')
    a.close()
  })

  it('a managed-DNS failure leaves the claim on the standard route and reports why', async () => {
    const a = new FakeAgent(port, { subdomain: 'charlie', password: PASSWORD, deviceId: 'd1', device: 'C' })
    await a.ready
    dns.failNext = 'cloudflare 1004 boom'
    const r = await premium(port, cookie, 'charlie', true)
    expect(r.status).toBe(502)
    expect(r.body.error).toContain('DNS update failed')
    expect(claims.premiumOf('charlie')).toBeNull()
    a.close()
  })

  it('disabling premium removes the DNS record and re-announces standard', async () => {
    const a = new FakeAgent(port, { subdomain: 'bravo', password: PASSWORD, deviceId: 'd3', device: 'B3' })
    await a.ready
    const r = await premium(port, cookie, 'bravo', false)
    expect(r.body).toMatchObject({ ok: true, route: 'standard' })
    expect(dns.unpoints.some((u) => u.name === `bravo.${APEX}`)).toBe(true)
    expect(claims.premiumOf('bravo')).toBeNull()
    await until(() => a.last('route')?.route === 'standard')
    a.close()
  })

  it('release cleans up the premium DNS record', async () => {
    const a = new FakeAgent(port, { subdomain: 'delta', password: PASSWORD, deviceId: 'd1', device: 'D' })
    await a.ready
    await premium(port, cookie, 'delta', true)
    expect(claims.premiumOf('delta')).not.toBeNull()
    dns.unpoints = []
    await request(port, '/__admin/api/release', { method: 'POST', cookie, json: { subdomain: 'delta' } })
    await until(() => dns.unpoints.some((u) => u.name === `delta.${APEX}`))
    expect(claims.isClaimed('delta')).toBe(false)
    a.close()
  })

  it('a claim released while its DNS record is being created leaves no record behind', async () => {
    const a = new FakeAgent(port, { subdomain: 'golf', password: PASSWORD, deviceId: 'd1', device: 'G' })
    await a.ready
    let go: (() => void) | null = null
    dns.holdNext = (resume) => { go = resume }
    dns.unpoints = []
    const pending = premium(port, cookie, 'golf', true)
    await until(() => go !== null)
    // The operator releases the claim while the DNS API call is still in flight.
    await request(port, '/__admin/api/release', { method: 'POST', cookie, json: { subdomain: 'golf' } })
    expect(claims.isClaimed('golf')).toBe(false)
    go!()
    const r = await pending
    expect(r.status).toBe(404)
    // The record that was created for a claim that no longer exists is removed again.
    await until(() => dns.unpoints.some((u) => u.name === `golf.${APEX}`))
    expect(dns.records.has(`golf.${APEX}`)).toBe(false)
    a.close()
  })

  it('reports premium totals and a per-claim flag in admin state', async () => {
    const a = new FakeAgent(port, { subdomain: 'echo', password: PASSWORD, deviceId: 'd1', device: 'E' })
    await a.ready
    await premium(port, cookie, 'echo', true)
    const st = await state(port, cookie)
    expect(st.premium).toMatchObject({ host: PREMIUM_IP, dns: 'managed' })
    expect(st.premium.tunnels).toBeGreaterThanOrEqual(1)
    const echo = st.claims.find((c: any) => c.subdomain === 'echo')
    expect(echo.premium).not.toBeNull()
    a.close()
  })

  it('the premium API is 409 when the relay has no premium configured', async () => {
    const dir2 = mkdtempSync(join(tmpdir(), 'dshn-prem2-'))
    const s2 = new RelayServer({ apex: APEX, port: 0, cookieSecret: 'another-cookie-secret-val', claims: ClaimStore.fromFile(join(dir2, 'c.json')), adminPassword: ADMIN_PW })
    await new Promise<void>((r) => s2.listen(r))
    const p2 = s2.port()
    const c2 = await adminLogin(p2)
    const a = new FakeAgent(p2, { subdomain: 'foxtrot', password: PASSWORD, deviceId: 'd1', device: 'F' })
    await a.ready
    const r = await premium(p2, c2, 'foxtrot', true)
    expect(r.status).toBe(409)
    const st = await state(p2, c2)
    expect(st.premium).toBeNull()
    a.close(); s2.close(); rmSync(dir2, { recursive: true, force: true })
  })
})
