/**
 * The operator admin panel, end to end against a real RelayServer: the panel is
 * invisible without a configured password, the login gate mints an apex-scoped
 * session, `/__admin/api/state` reports claims/devices/traffic truthfully, and
 * the management actions (kick, release, ban, unban) actually disconnect
 * agents and change what the claim store will accept next.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { WebSocket, type RawData } from 'ws'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  DATA_RES_BODY,
  decodeControl,
  encodeControl,
  encodeData,
  type ControlFrame,
  type HelloFrame,
} from '@dshn/protocol'
import { ClaimStore } from '../src/claims.js'
import { RelayServer } from '../src/server.js'

const APEX = 'test.local'
const PASSWORD = 'password123'
const ADMIN_PW = 'admin-secret-1'

/** A fake dshn agent: claims a subdomain and answers every request with its marker. */
class FakeAgent {
  readonly ws: WebSocket
  readonly ready: Promise<void>
  readonly closed: Promise<void>
  deny: string | null = null

  constructor(port: number, hello: Omit<HelloFrame, 't' | 'agent' | 'protocol'>, readonly marker: string) {
    this.ws = new WebSocket(`ws://127.0.0.1:${port}/dshn-agent`)
    let onReady!: () => void
    let onClosed!: () => void
    this.ready = new Promise((r) => { onReady = r })
    this.closed = new Promise((r) => { onClosed = r })
    this.ws.on('open', () => {
      this.ws.send(encodeControl({ t: 'hello', agent: 'test-agent', protocol: 1, ...hello }))
    })
    this.ws.on('close', onClosed)
    this.ws.on('error', () => { /* terminated by the relay is expected in tests */ })
    this.ws.on('message', (data: RawData, isBinary: boolean) => {
      if (isBinary) return
      const frame = decodeControl(data.toString()) as ControlFrame
      if (frame.t === 'ready') onReady()
      else if (frame.t === 'deny') { this.deny = frame.reason; onClosed() }
      else if (frame.t === 'ping') this.ws.send(encodeControl({ t: 'pong' }))
      else if (frame.t === 'req_head') {
        this.ws.send(encodeControl({ t: 'res_head', id: frame.id, status: 200, headers: [['content-type', 'text/plain']] }))
        this.ws.send(encodeData(DATA_RES_BODY, frame.id, Buffer.from(this.marker)))
        this.ws.send(encodeControl({ t: 'res_end', id: frame.id }))
      }
    })
  }
}

interface Res { status: number; headers: http.IncomingHttpHeaders; body: string }

/** One HTTP request against the relay with an arbitrary Host. */
function request(port: number, host: string, path: string, opts: {
  method?: string
  cookie?: string
  contentType?: string
  body?: string
  ip?: string
} = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: opts.method ?? 'GET' }, (res) => {
      let body = ''
      res.on('data', (c: Buffer) => { body += c.toString() })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }))
    })
    req.setHeader('host', host)
    if (opts.cookie !== undefined) req.setHeader('cookie', opts.cookie)
    if (opts.contentType !== undefined) req.setHeader('content-type', opts.contentType)
    if (opts.ip !== undefined) req.setHeader('cf-connecting-ip', opts.ip)
    req.on('error', reject)
    req.end(opts.body)
  })
}

/** Extract the `name=value` pair from a Set-Cookie header list. */
function cookiePair(headers: http.IncomingHttpHeaders, name: string): string {
  const raw = ([] as string[]).concat(headers['set-cookie'] ?? []).find((c) => c.startsWith(`${name}=`))
  if (raw === undefined) throw new Error(`no ${name} cookie set`)
  return raw.split(';', 1)[0]
}

/** Poll the admin state until `cond` holds (agent register/close land async). */
async function untilState(port: number, cookie: string, cond: (j: any) => boolean): Promise<any> {
  for (let i = 0; i < 100; i++) {
    const res = await request(port, APEX, '/__admin/api/state', { cookie })
    const j = JSON.parse(res.body)
    if (cond(j)) return j
    await new Promise((r) => setTimeout(r, 20))
  }
  throw new Error('condition never held for /__admin/api/state')
}

describe('admin panel', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dshn-admin-'))
  const relay = new RelayServer({
    apex: APEX,
    port: 0,
    cookieSecret: 'test-cookie-secret',
    claims: ClaimStore.fromFile(join(dir, 'claims.json')),
    adminPassword: ADMIN_PW,
  })
  let port = 0
  let admin = '' // the dshn_admin session cookie pair

  beforeAll(async () => {
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port()
  })

  afterAll(() => {
    relay.close()
    rmSync(dir, { recursive: true, force: true })
  })

  it('is a 404 everywhere when no admin password is configured', async () => {
    const bare = new RelayServer({
      apex: APEX, port: 0, cookieSecret: 's'.repeat(32),
      claims: ClaimStore.fromFile(join(dir, 'claims-none.json')),
    })
    await new Promise<void>((r) => bare.listen(r))
    const p = bare.port()
    expect((await request(p, APEX, '/__admin')).status).toBe(404)
    expect((await request(p, APEX, '/__admin/api/state')).status).toBe(404)
    expect((await request(p, APEX, '/__admin/login', { method: 'POST', body: `password=${ADMIN_PW}` })).status).toBe(404)
    bare.close()
  })

  it('serves the login page unauthenticated and rejects a wrong password', async () => {
    const page = await request(port, APEX, '/__admin')
    expect(page.status).toBe(200)
    expect(page.body).toContain('Admin password')
    expect(page.body).not.toContain('api/state') // dashboard not leaked to the logged-out page

    const bad = await request(port, APEX, '/__admin/login', { method: 'POST', body: 'password=wrong-password' })
    expect(bad.status).toBe(401)
    expect(bad.body).toContain('Incorrect password')
    expect((await request(port, APEX, '/__admin/api/state')).status).toBe(401)
  })

  it('locks the admin login after a burst of wrong guesses, per IP', async () => {
    for (let i = 0; i < 8; i++) {
      await request(port, APEX, '/__admin/login', { method: 'POST', body: 'password=wrong-password', ip: '10.9.9.9' })
    }
    const locked = await request(port, APEX, '/__admin/login', { method: 'POST', body: `password=${ADMIN_PW}`, ip: '10.9.9.9' })
    expect(locked.status).toBe(429)
    // A different IP (the legitimate operator) is unaffected.
    const ok = await request(port, APEX, '/__admin/login', { method: 'POST', body: `password=${ADMIN_PW}`, ip: '10.1.1.1' })
    expect(ok.status).toBe(302)
  })

  it('logs in with the right password and serves the dashboard', async () => {
    const login = await request(port, APEX, '/__admin/login', { method: 'POST', body: `password=${ADMIN_PW}` })
    expect(login.status).toBe(302)
    admin = cookiePair(login.headers, 'dshn_admin')

    const page = await request(port, APEX, '/__admin', { cookie: admin })
    expect(page.status).toBe(200)
    expect(page.body).toContain('api/state')
  })

  it('does not accept the admin cookie as a tunnel session', async () => {
    const agent = new FakeAgent(port, { subdomain: 'alpha', password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A')
    await agent.ready
    // The admin session must not unlock a tunnel host.
    const res = await request(port, `alpha.${APEX}`, '/', { cookie: admin.replace('dshn_admin', 'dshn_sess') })
    expect(res.body).not.toBe('A')
    agent.ws.close()
    await agent.closed
  })

  it('reports claims, live devices, and traffic in /api/state', async () => {
    const agent = new FakeAgent(port, { subdomain: 'alpha', password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A')
    await agent.ready
    await untilState(port, admin, (j) => j.totals.onlineDevices === 1)

    // Log into the tunnel and push one public request through it.
    const login = await request(port, `alpha.${APEX}`, '/__dshn/login', { method: 'POST', body: `password=${PASSWORD}` })
    const sess = cookiePair(login.headers, 'dshn_sess')
    const pub = await request(port, `alpha.${APEX}`, '/hello', { cookie: sess })
    expect(pub.body).toBe('A')

    const st = await untilState(port, admin, (j) => (j.claims.find((c: any) => c.subdomain === 'alpha')?.traffic.requests ?? 0) >= 1)
    expect(st.apex).toBe(APEX)
    expect(st.totals.claims).toBeGreaterThanOrEqual(1)
    expect(st.totals.onlineSubdomains).toBe(1)
    const alpha = st.claims.find((c: any) => c.subdomain === 'alpha')
    expect(alpha.online).toBe(true)
    expect(alpha.devices[0]).toMatchObject({ id: 'deva', name: 'Laptop A', online: true })
    expect(alpha.traffic.bytesOut).toBeGreaterThanOrEqual(1) // the "A" body
    expect(st.traffic.requests).toBeGreaterThanOrEqual(1)

    agent.ws.close()
    await agent.closed
  })

  it('kicks a live agent without touching the claim', async () => {
    const agent = new FakeAgent(port, { subdomain: 'alpha', password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A')
    await agent.ready
    await untilState(port, admin, (j) => j.totals.onlineDevices === 1)

    const res = await request(port, APEX, '/__admin/api/kick', {
      method: 'POST', cookie: admin, contentType: 'application/json', body: JSON.stringify({ subdomain: 'alpha' }),
    })
    expect(JSON.parse(res.body)).toMatchObject({ ok: true, kicked: 1 })
    await agent.closed
    await untilState(port, admin, (j) => j.totals.onlineDevices === 0)

    // The claim survives: the same password reconnects fine.
    const back = new FakeAgent(port, { subdomain: 'alpha', password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A')
    await back.ready
    back.ws.close()
    await back.closed
  })

  it('releases a claim: agent kicked, subdomain claimable with a NEW password', async () => {
    const agent = new FakeAgent(port, { subdomain: 'alpha', password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A')
    await agent.ready

    const res = await request(port, APEX, '/__admin/api/release', {
      method: 'POST', cookie: admin, contentType: 'application/json', body: JSON.stringify({ subdomain: 'alpha' }),
    })
    expect(JSON.parse(res.body)).toMatchObject({ ok: true, released: true })
    await agent.closed
    await untilState(port, admin, (j) => !j.claims.some((c: any) => c.subdomain === 'alpha'))

    const fresh = new FakeAgent(port, { subdomain: 'alpha', password: 'brand-new-pass', deviceId: 'devb', device: 'Laptop B' }, 'B')
    await fresh.ready // re-claim succeeds because the name is free again
    fresh.ws.close()
    await fresh.closed
  })

  it('bans a claim: agent kicked and the label denied until unbanned', async () => {
    const agent = new FakeAgent(port, { subdomain: 'alpha', password: 'brand-new-pass', deviceId: 'devb', device: 'Laptop B' }, 'B')
    await agent.ready

    const res = await request(port, APEX, '/__admin/api/ban', {
      method: 'POST', cookie: admin, contentType: 'application/json', body: JSON.stringify({ subdomain: 'alpha' }),
    })
    expect(JSON.parse(res.body)).toMatchObject({ ok: true, released: true, kicked: 1 })
    await agent.closed

    // Reconnecting — even with the original password — is denied now.
    const again = new FakeAgent(port, { subdomain: 'alpha', password: 'brand-new-pass', deviceId: 'devb', device: 'Laptop B' }, 'B')
    await again.closed
    expect(again.deny).toContain('banned')

    const st = await untilState(port, admin, (j) => j.banned.includes('alpha'))
    expect(st.banned).toContain('alpha')

    const un = await request(port, APEX, '/__admin/api/unban', {
      method: 'POST', cookie: admin, contentType: 'application/json', body: JSON.stringify({ subdomain: 'alpha' }),
    })
    expect(JSON.parse(un.body)).toMatchObject({ ok: true })
    const back = new FakeAgent(port, { subdomain: 'alpha', password: 'post-ban-pass', deviceId: 'devc', device: 'Laptop C' }, 'C')
    await back.ready // claimable again after the unban
    back.ws.close()
    await back.closed
  })

  it('persists bans across a store reload', async () => {
    const path = join(dir, 'claims-persist.json')
    const store = new ClaimStore(path)
    expect(store.claimOrVerify('gone', 'some-password', Date.now()).ok).toBe(true)
    store.ban('gone')
    const reloaded = ClaimStore.fromFile(path)
    expect(reloaded.claimOrVerify('gone', 'some-password', Date.now()).ok).toBe(false)
    expect(reloaded.listBanned()).toContain('gone')
    reloaded.unban('gone')
    expect(reloaded.claimOrVerify('gone', 'some-password', Date.now()).ok).toBe(true)
  })

  it('serves trend history: a sample taken at start, cumulative columns', async () => {
    const res = await request(port, APEX, '/__admin/api/history', { cookie: admin })
    expect(res.status).toBe(200)
    const h = JSON.parse(res.body)
    expect(h.interval).toBeGreaterThan(0)
    expect(h.columns).toEqual(['t', 'requests', 'wsSessions', 'bytesIn', 'bytesOut', 'onlineDevices', 'onlineSubdomains'])
    expect(h.samples.length).toBeGreaterThanOrEqual(1)
    const first = h.samples[0]
    expect(first).toHaveLength(7)
    expect(first[0]).toBeGreaterThan(0)
    expect((await request(port, APEX, '/__admin/api/history')).status).toBe(401)
  })

  it('rejects admin API calls without a session and logs out cleanly', async () => {
    const unauth = await request(port, APEX, '/__admin/api/kick', {
      method: 'POST', contentType: 'application/json', body: JSON.stringify({ subdomain: 'alpha' }),
    })
    expect(unauth.status).toBe(401)

    const out = await request(port, APEX, '/__admin/logout', { method: 'POST', cookie: admin })
    expect(out.status).toBe(302)
    expect(cookiePair(out.headers, 'dshn_admin')).toBe('dshn_admin=')
  })
})
