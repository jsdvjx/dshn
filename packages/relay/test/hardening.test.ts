/**
 * Negative and abuse cases from the 2026-08-26 audit: a hostile or broken
 * agent cannot crash the relay, a corrupt claims file cannot fail open,
 * sessions die with their claim, the login gate cannot be dodged by forging
 * the proxied client IP, the agent's local-only surface is bound to the
 * socket (not the Host header), E2E fails closed for unsealed /api traffic,
 * and rewritten documents carry no cache validators.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DSHN_PROTOCOL_VERSION, decodeControl, encodeControl, type ControlFrame } from '@dshn/protocol'
import { ClaimStore } from '../src/claims.js'
import { RelayServer } from '../src/server.js'
import { AgentTunnel, fileStore, isLoopbackRequest } from '../../agent/lib/index.js'

const require = createRequire(new URL('../../agent/package.json', import.meta.url))
const { WebSocket } = require('ws') as typeof import('ws')

const APEX = 'test.local'
const PASSWORD = 'password123'
const ADMIN_PW = 'admin-secret-1'

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
async function until(cond: () => boolean, ms = 5000): Promise<void> {
  const start = Date.now()
  while (!cond()) { if (Date.now() - start > ms) throw new Error('timeout'); await sleep(15) }
}

/** A raw socket on the agent path that records frames and its close. */
function rawAgent(port: number): { ws: InstanceType<typeof WebSocket>; frames: ControlFrame[]; closed: Promise<number>; opened: Promise<void> } {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/dshn-agent`)
  const frames: ControlFrame[] = []
  const opened = new Promise<void>((r) => ws.on('open', r))
  const closed = new Promise<number>((r) => ws.on('close', (code: number) => r(code)))
  ws.on('error', () => { /* expected on terminate */ })
  ws.on('message', (data: Buffer, isBinary: boolean) => {
    if (isBinary) return
    try { frames.push(decodeControl(data.toString()) as ControlFrame) } catch { /* ignore */ }
    const last = frames[frames.length - 1]
    if (last?.t === 'ping') ws.send(encodeControl({ t: 'pong' }))
  })
  return { ws, frames, closed, opened }
}

async function hello(port: number, fields: Record<string, unknown>): Promise<ReturnType<typeof rawAgent>> {
  const a = rawAgent(port)
  await a.opened
  a.ws.send(JSON.stringify(fields))
  return a
}

const goodHello = (subdomain: string, password = PASSWORD, deviceId = 'd1') =>
  ({ t: 'hello', subdomain, password, agent: 'test', protocol: DSHN_PROTOCOL_VERSION, deviceId, device: 'Test' })

interface Res { status: number; headers: http.IncomingHttpHeaders; body: string }
function request(port: number, host: string, path: string, opts: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: opts.method ?? 'GET' }, (res) => {
      let body = ''
      res.on('data', (c: Buffer) => { body += c.toString() })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }))
    })
    req.setHeader('host', host)
    for (const [k, v] of Object.entries(opts.headers ?? {})) req.setHeader(k, v)
    req.on('error', reject)
    req.end(opts.body)
  })
}

function cookieOf(res: Res, name: string): string | undefined {
  return ([] as string[]).concat(res.headers['set-cookie'] ?? []).find((c) => c.startsWith(`${name}=`))?.split(';', 1)[0]
}

describe('relay hardening', () => {
  let dir: string, relay: RelayServer, port: number, admin: string

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'dshn-hard-'))
    relay = new RelayServer({
      apex: APEX, port: 0, cookieSecret: 'cookie-secret-value-hardening', claims: ClaimStore.fromFile(join(dir, 'claims.json')),
      adminPassword: ADMIN_PW, helloTimeoutMs: 300, helloPerMinute: 1000,
    })
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port()
    const login = await request(port, APEX, '/__admin/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `password=${ADMIN_PW}` })
    admin = cookieOf(login, 'dshn_admin')!
  })
  afterAll(() => { relay.close(); rmSync(dir, { recursive: true, force: true }) })

  it('a HELLO missing its password is denied — the relay does not crash', async () => {
    // The audit's crash repro: password absent, so the old `password.length`
    // threw. It has a valid subdomain and protocol so the check reaches password.
    const bad = await hello(port, { t: 'hello', subdomain: 'audit', protocol: DSHN_PROTOCOL_VERSION })
    expect(await bad.closed).toBeGreaterThan(0)
    expect(bad.frames.find((f) => f.t === 'deny')).toMatchObject({ reason: expect.stringContaining('password') })
    // Still alive: a proper agent gets in right after.
    const good = await hello(port, goodHello('alive'))
    await until(() => good.frames.some((f) => f.t === 'ready'))
    good.ws.close()
  })

  it('binary, non-JSON and wrong-protocol first frames are all denied', async () => {
    const bin = rawAgent(port); await bin.opened; bin.ws.send(Buffer.from([1, 2, 3]))
    expect(await bin.closed).toBeGreaterThan(0)
    const junk = rawAgent(port); await junk.opened; junk.ws.send('{not json')
    expect(await junk.closed).toBeGreaterThan(0)
    expect(junk.frames.find((f) => f.t === 'deny')).toMatchObject({ reason: 'malformed hello' })
    const wrongVersion = await hello(port, { ...goodHello('vers'), protocol: 99 })
    expect(await wrongVersion.closed).toBeGreaterThan(0)
    expect(wrongVersion.frames.find((f) => f.t === 'deny')).toMatchObject({ reason: expect.stringContaining('protocol version') })
    const longPw = await hello(port, goodHello('longpw', 'x'.repeat(1000)))
    expect(await longPw.closed).toBeGreaterThan(0)
    expect(longPw.frames.find((f) => f.t === 'deny')).toMatchObject({ reason: expect.stringContaining('too long') })
  })

  it('a socket that never says HELLO is dropped at the deadline', async () => {
    const silent = rawAgent(port)
    await silent.opened
    const t0 = Date.now()
    expect(await silent.closed).toBeGreaterThan(0)
    expect(Date.now() - t0).toBeLessThan(3000)
  })

  it('a malformed frame after HELLO ends that agent connection, nothing else', async () => {
    const a = await hello(port, goodHello('framing'))
    await until(() => a.frames.some((f) => f.t === 'ready'))
    const b = await hello(port, goodHello('bystander'))
    await until(() => b.frames.some((f) => f.t === 'ready'))
    a.ws.send('{oops')
    expect(await a.closed).toBeGreaterThan(0)
    // The bystander is untouched.
    await sleep(100)
    expect(b.ws.readyState).toBe(WebSocket.OPEN)
    b.ws.close()
  })

  it('a corrupt claims file refuses to load instead of failing open', async () => {
    const p = join(dir, 'corrupt.json')
    writeFileSync(p, 'not json at all')
    expect(() => ClaimStore.fromFile(p)).toThrow(/refusing to start/)
    writeFileSync(p, JSON.stringify({ claims: { taken: { hash: 'zz', salt: 'aa', createdAt: 1 } } }))
    expect(() => ClaimStore.fromFile(p)).toThrow(/bad hash/)
    writeFileSync(p, JSON.stringify({ claims: {}, banned: 'nope' }))
    expect(() => ClaimStore.fromFile(p)).toThrow(/banned/)
    // Absent → fresh; a real store written by the store itself round-trips.
    expect(ClaimStore.fromFile(join(dir, 'absent.json')).isClaimed('x')).toBe(false)
    const good = join(dir, 'good.json')
    const store = ClaimStore.fromFile(good)
    expect((await store.claimOrVerify('roundtrip', 'a-good-password', Date.now())).claimed).toBe(true)
    expect(ClaimStore.fromFile(good).isClaimed('roundtrip')).toBe(true)
  })

  it('browser sessions die with the claim and do not carry over to the next owner', async () => {
    const owner = await hello(port, goodHello('revoke'))
    await until(() => owner.frames.some((f) => f.t === 'ready'))
    const host = `revoke.${APEX}`
    const login = await request(port, host, '/__dshn/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `password=${PASSWORD}` })
    expect(login.status).toBe(302)
    const session = cookieOf(login, 'dshn_sess')!
    const authed = () => request(port, host, '/__dshn/devices', { headers: { cookie: session, accept: 'application/json' } })
    expect((await authed()).headers['content-type']).toContain('application/json')

    // Admin releases the name: the session is dead at once.
    const rel = await request(port, APEX, '/__admin/api/release', { method: 'POST', headers: { cookie: admin, 'content-type': 'application/json' }, body: JSON.stringify({ subdomain: 'revoke' }) })
    expect(rel.status).toBe(200)
    await owner.closed
    expect((await authed()).headers['content-type']).toContain('text/html')

    // Someone else claims the name with their own password: the old cookie
    // still opens nothing; their password mints a session that works.
    const next = await hello(port, goodHello('revoke', 'another-password-9', 'd2'))
    await until(() => next.frames.some((f) => f.t === 'ready'))
    expect((await authed()).headers['content-type']).toContain('text/html')
    const login2 = await request(port, host, '/__dshn/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'password=another-password-9' })
    expect(login2.status).toBe(302)
    const session2 = cookieOf(login2, 'dshn_sess')!
    expect((await request(port, host, '/__dshn/devices', { headers: { cookie: session2, accept: 'application/json' } })).headers['content-type']).toContain('application/json')
    next.ws.close()
  })

  it('the login lockout cannot be dodged by forging cf-connecting-ip per guess', async () => {
    const a = await hello(port, goodHello('gate'))
    await until(() => a.frames.some((f) => f.t === 'ready'))
    const host = `gate.${APEX}`
    const attempt = (i: number) => request(port, host, '/__dshn/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': `10.0.${Math.floor(i / 250)}.${i % 250}` },
      body: 'password=wrong-password-x',
    })
    let status = 0
    for (let i = 0; i < 70 && status !== 429; i += 1) status = (await attempt(i)).status
    expect(status).toBe(429) // the socket-peer gate closed despite a fresh "client IP" every time
    a.ws.close()
  }, 30000)
})

describe('agent hardening', () => {
  const fakeReq = (host: string, remoteAddress: string | undefined, extra: Record<string, string> = {}) =>
    ({ headers: { host, ...extra }, socket: { remoteAddress } }) as unknown as http.IncomingMessage

  it('the local-only surface is bound to the socket, not the Host header', () => {
    expect(isLoopbackRequest(fakeReq('localhost:3080', '127.0.0.1'))).toBe(true)
    expect(isLoopbackRequest(fakeReq('127.0.0.1:3080', '::ffff:127.0.0.1'))).toBe(true)
    expect(isLoopbackRequest(fakeReq('[::1]:3080', '::1'))).toBe(true)
    expect(isLoopbackRequest(fakeReq('localhost:3080', '10.0.0.5'))).toBe(false) // spoofed Host from the LAN
    expect(isLoopbackRequest(fakeReq('localhost:3080', undefined))).toBe(false)
    expect(isLoopbackRequest(fakeReq('127.0.0.1:3080', '127.0.0.1', { 'x-dshn-forwarded': '1' }))).toBe(false) // replayed through the tunnel
    expect(isLoopbackRequest(fakeReq('alice.ds.hn', '127.0.0.1'))).toBe(false)
  })

  it('refuses plain ws:// to anything but loopback', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dshn-ws-'))
    const config = { enabled: true, relayHost: 'ws://relay.example.invalid:1', localHost: '127.0.0.1', localPort: 1, originCa: '', statePath: join(dir, 'creds.json') }
    const tunnel = new AgentTunnel(config as any, () => 1, fileStore(config.statePath))
    tunnel.configure('plainws', PASSWORD)
    await until(() => String(tunnel.status.lastError ?? '').includes('wss://'))
    expect(tunnel.status.connected).toBe(false)
    tunnel.stop()
    rmSync(dir, { recursive: true, force: true })
  })

  it('a configured CA file that cannot be read stops the dial instead of trusting the system store', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dshn-ca-'))
    const config = { enabled: true, relayHost: 'wss://relay.example.invalid', localHost: '127.0.0.1', localPort: 1, originCa: join(dir, 'missing-ca.pem'), statePath: join(dir, 'creds.json') }
    const tunnel = new AgentTunnel(config as any, () => 1, fileStore(config.statePath))
    tunnel.configure('pinned', PASSWORD)
    await until(() => String(tunnel.status.lastError ?? '').includes('cannot read the relay CA'))
    tunnel.stop()
    rmSync(dir, { recursive: true, force: true })
  })

  describe('with E2E on, through a real relay', () => {
    let dir: string, relay: RelayServer, port: number, origin: http.Server, tunnel: AgentTunnel, session: string
    const SUB = 'closed'
    const host = () => `${SUB}.${APEX}`

    beforeAll(async () => {
      dir = mkdtempSync(join(tmpdir(), 'dshn-e2eclosed-'))
      origin = http.createServer((req, res) => {
        if (req.url === '/api/ping') { res.writeHead(200, { 'content-type': 'application/json', etag: '"api-v1"' }); res.end('{"ok":true}'); return }
        if (req.headers['if-none-match'] === '"shell-v1"') { res.writeHead(304); res.end(); return }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', etag: '"shell-v1"', 'last-modified': 'Tue, 26 Aug 2026 00:00:00 GMT', 'cache-control': 'max-age=600' })
        res.end('<!doctype html><html><head><title>s</title></head><body>app</body></html>')
      })
      await new Promise<void>((r) => origin.listen(0, r))
      const originPort = (origin.address() as any).port
      relay = new RelayServer({ apex: APEX, port: 0, cookieSecret: 'cookie-secret-value-e2eclosed', claims: ClaimStore.fromFile(join(dir, 'claims.json')), helloPerMinute: 1000 })
      await new Promise<void>((r) => relay.listen(r))
      port = relay.port()
      const config = { enabled: true, relayHost: `ws://127.0.0.1:${port}`, localHost: '127.0.0.1', localPort: originPort, originCa: '', statePath: join(dir, 'creds.json') }
      tunnel = new AgentTunnel(config as any, () => originPort, fileStore(config.statePath))
      tunnel.configure(SUB, PASSWORD)
      expect(tunnel.setE2E('e2e-password-1')).toBeNull()
      await until(() => tunnel.status.connected)
      const login = await request(port, host(), '/__dshn/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `password=${PASSWORD}` })
      session = cookieOf(login, 'dshn_sess')!
    })
    afterAll(() => { tunnel.stop(); relay.close(); origin.close(); rmSync(dir, { recursive: true, force: true }) })

    it('an /api request that did not go through the shim is refused, never forwarded in plaintext', async () => {
      const res = await request(port, host(), '/api/ping', { method: 'POST', headers: { cookie: session, 'content-type': 'application/json' }, body: '{}' })
      expect(res.status).toBe(428)
      expect(JSON.parse(res.body)).toMatchObject({ error: expect.stringContaining('end-to-end') })
      expect(res.body).not.toContain('"ok"')
    })

    it('sealed responses and rewritten documents carry no validators and are never cached', async () => {
      const api = await request(port, host(), '/api/ping', { headers: { cookie: session, 'x-dshn-e2e': '1' } })
      expect(api.status).toBe(200)
      expect(api.headers['x-dshn-e2e']).toBe('1')
      expect(api.headers.etag).toBeUndefined()
      expect(api.headers['cache-control']).toBe('no-store')
      // A conditional navigation is answered in full (the origin would have said
      // 304 to the browser's validator), with the validators stripped.
      const doc = await request(port, host(), '/', { headers: { cookie: session, accept: 'text/html', 'if-none-match': '"shell-v1"' } })
      expect(doc.status).toBe(200)
      expect(doc.body).toContain('__dshnInfo')
      expect(doc.headers.etag).toBeUndefined()
      expect(doc.headers['last-modified']).toBeUndefined()
      expect(doc.headers['cache-control']).toBe('no-store')
    })
  })
})
