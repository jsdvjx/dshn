/**
 * Multi-device routing, end to end against a real RelayServer: two fake agents
 * hold ONE subdomain with distinct device ids, and public requests are routed
 * by the `dshn_dev` cookie — with the picker page on ambiguous navigations, the
 * longest-connected device for ambiguous API calls, fail-closed on a selection
 * pointing at a dead device, and the legacy one-agent-per-subdomain behavior
 * preserved for agents that send no device id.
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
const SUB = 'testsub'
const HOST = `${SUB}.${APEX}`
const PASSWORD = 'password123'

/** A fake dshn agent: claims the subdomain and answers every request with its marker. */
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
        this.ws.send(encodeControl({ t: 'res_head', id: frame.id, status: 200, headers: [['content-type', 'text/plain'], ['x-device', this.marker]] }))
        this.ws.send(encodeData(DATA_RES_BODY, frame.id, Buffer.from(this.marker)))
        this.ws.send(encodeControl({ t: 'res_end', id: frame.id }))
      }
    })
  }
}

interface Res { status: number; headers: http.IncomingHttpHeaders; body: string }

/** One public HTTP request against the relay, with the tunnel Host set. */
function request(port: number, path: string, opts: {
  method?: string
  cookie?: string
  accept?: string
  contentType?: string
  body?: string
} = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: opts.method ?? 'GET' }, (res) => {
      let body = ''
      res.on('data', (c: Buffer) => { body += c.toString() })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }))
    })
    req.setHeader('host', HOST)
    if (opts.cookie !== undefined) req.setHeader('cookie', opts.cookie)
    if (opts.accept !== undefined) req.setHeader('accept', opts.accept)
    if (opts.contentType !== undefined) req.setHeader('content-type', opts.contentType)
    req.on('error', reject)
    req.end(opts.body)
  })
}

/** Poll the JSON device list until `cond` holds (the relay reacts to socket events async). */
async function untilDevices(port: number, cookie: string, cond: (j: any) => boolean): Promise<any> {
  for (let i = 0; i < 100; i++) {
    const res = await request(port, '/__dshn/devices', { cookie, accept: 'application/json' })
    const j = JSON.parse(res.body)
    if (cond(j)) return j
    await new Promise((r) => setTimeout(r, 20))
  }
  throw new Error('condition never held for /__dshn/devices')
}

describe('multi-device routing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dshn-mdev-'))
  const relay = new RelayServer({
    apex: APEX,
    port: 0,
    cookieSecret: 'test-cookie-secret',
    claims: ClaimStore.fromFile(join(dir, 'claims.json')),
  })
  let port = 0
  let session = '' // the dshn_sess login cookie pair
  let agentA: FakeAgent
  let agentB: FakeAgent

  beforeAll(async () => {
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port()

    agentA = new FakeAgent(port, { subdomain: SUB, password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A')
    await agentA.ready

    const login = await request(port, '/__dshn/login', {
      method: 'POST', contentType: 'application/x-www-form-urlencoded', body: `password=${PASSWORD}`,
    })
    expect(login.status).toBe(302)
    session = String(login.headers['set-cookie']![0]).split(';', 1)[0]
  })

  afterAll(() => {
    relay.close()
    rmSync(dir, { recursive: true, force: true })
  })

  it('routes the classic single-device path untouched', async () => {
    const res = await request(port, '/', { cookie: session, accept: 'text/html' })
    expect(res.status).toBe(200)
    expect(res.body).toBe('A')
  })

  it('keeps unauthenticated visitors at the login page in multi mode too', async () => {
    agentB = new FakeAgent(port, { subdomain: SUB, password: PASSWORD, deviceId: 'devb', device: 'Desktop B' }, 'B')
    await agentB.ready
    const res = await request(port, '/', { accept: 'text/html' })
    expect(res.status).toBe(200)
    expect(res.body).toContain('Access password')
    expect(res.body).not.toContain('Laptop A')
  })

  it('keeps unselected API requests on the longest-connected device', async () => {
    const res = await request(port, '/api/x', { cookie: session, accept: 'application/json' })
    expect(res.status).toBe(200)
    expect(res.body).toBe('A')
  })

  it('shows the picker page on an unselected navigation', async () => {
    const res = await request(port, '/', { cookie: session, accept: 'text/html' })
    expect(res.status).toBe(200)
    expect(res.body).toContain('Laptop A')
    expect(res.body).toContain('Desktop B')
    expect(res.body).toContain('/__dshn/select')
  })

  it('lists both devices as live in the JSON device list', async () => {
    const j = await untilDevices(port, session, (x) => x.live === 2)
    expect(j.multi).toBe(true)
    expect(j.devices.map((d: any) => d.id).sort()).toEqual(['deva', 'devb'])
    expect(j.devices.every((d: any) => d.online)).toBe(true)
  })

  it('selects a device and routes everything to it', async () => {
    const sel = await request(port, '/__dshn/select', {
      method: 'POST', cookie: session, contentType: 'application/json',
      accept: 'application/json', body: JSON.stringify({ device: 'devb' }),
    })
    expect(sel.status).toBe(200)
    const devCookie = String(sel.headers['set-cookie']![0]).split(';', 1)[0]
    expect(devCookie).toBe('dshn_dev=devb')
    const both = `${session}; ${devCookie}`
    const nav = await request(port, '/', { cookie: both, accept: 'text/html' })
    expect(nav.body).toBe('B')
    const api = await request(port, '/api/x', { cookie: both, accept: 'application/json' })
    expect(api.body).toBe('B')
  })

  it('answers the picker form select with a redirect home', async () => {
    const sel = await request(port, '/__dshn/select', {
      method: 'POST', cookie: session, contentType: 'application/x-www-form-urlencoded',
      body: 'device=deva',
    })
    expect(sel.status).toBe(302)
    expect(sel.headers.location).toBe('/')
    expect(String(sel.headers['set-cookie']![0])).toContain('dshn_dev=deva')
  })

  it('rejects selecting an unknown device', async () => {
    const sel = await request(port, '/__dshn/select', {
      method: 'POST', cookie: session, contentType: 'application/json',
      accept: 'application/json', body: JSON.stringify({ device: 'nope' }),
    })
    expect(sel.status).toBe(400)
  })

  it('fails closed when the selected device dies, and re-offers the picker', async () => {
    agentB.ws.close()
    await untilDevices(port, session, (x) => x.live === 1)
    const both = `${session}; dshn_dev=devb`
    const api = await request(port, '/api/x', { cookie: both, accept: 'application/json' })
    expect(api.status).toBe(502) // never silently lands on a DIFFERENT machine
    const nav = await request(port, '/', { cookie: both, accept: 'text/html' })
    expect(nav.status).toBe(200)
    expect(nav.body).toContain('Desktop B') // remembered, shown offline
    expect(nav.body).toContain('offline')
    // The un-selected single-device path still routes to the survivor.
    const plain = await request(port, '/', { cookie: session, accept: 'text/html' })
    expect(plain.body).toBe('A')
  })

  it('remembers the dead device in the claim store', async () => {
    const j = await untilDevices(port, session, (x) => x.devices.length === 2)
    const b = j.devices.find((d: any) => d.id === 'devb')
    expect(b.online).toBe(false)
    expect(b.name).toBe('Desktop B')
  })

  it('supersedes only the SAME device id on reconnect', async () => {
    const again = new FakeAgent(port, { subdomain: SUB, password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A2')
    await again.ready
    await agentA.closed // the old connection of deva was terminated…
    const j = await untilDevices(port, session, (x) => x.live === 1)
    expect(j.devices.filter((d: any) => d.online).map((d: any) => d.id)).toEqual(['deva'])
    const res = await request(port, '/', { cookie: session, accept: 'text/html' })
    expect(res.body).toBe('A2') // …and the new one serves
    again.ws.close()
    await untilDevices(port, session, (x) => x.live === 0) // settle before the next test
  })

  it('keeps the legacy one-agent-per-subdomain behavior for agents without a device id', async () => {
    const legacy1 = new FakeAgent(port, { subdomain: SUB, password: PASSWORD }, 'L1')
    await legacy1.ready
    const legacy2 = new FakeAgent(port, { subdomain: SUB, password: PASSWORD }, 'L2')
    await legacy2.ready
    await legacy1.closed // the second legacy agent knocked the first off
    const res = await request(port, '/', { cookie: session, accept: 'text/html' })
    expect(res.body).toBe('L2')
    legacy2.ws.close()
    await untilDevices(port, session, (x) => x.live === 0)
  })

  it('mixes a legacy agent with a device-id agent as two devices', async () => {
    const modern = new FakeAgent(port, { subdomain: SUB, password: PASSWORD, deviceId: 'deva', device: 'Laptop A' }, 'A3')
    await modern.ready
    const legacy = new FakeAgent(port, { subdomain: SUB, password: PASSWORD }, 'L')
    await legacy.ready
    const j = await untilDevices(port, session, (x) => x.live === 2)
    expect(j.multi).toBe(true)
    expect(j.devices.filter((d: any) => d.online).map((d: any) => d.id).sort()).toEqual(['deva', 'device'])
    // Unselected API traffic stays on the longest-connected device (the modern one).
    const api = await request(port, '/api/x', { cookie: session, accept: 'application/json' })
    expect(api.body).toBe('A3')
    modern.ws.close()
    legacy.ws.close()
    await untilDevices(port, session, (x) => x.live === 0)
  })

  it('keeps the device endpoints behind the login gate', async () => {
    const list = await request(port, '/__dshn/devices', { accept: 'application/json' })
    expect(list.body).toContain('Access password') // the login page, not JSON
    expect(list.headers['content-type']).toContain('text/html')
    const sel = await request(port, '/__dshn/select', {
      method: 'POST', contentType: 'application/json', accept: 'application/json',
      body: JSON.stringify({ device: 'deva' }),
    })
    expect(sel.headers['set-cookie']).toBeUndefined()
    expect(sel.body).toContain('Access password')
  })

  it('rejects malformed device ids without consulting the store', async () => {
    for (const device of ['UPPER', 'a b', 'x'.repeat(80), '../../etc', '<img>', '', 42, null]) {
      const sel = await request(port, '/__dshn/select', {
        method: 'POST', cookie: session, contentType: 'application/json',
        accept: 'application/json', body: JSON.stringify({ device }),
      })
      expect(sel.status, `device=${String(device)}`).toBe(400)
    }
  })

  it('escapes hostile device names in the picker HTML', async () => {
    const evil = new FakeAgent(port, {
      subdomain: SUB, password: PASSWORD, deviceId: 'evil', device: '<script>alert(1)</script>',
    }, 'E')
    await evil.ready
    await untilDevices(port, session, (x) => x.live === 1)
    // /__dshn/devices without an accept:json serves the picker page directly.
    const page = await request(port, '/__dshn/devices', { cookie: session })
    expect(page.headers['content-type']).toContain('text/html')
    expect(page.body).not.toContain('<script>alert(1)</script>')
    expect(page.body).toContain('&lt;script&gt;')
    evil.ws.close()
  })
})
