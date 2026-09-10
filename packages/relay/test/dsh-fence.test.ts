/**
 * The two things that had to change for dsh ≥ 0.1.2-rc.1:
 *
 *  - Its `/api` fence grew a signed, authority-bound browser-session cookie in
 *    front of BOTH the app shell and every API call. A public visitor cannot
 *    hold one (their browser's cookies are for the public authority; every
 *    replay's Host is rewritten to loopback), so without the agent presenting
 *    dsh's own cookie the tunnel forwards `401 dsh web authentication required`
 *    and nothing else. The origin here is a faithful stand-in for that fence:
 *    same cookie name derivation, same token-for-cookie 303, same 401.
 *
 *  - Nothing on the path compresses, so the agent does — the uplink to the
 *    relay is the narrow hop. `shouldGzip` decides; these cases pin the
 *    decision and one real round trip through a live relay + tunnel.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { createHash } from 'node:crypto'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { ClaimStore } from '../src/claims.js'
import { RelayServer } from '../src/server.js'
import { AgentTunnel, fileStore } from '../../agent/lib/index.js'
import { DshAuth } from '../../agent/lib/dsh-auth.js'
import { acceptsGzip, shouldGzip } from '../../agent/lib/compress.js'

const APEX = 'test.local'
const SUB = 'fenced'
const PASSWORD = 'password123'
/** The launch token this fake dsh process hands out, exactly once per URL mint. */
const TOKEN = 'launch-token-abcdefghijklmnop'
const SHELL = '<!doctype html>\n<html><head><title>t</title></head><body>app</body></html>'
/** Big enough to be worth compressing, and compressible. */
const BUNDLE = `/* dsh bundle */\n${'export const chunk = "aaaaaaaaaaaaaaaaaaaaaaaa";\n'.repeat(400)}`

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
async function until(cond: () => boolean, ms = 6000): Promise<void> {
  const start = Date.now()
  while (!cond()) { if (Date.now() - start > ms) throw new Error('timeout'); await sleep(20) }
}

/** Clear the relay's login gate and return the session cookie pair. */
function login(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: '/__dshn/login', method: 'POST', headers: { host: `${SUB}.${APEX}`, 'content-type': 'application/x-www-form-urlencoded' } },
      (res) => { res.resume(); res.on('end', () => resolve(String(res.headers['set-cookie']![0]).split(';', 1)[0])) },
    )
    req.on('error', reject); req.end(`password=${PASSWORD}`)
  })
}

/** dsh's own cookie-name derivation: the prefix plus base64url(sha256(authority)). */
function cookieName(authority: string): string {
  return `dsh-auth-${createHash('sha256').update(authority).digest('base64url')}`
}

describe('shouldGzip decides what the tunnel compresses', () => {
  const facts = (headers: Record<string, string>, status = 200) => ({
    status,
    header: (name: string) => headers[name],
  })
  const GZIP = 'gzip, deflate, br'
  const BIG = { 'content-type': 'application/javascript', 'content-length': '500000' }

  it('compresses the text families a dsh app is made of', () => {
    for (const type of ['text/html', 'application/javascript', 'text/css', 'application/json', 'image/svg+xml', 'application/manifest+json']) {
      expect(shouldGzip(facts({ 'content-type': type }), 'GET', GZIP), type).toBe(true)
    }
  })

  it('leaves already-compressed and opaque payloads alone', () => {
    for (const type of ['image/png', 'font/woff2', 'application/zip', 'video/mp4']) {
      expect(shouldGzip(facts({ 'content-type': type }), 'GET', GZIP), type).toBe(false)
    }
    // An unlabelled body is opaque, not an opportunity.
    expect(shouldGzip(facts({}), 'GET', GZIP)).toBe(false)
  })

  it('never compresses a live stream: latency is the point of an event stream', () => {
    expect(shouldGzip(facts({ 'content-type': 'text/event-stream' }), 'GET', GZIP)).toBe(false)
  })

  it('does not re-encode what dsh already encoded', () => {
    expect(shouldGzip(facts({ ...BIG, 'content-encoding': 'gzip' }), 'GET', GZIP)).toBe(false)
    expect(shouldGzip(facts({ ...BIG, 'content-encoding': 'br' }), 'GET', GZIP)).toBe(false)
    // `identity` is not an encoding, so it stays eligible.
    expect(shouldGzip(facts({ ...BIG, 'content-encoding': 'identity' }), 'GET', GZIP)).toBe(true)
  })

  it('skips bodies that are absent, ranged, or too small to pay for the framing', () => {
    expect(shouldGzip(facts(BIG, 204), 'GET', GZIP)).toBe(false)
    expect(shouldGzip(facts(BIG, 304), 'GET', GZIP)).toBe(false)
    expect(shouldGzip(facts({ ...BIG, 'content-range': 'bytes 0-99/500000' }, 206), 'GET', GZIP)).toBe(false)
    expect(shouldGzip(facts(BIG, 200), 'HEAD', GZIP)).toBe(false)
    expect(shouldGzip(facts({ 'content-type': 'application/json', 'content-length': '12' }), 'GET', GZIP)).toBe(false)
    // A streamed body of unknown length is worth compressing.
    expect(shouldGzip(facts({ 'content-type': 'application/json' }), 'GET', GZIP)).toBe(true)
  })

  it('only compresses for a visitor that actually offered gzip', () => {
    expect(shouldGzip(facts(BIG), 'GET', undefined)).toBe(false)
    expect(shouldGzip(facts(BIG), 'GET', 'br')).toBe(false)
    expect(acceptsGzip('gzip;q=0')).toBe(false) // an explicit refusal
    expect(acceptsGzip('br, gzip;q=0.5')).toBe(true)
    expect(acceptsGzip('*')).toBe(true)
  })
})

describe('a tunnel against a dsh that fences its app behind a session cookie', () => {
  let dir: string, relay: RelayServer, port: number, origin: http.Server, originPort: number
  let tunnel: AgentTunnel, session: string
  /** Every request the fake dsh saw, so the assertions can inspect the replay. */
  const seen: Array<{ path: string; cookie: string | undefined; encoding: string | undefined }> = []
  /** Rotating this is how a real dsh invalidates every cookie it ever minted. */
  let secret = 'fence-secret-1'

  function request(path: string, headers: Record<string, string> = {}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer; raw: Buffer }> {
    return new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          const raw = Buffer.concat(chunks)
          const body = res.headers['content-encoding'] === 'gzip' ? gunzipSync(raw) : raw
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body, raw })
        })
      })
      req.setHeader('host', `${SUB}.${APEX}`)
      for (const [k, v] of Object.entries(headers)) req.setHeader(k, v)
      req.on('error', reject); req.end()
    })
  }

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'dshn-fence-'))
    origin = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://x')
      const authority = String(req.headers.host ?? '')
      const cookies = String(req.headers.cookie ?? '')
      seen.push({ path: req.url ?? '', cookie: req.headers.cookie as string | undefined, encoding: req.headers['accept-encoding'] as string | undefined })

      // The token-for-cookie exchange, as dsh does it: GET / with the launch
      // token, answered 303 with a cookie bound to the Host it arrived on.
      if (url.pathname === '/' && url.searchParams.get('token') === TOKEN) {
        res.writeHead(303, { location: '/', 'set-cookie': `${cookieName(authority)}=${secret}; Path=/; HttpOnly; SameSite=Strict` })
        res.end()
        return
      }
      // The fence: no valid cookie for THIS authority, no app.
      const expected = `${cookieName(authority)}=${secret}`
      if (!cookies.split(';').map((c) => c.trim()).includes(expected)) {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('dsh web authentication required; reopen the URL printed by dsh web.\n')
        return
      }
      if (url.pathname === '/bundle.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end(BUNDLE); return }
      if (url.pathname === '/logo.png') { res.writeHead(200, { 'content-type': 'image/png' }); res.end(Buffer.alloc(4096, 7)); return }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(SHELL)
    })
    await new Promise<void>((r) => origin.listen(0, r))
    originPort = (origin.address() as any).port

    relay = new RelayServer({ apex: APEX, port: 0, cookieSecret: 'cookie-secret-value-here-fen', claims: ClaimStore.fromFile(join(dir, 'claims.json')) })
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port()

    const config = { enabled: true, relayHost: `ws://127.0.0.1:${port}`, localHost: '127.0.0.1', localPort: originPort, originCa: '', statePath: join(dir, 'creds.json') }
    // Stand in for dsh's `connection` service: the one method the agent needs.
    const auth = new DshAuth({
      connection: () => ({ authenticatedUrl: (base: string) => `${base}/?token=${TOKEN}` }),
      authority: () => `127.0.0.1:${originPort}`,
      host: () => '127.0.0.1',
      port: () => originPort,
    })
    tunnel = new AgentTunnel(config as any, () => originPort, fileStore(config.statePath), auth)
    expect(tunnel.configure(SUB, PASSWORD)).toBeNull()
    await until(() => tunnel.status.connected)
    session = await login(port)
  })
  afterAll(() => { tunnel.stop(); relay.close(); origin.close(); rmSync(dir, { recursive: true, force: true }) })

  it('serves the app instead of a 401: the agent presents dsh\'s own session cookie', async () => {
    const res = await request('/', { cookie: session, accept: 'text/html' })
    expect(res.status).toBe(200)
    expect(res.body.toString('utf8')).toContain('<body>app</body>')
    const replay = seen.findLast((s) => s.path === '/')
    expect(replay?.cookie).toContain(cookieName(`127.0.0.1:${originPort}`))
  })

  it('drops a visitor-forged dsh-auth cookie so it cannot shadow the real one', async () => {
    const forged = `dsh-auth-${createHash('sha256').update(`127.0.0.1:${originPort}`).digest('base64url')}=forged`
    const res = await request('/', { cookie: `${session}; ${forged}`, accept: 'text/html' })
    expect(res.status).toBe(200)
    const replay = seen.findLast((s) => s.path === '/')
    expect(replay?.cookie).not.toContain('forged')
  })

  it('keeps the visitor\'s unrelated cookies alongside it', async () => {
    const res = await request('/', { cookie: `${session}; theme=dark`, accept: 'text/html' })
    expect(res.status).toBe(200)
    const replay = seen.findLast((s) => s.path === '/')
    expect(replay?.cookie).toContain('theme=dark')
    expect(replay?.cookie).toContain(cookieName(`127.0.0.1:${originPort}`))
  })

  it('recovers on its own after dsh rotates the signing secret', async () => {
    secret = 'fence-secret-2' // every cookie dsh ever minted is now worthless
    // One request discovers the staleness and hands the visitor dsh's own 401 —
    // and that same 401 is what tells the agent to mint a fresh cookie.
    const stale = await request('/', { cookie: session, accept: 'text/html' })
    expect(stale.status).toBe(401)
    // The re-exchange runs in the background; the requests after it succeed
    // again with no intervention.
    let status = 0
    for (let attempt = 0; attempt < 50 && status !== 200; attempt++) {
      await sleep(40)
      status = (await request('/', { cookie: session, accept: 'text/html' })).status
    }
    expect(status).toBe(200)
  })

  it('gzips a bundle on the way into the tunnel, and leaves a PNG alone', async () => {
    const js = await request('/bundle.js', { cookie: session, 'accept-encoding': 'gzip, br' })
    expect(js.status).toBe(200)
    expect(js.headers['content-encoding']).toBe('gzip')
    expect(js.headers.vary).toContain('accept-encoding')
    expect(js.body.toString('utf8')).toBe(BUNDLE)
    // The whole point: markedly fewer bytes crossed the uplink.
    expect(js.raw.length).toBeLessThan(js.body.length / 2)

    const png = await request('/logo.png', { cookie: session, 'accept-encoding': 'gzip, br' })
    expect(png.headers['content-encoding']).toBeUndefined()
    expect(png.body.length).toBe(4096)
  })

  it('sends plaintext to a visitor that did not offer gzip', async () => {
    const js = await request('/bundle.js', { cookie: session })
    expect(js.headers['content-encoding']).toBeUndefined()
    expect(js.body.toString('utf8')).toBe(BUNDLE)
  })
})

describe('a tunnel against a dsh with no fence at all', () => {
  let dir: string, relay: RelayServer, port: number, origin: http.Server, originPort: number
  let tunnel: AgentTunnel
  const seen: string[] = []

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'dshn-nofence-'))
    origin = http.createServer((req, res) => {
      seen.push(String(req.headers.cookie ?? ''))
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(SHELL)
    })
    await new Promise<void>((r) => origin.listen(0, r))
    originPort = (origin.address() as any).port
    relay = new RelayServer({ apex: APEX, port: 0, cookieSecret: 'cookie-secret-value-here-nof', claims: ClaimStore.fromFile(join(dir, 'claims.json')) })
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port()
    const config = { enabled: true, relayHost: `ws://127.0.0.1:${port}`, localHost: '127.0.0.1', localPort: originPort, originCa: '', statePath: join(dir, 'creds.json') }
    // A dsh predating the fence provides no `connection` service.
    const auth = new DshAuth({
      connection: () => undefined,
      authority: () => `127.0.0.1:${originPort}`,
      host: () => '127.0.0.1',
      port: () => originPort,
    })
    tunnel = new AgentTunnel(config as any, () => originPort, fileStore(config.statePath), auth)
    expect(tunnel.configure(SUB, PASSWORD)).toBeNull()
    await until(() => tunnel.status.connected)
  })
  afterAll(() => { tunnel.stop(); relay.close(); origin.close(); rmSync(dir, { recursive: true, force: true }) })

  it('stays inert: nothing to authenticate, nothing added, no request parked', async () => {
    const session = await login(port)
    const res = await new Promise<number>((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: '/', method: 'GET', headers: { host: `${SUB}.${APEX}`, cookie: `${session}; theme=dark`, accept: 'text/html' } }, (r) => { r.resume(); r.on('end', () => resolve(r.statusCode ?? 0)) })
      req.on('error', reject); req.end()
    })
    expect(res).toBe(200)
    const replay = seen.at(-1) ?? ''
    expect(replay).toContain('theme=dark')
    expect(replay).not.toContain('dsh-auth-')
  })
})
