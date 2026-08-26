/**
 * The E2E bootstrap the host injects into HTML documents when end-to-end
 * encryption is on: placement in the document, that the script parses, and —
 * with a real AgentTunnel behind a real RelayServer — that a browser navigation
 * through the tunnel gets it while non-document requests and the /api sealing
 * are untouched.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { ClaimStore } from '../src/claims.js'
import { RelayServer } from '../src/server.js'
import { AgentTunnel, fileStore } from '../../agent/lib/index.js'
import { credentialManifestLinks, e2eBootstrapTag, injectE2EBootstrap } from '../../agent/lib/e2e-shim.js'

const APEX = 'test.local'
const SUB = 'sealed'
const PASSWORD = 'password123'
const E2E_PW = 'e2e-secret-pw'
const INFO = { salt: 'e3f5c44283c186739ee2064db15793ef', device: '123d3ef65aae' }
const SHELL = '<!doctype html>\n<html lang="en">\n  <head><script>window.__first = "dsh"</script><link rel="manifest" href="/manifest.webmanifest" /><title>t</title></head><body>app</body></html>'
/** SHELL as every tunnelled navigation sees it: the manifest link fetches with credentials. */
const SHELL_OUT = SHELL.replace('<link rel="manifest" href="/manifest.webmanifest" />', '<link rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials" />')

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
async function until(cond: () => boolean, ms = 6000): Promise<void> {
  const start = Date.now()
  while (!cond()) { if (Date.now() - start > ms) throw new Error('timeout'); await sleep(20) }
}

describe('E2E bootstrap injection', () => {
  it('goes first inside <head>, ahead of the document\'s own scripts', () => {
    const out = injectE2EBootstrap(SHELL, INFO)
    const tag = e2eBootstrapTag(INFO)
    expect(out.indexOf(tag)).toBe(SHELL.indexOf('<head>') + '<head>'.length)
    expect(out.indexOf(tag)).toBeLessThan(out.indexOf('window.__first'))
    expect(out.endsWith('</html>')).toBe(true)
  })

  it('falls back to <html>, then to the very start', () => {
    expect(injectE2EBootstrap('<html><body>x</body></html>', INFO).startsWith('<html><script>')).toBe(true)
    expect(injectE2EBootstrap('<body>x</body>', INFO).startsWith('<script>')).toBe(true)
    expect(injectE2EBootstrap('<HEAD data-x="1">y</HEAD>', INFO).startsWith('<HEAD data-x="1"><script>')).toBe(true)
  })

  it('makes manifest links fetch with credentials, leaving other links and explicit ones alone', () => {
    expect(credentialManifestLinks(SHELL)).toBe(SHELL_OUT)
    expect(credentialManifestLinks('<link rel="manifest" href="/m.json">')).toBe('<link rel="manifest" href="/m.json" crossorigin="use-credentials">')
    expect(credentialManifestLinks('<link href="/m.json" rel=manifest>')).toBe('<link href="/m.json" rel=manifest crossorigin="use-credentials">')
    const keep = '<link rel="stylesheet" href="/a.css"><link rel="manifest" href="/m.json" crossorigin="anonymous">'
    expect(credentialManifestLinks(keep)).toBe(keep)
  })

  it('is one script that parses, carries the info inline and cannot break out of the tag', () => {
    const tag = e2eBootstrapTag({ salt: 'ab', device: '</script><b>' })
    expect(tag.startsWith('<script>') && tag.endsWith('</script>')).toBe(true)
    expect(tag.indexOf('</script>')).toBe(tag.length - '</script>'.length) // the payload's </script> is escaped
    const js = tag.slice('<script>'.length, -'</script>'.length)
    expect(() => new Function(js)).not.toThrow()
    expect(js).toContain('"salt":"ab"')
    expect(js).not.toContain('/dshn-e2e') // no async discovery any more
  })
})

describe('E2E bootstrap through a real tunnel', () => {
  let dir: string, relay: RelayServer, port: number, origin: http.Server, originPort: number, tunnel: AgentTunnel, session: string
  const seen: Array<{ path: string; encoding: string | undefined; accept: string | undefined }> = []

  function request(path: string, headers: Record<string, string> = {}, method = 'GET', body?: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
    return new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path, method }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }))
      })
      req.setHeader('host', `${SUB}.${APEX}`)
      for (const [k, v] of Object.entries(headers)) req.setHeader(k, v)
      req.on('error', reject); req.end(body)
    })
  }

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'dshn-e2eshim-'))
    origin = http.createServer((req, res) => {
      seen.push({ path: req.url ?? '', encoding: req.headers['accept-encoding'] as string | undefined, accept: req.headers.accept })
      if (req.url === '/api/ping') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); return }
      if (req.url === '/style.css') { res.writeHead(200, { 'content-type': 'text/css' }); res.end('body{}'); return }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(SHELL)
    })
    await new Promise<void>((r) => origin.listen(0, r))
    originPort = (origin.address() as any).port
    relay = new RelayServer({ apex: APEX, port: 0, cookieSecret: 'cookie-secret-value-here-e2', claims: ClaimStore.fromFile(join(dir, 'claims.json')) })
    await new Promise<void>((r) => relay.listen(r))
    port = relay.port()
    const config = { enabled: true, relayHost: `ws://127.0.0.1:${port}`, localHost: '127.0.0.1', localPort: originPort, originCa: '', statePath: join(dir, 'creds.json') }
    tunnel = new AgentTunnel(config as any, () => originPort, fileStore(config.statePath))
    tunnel.configure(SUB, PASSWORD)
    expect(tunnel.setE2E(E2E_PW)).toBeNull()
    await until(() => tunnel.status.connected)
    const login = await request('/__dshn/login', { 'content-type': 'application/x-www-form-urlencoded' }, 'POST', `password=${PASSWORD}`)
    expect(login.status).toBe(302)
    session = String(login.headers['set-cookie']![0]).split(';', 1)[0]
  })
  afterAll(() => { tunnel.stop(); relay.close(); origin.close(); rmSync(dir, { recursive: true, force: true }) })

  it('a browser navigation gets the bootstrap first in <head>, with the live salt and device', async () => {
    const res = await request('/', { cookie: session, accept: 'text/html,application/xhtml+xml,*/*;q=0.8', 'accept-encoding': 'gzip, br' })
    expect(res.status).toBe(200)
    const html = res.body.toString('utf8')
    const info = tunnel.e2eInfo()
    expect(html).toBe(injectE2EBootstrap(SHELL_OUT, { salt: info.salt, device: tunnel.deviceId }))
    expect(html.indexOf('(function (__dshnInfo)')).toBeLessThan(html.indexOf('window.__first'))
    expect(Number(res.headers['content-length'])).toBe(res.body.length)
    // The origin was asked for plaintext so the document could be edited.
    expect(seen.find((s) => s.path === '/')?.encoding).toBe('identity')
  })

  it('leaves non-document responses and non-navigation requests alone', async () => {
    const css = await request('/style.css', { cookie: session, accept: 'text/css,*/*;q=0.1' })
    expect(css.body.toString()).toBe('body{}')
    const xhr = await request('/', { cookie: session, accept: 'application/json' })
    expect(xhr.body.toString('utf8')).toBe(SHELL)
  })

  it('still seals /api requests the shim marked', async () => {
    const api = await request('/api/ping', { cookie: session, accept: 'application/json', 'x-dshn-e2e': '1' })
    expect(api.headers['x-dshn-e2e']).toBe('1')
    expect(api.body.toString('utf8')).not.toContain('"ok"')
  })

  it('with E2E off still fixes the manifest link but injects no bootstrap', async () => {
    expect(tunnel.setE2E('')).toBeNull()
    const res = await request('/', { cookie: session, accept: 'text/html' })
    expect(res.body.toString('utf8')).toBe(SHELL_OUT)
    expect(Number(res.headers['content-length'])).toBe(res.body.length)
  })
})
