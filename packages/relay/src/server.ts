/**
 * The relay bridge. It listens on one plain HTTP port (Cloudflare terminates
 * TLS in front and forwards here), and does three jobs:
 *
 *   - accepts each device's agent on `AGENT_WS_PATH`, authenticates the token,
 *     and holds that one WebSocket as the device's control channel;
 *   - routes every public request by subdomain to the matching agent, gating it
 *     behind the login cookie first;
 *   - multiplexes HTTP requests and browser WebSocket upgrades over the agent's
 *     single socket, streaming bodies both ways.
 *
 * The relay never terminates dsh's own protocol — it moves bytes. Auth is the
 * one thing it enforces, because the thing on the other end is a shell.
 */
import http from 'node:http'
import https from 'node:https'
import { readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { Duplex } from 'node:stream'
import { WebSocket, WebSocketServer, type RawData } from 'ws'
import {
  AGENT_WS_PATH,
  DATA_REQ_BODY,
  DATA_RES_BODY,
  DATA_WS_BINARY,
  DATA_WS_TEXT,
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_TIMEOUT_MS,
  decodeControl,
  decodeData,
  encodeControl,
  encodeData,
  sanitizeCloseCode,
  sanitizeCloseReason,
  subdomainOf,
  type ControlFrame,
  type DataKind,
  type HeaderList,
} from '@dshn/protocol'
import { ClaimStore } from './claims.js'
import { COOKIE_NAME, cookieHeader, loginPage, parseCookies, sign, verify } from './auth.js'

/** Relay construction options, all operator-supplied via the entry point. */
export interface RelayOptions {
  /** Tunnel apex, e.g. `ds.hn`. */
  apex: string
  /** Plain HTTP port to listen on behind Cloudflare. */
  port: number
  /** HMAC secret for session cookies; rotating it logs everyone out. */
  cookieSecret: string
  /** Subdomain-claim authority (trust-on-first-use, password-guarded). */
  claims: ClaimStore
  /**
   * TLS material to serve HTTPS directly (Cloudflare "Full" origin pull). Omit
   * to serve plain HTTP — only safe when something in front terminates TLS.
   */
  tls?: { cert: Buffer; key: Buffer }
  /**
   * Path to the site's index.html, served on the bare apex (the project site).
   * Flat sibling assets in the same directory (`en.html`, `site.css`, …) are
   * served too; `/en` resolves to `en.html`. Files are re-read when their mtime
   * changes, so updating the site is just replacing files. Omit to keep
   * answering the apex with 421 as before.
   */
  sitePath?: string
}

/** Content types for the flat asset extensions the apex site may serve. */
const SITE_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
}

/** Largest login POST body accepted, so the gate can't be used to buffer memory. */
const MAX_LOGIN_BODY = 4096

/** Login brute-force gate: N wrong guesses within the window → lock out. */
const LOGIN_FAIL_MAX = 8
const LOGIN_FAIL_WINDOW_MS = 15 * 60 * 1000
const LOGIN_LOCKOUT_MS = 10 * 60 * 1000

/** Coerce a `ws` message payload to a single Buffer. */
function toBuf(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data
  if (Array.isArray(data)) return Buffer.concat(data)
  return Buffer.from(data as ArrayBuffer)
}

/** Build a protocol header list from a node request's raw header array. */
function headerList(raw: string[]): HeaderList {
  const out: HeaderList = []
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i], raw[i + 1]])
  return out
}

/** Flatten a header list into node's `writeHead` array form, preserving duplicates. */
function flatHeaders(headers: HeaderList): string[] {
  const flat: string[] = []
  for (const [k, v] of headers) flat.push(k, v)
  return flat
}

/**
 * One live agent: its control socket, the id allocator for streams the relay
 * opens through it, and the public responses and browser sockets currently
 * bridged over it.
 */
class AgentConnection {
  private nextId = 1
  lastPong = Date.now()
  readonly responses = new Map<number, http.ServerResponse>()
  readonly sockets = new Map<number, WebSocket>()

  constructor(readonly subdomain: string, readonly ws: WebSocket) {}

  /** Allocate the next stream id (wraps within uint32; collisions need ~4B live streams). */
  allocId(): number {
    const id = this.nextId
    this.nextId = this.nextId >= 0xffffffff ? 1 : this.nextId + 1
    return id
  }

  send(frame: ControlFrame): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(encodeControl(frame))
  }

  sendData(kind: DataKind, id: number, payload: Uint8Array): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(encodeData(kind, id, payload))
  }
}

/** The relay server. Construct with options, then {@link listen}. */
export class RelayServer {
  private readonly http: http.Server
  private readonly wss: WebSocketServer
  private readonly agents = new Map<string, AgentConnection>()
  /** Per-subdomain login failure tracking for the brute-force lockout. */
  private readonly loginGate = new Map<string, { count: number; last: number; until: number }>()
  private heartbeat: ReturnType<typeof setInterval> | null = null

  constructor(private readonly opts: RelayOptions) {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => this.onRequest(req, res)
    this.http = opts.tls !== undefined
      ? https.createServer({ cert: opts.tls.cert, key: opts.tls.key }, handler)
      : http.createServer(handler)
    this.http.on('upgrade', (req, socket, head) => this.onUpgrade(req, socket, head))
    this.wss = new WebSocketServer({ noServer: true })
  }

  /**
   * Start listening.
   * @param cb - called once bound.
   */
  listen(cb?: () => void): void {
    this.http.listen(this.opts.port, cb)
    this.heartbeat = setInterval(() => this.sweep(), HEARTBEAT_INTERVAL_MS)
  }

  /** Drop agents that have gone silent past the timeout, and ping the rest. */
  private sweep(): void {
    const now = Date.now()
    for (const conn of this.agents.values()) {
      if (now - conn.lastPong > HEARTBEAT_TIMEOUT_MS) {
        if (process.env.DSHN_DEBUG) console.error(`[relay] heartbeat timeout for "${conn.subdomain}" (silent ${now - conn.lastPong}ms) — terminating`)
        conn.ws.terminate()
      } else conn.send({ t: 'ping' })
    }
    // Drop stale login-gate entries (lock expired and no recent failures) so the
    // map can't grow without bound from probing traffic.
    for (const [key, g] of this.loginGate) {
      if (g.until <= now && now - g.last > LOGIN_FAIL_WINDOW_MS) this.loginGate.delete(key)
    }
  }

  // ── public HTTP ───────────────────────────────────────────────────────────

  private onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const bare = (req.headers.host ?? '').toLowerCase().split(':', 1)[0].replace(/\.$/, '')
    if (bare === `www.${this.opts.apex}`) {
      // `www` rides the wildcard DNS record; it is reserved, so send visitors home.
      res.writeHead(301, { location: `https://${this.opts.apex}${req.url ?? '/'}` })
      res.end()
      return
    }
    if (bare === this.opts.apex && this.opts.sitePath !== undefined) return this.serveSite(req, res)

    const sub = subdomainOf(req.headers.host ?? '', this.opts.apex)
    if (sub === null) return this.fail(res, 421, 'Unknown host')

    const url = req.url ?? '/'
    if (url === '/__dshn/login' && req.method === 'POST') return this.handleLogin(req, res, sub)

    const cookies = parseCookies(req.headers.cookie)
    if (!verify(this.opts.cookieSecret, sub, cookies[COOKIE_NAME] ?? '')) {
      return this.serveLogin(res, `${sub}.${this.opts.apex}`, false, 200)
    }

    const conn = this.agents.get(sub)
    if (conn === undefined) return this.fail(res, 502, 'Tunnel offline — the device is not connected.')

    const id = conn.allocId()
    conn.responses.set(id, res)
    conn.send({ t: 'req_head', id, method: req.method ?? 'GET', path: url, headers: headerList(req.rawHeaders) })
    req.on('data', (chunk: Buffer) => conn.sendData(DATA_REQ_BODY, id, chunk))
    req.on('end', () => conn.send({ t: 'req_end', id }))
    req.on('error', () => conn.send({ t: 'abort', id, reason: 'request stream error' }))
    res.on('close', () => {
      if (conn.responses.delete(id)) conn.send({ t: 'abort', id, reason: 'client closed' })
    })
  }

  /**
   * The rate-limit key: the real client IP (Cloudflare passes it as
   * `cf-connecting-ip`; the socket peer is CF's shared address, useless as a
   * key) plus the subdomain. Keying on the IP means a wrong-guess flood locks
   * out only the attacker, not the legitimate owner of the subdomain.
   */
  private loginKey(req: http.IncomingMessage, sub: string): string {
    const ip = String(req.headers['cf-connecting-ip'] ?? req.socket.remoteAddress ?? '?')
    return `${sub}|${ip}`
  }

  private handleLogin(req: http.IncomingMessage, res: http.ServerResponse, sub: string): void {
    const now = Date.now()
    const key = this.loginKey(req, sub)
    const gate = this.loginGate.get(key)
    if (gate !== undefined && gate.until > now) {
      // Locked out after too many wrong guesses — the password guards a shell.
      const secs = Math.ceil((gate.until - now) / 1000)
      res.writeHead(429, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': String(secs), 'cache-control': 'no-store' })
      res.end(`Too many attempts. Try again in ${secs}s.\n`)
      return
    }
    let body = ''
    let over = false
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString('utf8')
      if (body.length > MAX_LOGIN_BODY) {
        over = true
        req.destroy()
      }
    })
    req.on('end', () => {
      if (over) return
      const params = new URLSearchParams(body)
      const password = params.get('password') ?? ''
      const host = `${sub}.${this.opts.apex}`
      if (this.opts.claims.verifyLogin(sub, password)) {
        this.loginGate.delete(key)
        res.writeHead(302, {
          'set-cookie': cookieHeader(sign(this.opts.cookieSecret, sub)),
          location: '/',
        })
        res.end()
      } else {
        this.registerLoginFailure(key, now)
        this.serveLogin(res, host, true, 401)
      }
    })
  }

  /** Count a wrong password and lock the (subdomain, IP) out after a burst. */
  private registerLoginFailure(key: string, now: number): void {
    const g = this.loginGate.get(key)
    // Reset the counter if the last failure was long ago (a slow, honest retry).
    const fails = g !== undefined && now - g.last < LOGIN_FAIL_WINDOW_MS ? g.count + 1 : 1
    const until = fails >= LOGIN_FAIL_MAX ? now + LOGIN_LOCKOUT_MS : 0
    this.loginGate.set(key, { count: fails, last: now, until })
  }

  /** Cached apex site files, keyed by filename, invalidated by mtime. */
  private readonly site = new Map<string, { mtimeMs: number; body: Buffer }>()

  /** Serve the static project site on the bare apex. */
  private serveSite(req: http.IncomingMessage, res: http.ServerResponse): void {
    if (req.method !== 'GET' && req.method !== 'HEAD') return this.fail(res, 405, 'Method not allowed')
    let path = (req.url ?? '/').split('?', 1)[0]
    if (path === '/') path = '/index.html'
    if (!path.includes('.')) path += '.html' // pretty page URLs: `/en` → `en.html`
    // One flat, whitelisted-extension filename — no separators, no traversal.
    const m = /^\/([a-z0-9-]+(\.[a-z0-9]+))$/.exec(path)
    const type = m === null ? undefined : SITE_TYPES[m[2]]
    if (m === null || type === undefined) return this.fail(res, 404, 'Not found')
    const file = join(dirname(this.opts.sitePath!), m[1])
    let body: Buffer
    try {
      const mtimeMs = statSync(file).mtimeMs
      const cached = this.site.get(m[1])
      if (cached === undefined || cached.mtimeMs !== mtimeMs) this.site.set(m[1], { mtimeMs, body: readFileSync(file) })
      body = this.site.get(m[1])!.body
    } catch {
      return this.fail(res, 404, 'Not found')
    }
    res.writeHead(200, {
      'content-type': type,
      'content-length': String(body.length),
      'cache-control': 'public, max-age=300',
    })
    res.end(req.method === 'HEAD' ? undefined : body)
  }

  private serveLogin(res: http.ServerResponse, host: string, error: boolean, status: number): void {
    const html = loginPage(host, error)
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    res.end(html)
  }

  private fail(res: http.ServerResponse, status: number, message: string): void {
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    res.end(`${message}\n`)
  }

  // ── upgrades: agent control channel + tunnelled browser sockets ────────────

  private onUpgrade(req: http.IncomingMessage, socket: Duplex, head: Buffer): void {
    const path = (req.url ?? '/').split('?', 1)[0]
    if (path === AGENT_WS_PATH) {
      this.wss.handleUpgrade(req, socket, head, (ws) => this.registerAgent(ws))
      return
    }
    const sub = subdomainOf(req.headers.host ?? '', this.opts.apex)
    const cookies = parseCookies(req.headers.cookie)
    if (sub === null || !verify(this.opts.cookieSecret, sub, cookies[COOKIE_NAME] ?? '')) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
      socket.destroy()
      return
    }
    const conn = this.agents.get(sub)
    if (conn === undefined) {
      socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      socket.destroy()
      return
    }
    this.wss.handleUpgrade(req, socket, head, (browser) => this.bridgeSocket(conn, browser, req))
  }

  private registerAgent(ws: WebSocket): void {
    // The first frame must be a valid HELLO or the socket is dropped.
    ws.once('message', (data: RawData, isBinary: boolean) => {
      if (isBinary) return ws.close()
      let frame: ControlFrame
      try {
        frame = decodeControl(toBuf(data).toString('utf8'))
      } catch {
        return ws.close()
      }
      if (frame.t !== 'hello') return ws.close()
      const result = this.opts.claims.claimOrVerify(frame.subdomain, frame.password, Date.now())
      if (!result.ok) {
        ws.send(encodeControl({ t: 'deny', reason: result.reason ?? 'rejected' }))
        ws.close()
        return
      }
      const sub = frame.subdomain
      const previous = this.agents.get(sub)
      if (previous !== undefined) {
        if (process.env.DSHN_DEBUG) console.error(`[relay] new agent for "${sub}" — terminating previous (in-flight res=${previous.responses.size} ws=${previous.sockets.size})`)
        previous.ws.terminate() // one live agent per subdomain
      }

      const conn = new AgentConnection(sub, ws)
      this.agents.set(sub, conn)
      ws.on('message', (d: RawData, bin: boolean) => this.onAgentFrame(conn, d, bin))
      ws.on('close', (code: number, reason: Buffer) => {
        if (process.env.DSHN_DEBUG) console.error(`[relay] agent ws "${sub}" close code=${code} reason=${reason.toString('utf8')} bufferedAmount=${ws.bufferedAmount}`)
        if (this.agents.get(sub) === conn) this.agents.delete(sub)
        this.cleanup(conn)
      })
      ws.on('error', (err: Error) => {
        if (process.env.DSHN_DEBUG) console.error(`[relay] agent ws "${sub}" ERROR ${err.message}`)
        ws.terminate()
      })
      ws.send(encodeControl({ t: 'ready', subdomain: sub, publicUrl: `https://${sub}.${this.opts.apex}` }))
    })
  }

  private onAgentFrame(conn: AgentConnection, data: RawData, isBinary: boolean): void {
    // One tenant's malformed frame must never throw into the relay's event loop
    // and take down every other tenant's tunnel. Handle under one guard.
    try {
      this.dispatchAgentFrame(conn, data, isBinary)
    } catch {
      // Drop the frame; the connection stays up for its other streams.
    }
  }

  private dispatchAgentFrame(conn: AgentConnection, data: RawData, isBinary: boolean): void {
    if (isBinary) {
      const frame = decodeData(toBuf(data))
      if (frame.kind === DATA_RES_BODY) {
        conn.responses.get(frame.id)?.write(Buffer.from(frame.payload))
      } else if (frame.kind === DATA_WS_TEXT || frame.kind === DATA_WS_BINARY) {
        conn.sockets.get(frame.id)?.send(Buffer.from(frame.payload), { binary: frame.kind === DATA_WS_BINARY })
      }
      return
    }
    let frame: ControlFrame
    try {
      frame = decodeControl(toBuf(data).toString('utf8'))
    } catch {
      return
    }
    switch (frame.t) {
      case 'res_head': {
        const res = conn.responses.get(frame.id)
        if (res !== undefined && !res.headersSent) res.writeHead(frame.status, flatHeaders(frame.headers))
        break
      }
      case 'res_end':
        conn.responses.get(frame.id)?.end()
        conn.responses.delete(frame.id)
        break
      case 'ws_reject':
        conn.sockets.get(frame.id)?.close(1011, `origin rejected (${frame.status})`)
        conn.sockets.delete(frame.id)
        break
      case 'ws_close':
        conn.sockets.get(frame.id)?.close(sanitizeCloseCode(frame.code), sanitizeCloseReason(frame.reason))
        conn.sockets.delete(frame.id)
        break
      case 'abort':
        conn.responses.get(frame.id)?.destroy()
        conn.responses.delete(frame.id)
        conn.sockets.get(frame.id)?.close()
        conn.sockets.delete(frame.id)
        break
      case 'pong':
      case 'ping':
        conn.lastPong = Date.now()
        if (frame.t === 'ping') conn.send({ t: 'pong' })
        break
      // ws_ready needs no action: the browser socket is already open on our side.
      default:
        break
    }
  }

  private bridgeSocket(conn: AgentConnection, browser: WebSocket, req: http.IncomingMessage): void {
    const id = conn.allocId()
    conn.sockets.set(id, browser)
    conn.send({ t: 'ws_open', id, path: req.url ?? '/', headers: headerList(req.rawHeaders) })
    browser.on('message', (data: RawData, isBinary: boolean) => {
      conn.sendData(isBinary ? DATA_WS_BINARY : DATA_WS_TEXT, id, toBuf(data))
    })
    browser.on('close', (code: number, reason: Buffer) => {
      if (conn.sockets.delete(id)) conn.send({ t: 'ws_close', id, code: sanitizeCloseCode(code), reason: sanitizeCloseReason(reason.toString('utf8')) })
    })
    browser.on('error', () => browser.close())
  }

  /** Fail everything still bridged over a control socket that just died. */
  private cleanup(conn: AgentConnection): void {
    if (process.env.DSHN_DEBUG && (conn.responses.size > 0 || conn.sockets.size > 0)) {
      console.error(`[relay] cleanup "${conn.subdomain}": failing ${conn.responses.size} in-flight responses + ${conn.sockets.size} sockets`)
    }
    for (const res of conn.responses.values()) {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' })
      res.end('Tunnel closed.\n')
    }
    for (const sock of conn.sockets.values()) sock.close(1011, 'tunnel closed')
    conn.responses.clear()
    conn.sockets.clear()
  }
}
