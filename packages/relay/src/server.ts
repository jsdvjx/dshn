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
  type ReadyFrame,
  type TunnelRoute,
} from '@dshn/protocol'
import { ClaimStore, type PremiumRecord } from './claims.js'
import type { PremiumDns } from './dns.js'
import { DSHN_PROTOCOL_VERSION, isValidSubdomainLabel, type HelloFrame } from '@dshn/protocol'
import {
  COOKIE_NAME, DEVICE_COOKIE, constantTimeEqual, cookieHeader, deviceCookieHeader, devicesPage, loginPage,
  parseCookies, sign, verify, type PickerDevice,
} from './auth.js'
import {
  ADMIN_COOKIE, ADMIN_MAX_AGE_S, ADMIN_SCOPE, adminCookieHeader, adminLoginPage, adminPage,
} from './admin.js'

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
  /**
   * Admin panel password. When set, `/__admin` on the bare apex serves the
   * operator dashboard: platform stats plus claim management (kick, release,
   * ban). Unset (the default) disables every `/__admin` path with a 404.
   */
  adminPassword?: string
  /**
   * The premium route: an accelerator node that terminates TLS for the apex's
   * wildcard and proxies to this relay. Present = the operator may move
   * individual claims onto it from the admin panel; absent = the feature does
   * not exist on this relay (agents are told nothing about routes).
   */
  premium?: PremiumOptions
  /** How long an agent socket may sit without a HELLO before it is dropped (tests shorten it). */
  helloTimeoutMs?: number
  /** HELLOs accepted per client IP per minute (tests raise it; the peer gate is 10× this). */
  helloPerMinute?: number
}

/** Premium-route wiring, all operator-supplied. */
export interface PremiumOptions {
  /** The accelerator's address — what the dedicated DNS record points at. */
  host: string
  /**
   * DNS control for the dedicated records. Omit to run the route with manual
   * DNS: the panel then tells the operator which record to add or remove.
   */
  dns?: PremiumDns
  /**
   * Peers whose `X-Forwarded-For` is believed for the login rate limit (the
   * accelerator, which is not Cloudflare and so sends no `cf-connecting-ip`).
   * `host` is trusted implicitly when it is an IP address.
   */
  trustedProxies?: string[]
  /**
   * The authority an agent on the premium route dials, per subdomain. Defaults
   * to the tunnel's own public hostname (`<sub>.<apex>` — which the dedicated
   * record points at the accelerator); tests override it with a loopback URL.
   */
  routeHost?: (subdomain: string) => string
}

/** Per-subdomain traffic counters — in memory, since the relay started. */
interface Traffic {
  /** Public HTTP requests routed to an agent. */
  requests: number
  /** Browser WebSocket sessions bridged to an agent. */
  wsSessions: number
  /** Body/message bytes from the public side to the agent. */
  bytesIn: number
  /** Body/message bytes from the agent to the public side. */
  bytesOut: number
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

/**
 * Admin history sampling: one snapshot of the platform counters every
 * HISTORY_INTERVAL_MS, kept for HISTORY_MAX samples (24h at 30s). In memory
 * only — it is a dashboard trend line, not an audit log.
 */
const HISTORY_INTERVAL_MS = 30_000
const HISTORY_MAX = 2880

/** Login brute-force gate: N wrong guesses within the window → lock out. */
const LOGIN_FAIL_MAX = 8
const LOGIN_FAIL_WINDOW_MS = 15 * 60 * 1000
const LOGIN_LOCKOUT_MS = 10 * 60 * 1000
/**
 * A second, looser gate keyed on the SOCKET peer. The primary key is the
 * client IP a proxy reports, which a direct-to-origin client can forge per
 * request; the peer address cannot be forged, but behind Cloudflare it is
 * shared by many visitors — hence the higher threshold.
 */
const LOGIN_PEER_FAIL_MAX = 64

/** Agent handshake: a socket that has not said HELLO by then is dropped. */
const HELLO_TIMEOUT_MS = 10_000
/**
 * HELLOs accepted per client IP per minute (agents reconnect with backoff;
 * this is far above honest use). The socket-peer gate is 10× looser, since a
 * Cloudflare egress address is shared by many agents.
 */
const HELLO_PER_MINUTE = 60
/** Sockets one peer may hold open before HELLO at once. */
const PRE_HELLO_PER_PEER = 32
/** Largest single WebSocket frame accepted from an agent or a browser. */
export const MAX_FRAME_BYTES = 128 * 1024 * 1024
/** Buffered bytes on a socket above which the source feeding it is paused. */
const SEND_HIGH_WATER = 8 * 1024 * 1024
/** Buffered bytes above which a consumer that cannot be paused is dropped as too slow. */
const MAX_BUFFERED = 64 * 1024 * 1024
/** A public response with no bytes from the agent for this long is failed. */
const STREAM_IDLE_MS = 120_000

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
  readonly connectedAt = Date.now()
  readonly responses = new Map<number, http.ServerResponse>()
  readonly sockets = new Map<number, WebSocket>()
  /** Last time the agent sent anything for a pending response, by stream id (idle timeout). */
  readonly activity = new Map<number, number>()

  constructor(readonly subdomain: string, readonly deviceId: string, readonly deviceName: string, readonly ws: WebSocket) {}

  /** Allocate the next stream id (wraps within uint32; collisions need ~4B live streams). */
  allocId(): number {
    const id = this.nextId
    this.nextId = this.nextId >= 0xffffffff ? 1 : this.nextId + 1
    return id
  }

  send(frame: ControlFrame): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(encodeControl(frame))
  }

  /**
   * Send a data frame. When the socket already holds more than the high-water
   * mark, the caller's source should stop until `flushed` fires — that is how
   * a fast public client is kept from ballooning the relay's memory.
   * @returns false when the caller should pause its source.
   */
  sendData(kind: DataKind, id: number, payload: Uint8Array, flushed?: () => void): boolean {
    if (this.ws.readyState !== WebSocket.OPEN) return true
    const over = this.ws.bufferedAmount > SEND_HIGH_WATER
    this.ws.send(encodeData(kind, id, payload), over && flushed !== undefined ? () => flushed() : undefined)
    return !over
  }
}

/**
 * Validate an agent's first frame. Only the shape is checked here (types,
 * lengths, protocol version); the claim store decides ownership. Anything off
 * is a reason string, never a throw — the frame came from the network.
 */
function checkHello(frame: unknown): HelloFrame | string {
  if (frame === null || typeof frame !== 'object') return 'malformed hello'
  const f = frame as Record<string, unknown>
  if (f.t !== 'hello') return 'expected hello'
  if (typeof f.protocol !== 'number' || !Number.isInteger(f.protocol)) return 'malformed hello: protocol'
  if (f.protocol !== DSHN_PROTOCOL_VERSION) return `unsupported protocol version ${f.protocol} (relay speaks ${DSHN_PROTOCOL_VERSION})`
  if (typeof f.subdomain !== 'string' || f.subdomain.length > 64 || !isValidSubdomainLabel(f.subdomain)) return 'invalid or reserved subdomain'
  if (typeof f.password !== 'string') return 'malformed hello: password'
  if (f.password.length < 8) return 'password too short (min 8)'
  if (f.password.length > 256) return 'password too long (max 256)'
  if (f.agent !== undefined && (typeof f.agent !== 'string' || f.agent.length > 128)) return 'malformed hello: agent'
  if (f.deviceId !== undefined && (typeof f.deviceId !== 'string' || f.deviceId.length > 128)) return 'malformed hello: deviceId'
  if (f.device !== undefined && (typeof f.device !== 'string' || f.device.length > 256)) return 'malformed hello: device'
  return {
    t: 'hello',
    subdomain: f.subdomain,
    password: f.password,
    agent: typeof f.agent === 'string' ? f.agent : '',
    protocol: f.protocol,
    ...(typeof f.deviceId === 'string' ? { deviceId: f.deviceId } : {}),
    ...(typeof f.device === 'string' ? { device: f.device } : {}),
  }
}

/** A sliding one-minute counter per key, for the HELLO rate gates. */
class MinuteGate {
  private readonly counts = new Map<string, { n: number; since: number }>()

  constructor(private readonly max: number) {}

  /** Count one event; false when the key is over its budget for this minute. */
  admit(key: string, now: number): boolean {
    const c = this.counts.get(key)
    if (c === undefined || now - c.since >= 60_000) {
      this.counts.set(key, { n: 1, since: now })
      return true
    }
    c.n += 1
    return c.n <= this.max
  }

  /** Drop keys whose minute has passed. */
  prune(now: number): void {
    for (const [key, c] of this.counts) if (now - c.since >= 60_000) this.counts.delete(key)
  }
}

/**
 * Device id assigned to a legacy agent whose HELLO carries none. All legacy
 * agents of a subdomain share it, so a second one still supersedes the first —
 * exactly the old one-agent-per-subdomain behavior.
 */
const LEGACY_DEVICE_ID = 'device'

/** Sanitize an agent-supplied device id: short, flat, cookie/HTML-safe charset. */
function sanitizeDeviceId(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const id = raw.trim().toLowerCase()
  return /^[a-z0-9][a-z0-9_-]{0,63}$/.test(id) ? id : null
}

/** Sanitize an agent-supplied device name: printable, bounded; empty → null. */
function sanitizeDeviceName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  // eslint-disable-next-line no-control-regex
  const name = raw.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 40)
  return name === '' ? null : name
}

/**
 * Whether a request is a top-level HTML navigation — the only case where the
 * device picker page may replace the response. API/asset fetches never see the
 * picker: they either route to a live device or fail cleanly.
 */
function isNavigation(req: http.IncomingMessage): boolean {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false
  const dest = String(req.headers['sec-fetch-dest'] ?? '')
  if (dest !== '') return dest === 'document'
  return String(req.headers.accept ?? '').includes('text/html')
}

/**
 * Where a public request should go when its subdomain has 0..N live devices.
 * `conn` routes to that device; `picker` shows the device page (navigations
 * only); `offline` fails the request with the given message.
 */
type DeviceRoute =
  | { kind: 'conn'; conn: AgentConnection }
  | { kind: 'picker' }
  | { kind: 'offline'; message: string }

/** The relay server. Construct with options, then {@link listen}. */
export class RelayServer {
  private readonly http: http.Server
  private readonly wss: WebSocketServer
  /** Live agents: subdomain → device id → connection (multi-device). */
  private readonly agents = new Map<string, Map<string, AgentConnection>>()
  /** Per-subdomain login failure tracking for the brute-force lockout. */
  private readonly loginGate = new Map<string, { count: number; last: number; until: number }>()
  /** HELLO rate gates: by reported client IP, and by socket peer. */
  private readonly helloGate: MinuteGate
  private readonly helloPeerGate: MinuteGate
  /** Sockets per peer that are open but have not completed HELLO. */
  private readonly preHello = new Map<string, number>()
  /** Per-subdomain premium/DNS operation chains, so enable/disable/release never interleave. */
  private readonly premiumOps = new Map<string, Promise<unknown>>()
  private heartbeat: ReturnType<typeof setInterval> | null = null
  /** When this relay process started, for the admin panel's uptime. */
  private readonly startedAt = Date.now()
  /** Per-subdomain traffic counters since start (admin panel; bounded by claims). */
  private readonly traffic = new Map<string, Traffic>()
  /**
   * Admin trend samples, oldest first. Each row is
   * `[t, requests, wsSessions, bytesIn, bytesOut, onlineDevices, onlineSubdomains]`
   * with the counters cumulative — the dashboard diffs neighbours for rates.
   */
  private readonly history: number[][] = []
  private sampler: ReturnType<typeof setInterval> | null = null

  constructor(private readonly opts: RelayOptions) {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => this.onRequest(req, res)
    this.http = opts.tls !== undefined
      ? https.createServer({ cert: opts.tls.cert, key: opts.tls.key }, handler)
      : http.createServer(handler)
    this.http.on('upgrade', (req, socket, head) => this.onUpgrade(req, socket, head))
    this.wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES })
    const perMinute = opts.helloPerMinute ?? HELLO_PER_MINUTE
    this.helloGate = new MinuteGate(perMinute)
    this.helloPeerGate = new MinuteGate(perMinute * 10)
  }

  /**
   * Start listening.
   * @param cb - called once bound.
   */
  listen(cb?: () => void): void {
    this.http.listen(this.opts.port, cb)
    this.heartbeat = setInterval(() => this.sweep(), HEARTBEAT_INTERVAL_MS)
    if (this.opts.adminPassword) {
      this.sample()
      this.sampler = setInterval(() => this.sample(), HISTORY_INTERVAL_MS)
    }
  }

  /** The actually bound port (differs from the option when it was 0). */
  port(): number {
    const addr = this.http.address()
    return addr !== null && typeof addr === 'object' ? addr.port : this.opts.port
  }

  /** Shut down: drop every agent socket and stop listening (tests, embedding). */
  close(): void {
    if (this.heartbeat !== null) { clearInterval(this.heartbeat); this.heartbeat = null }
    if (this.sampler !== null) { clearInterval(this.sampler); this.sampler = null }
    for (const group of this.agents.values()) for (const conn of group.values()) conn.ws.terminate()
    this.wss.close()
    this.http.close()
    this.http.closeAllConnections()
    this.opts.claims.flush()
  }

  /** Drop agents that have gone silent past the timeout, and ping the rest. */
  private sweep(): void {
    const now = Date.now()
    for (const group of this.agents.values()) {
      for (const conn of group.values()) {
        if (now - conn.lastPong > HEARTBEAT_TIMEOUT_MS) {
          if (process.env.DSHN_DEBUG) console.error(`[relay] heartbeat timeout for "${conn.subdomain}"/${conn.deviceId} (silent ${now - conn.lastPong}ms) — terminating`)
          conn.ws.terminate()
          continue
        }
        conn.send({ t: 'ping' })
        // A pending response the agent has gone quiet on is failed, so a stuck
        // origin cannot pin public sockets (and the relay's memory) forever.
        for (const [id, last] of conn.activity) {
          if (now - last <= STREAM_IDLE_MS) continue
          const res = conn.responses.get(id)
          conn.responses.delete(id)
          conn.activity.delete(id)
          if (res !== undefined) {
            if (!res.headersSent) res.writeHead(504, { 'content-type': 'text/plain' })
            res.end('Tunnel timeout.\n')
          }
          conn.send({ t: 'abort', id, reason: 'idle timeout' })
        }
      }
    }
    // Drop stale login-gate entries (lock expired and no recent failures) so the
    // map can't grow without bound from probing traffic.
    for (const [key, g] of this.loginGate) {
      if (g.until <= now && now - g.last > LOGIN_FAIL_WINDOW_MS) this.loginGate.delete(key)
    }
    this.helloGate.prune(now)
    this.helloPeerGate.prune(now)
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
    if (bare === this.opts.apex) {
      const apexPath = (req.url ?? '/').split('?', 1)[0]
      if (apexPath === '/__admin' || apexPath.startsWith('/__admin/')) return this.handleAdmin(req, res, apexPath)
      if (this.opts.sitePath !== undefined) return this.serveSite(req, res)
    }

    const sub = subdomainOf(req.headers.host ?? '', this.opts.apex)
    if (sub === null) return this.fail(res, 421, 'Unknown host')

    const url = req.url ?? '/'
    if (url === '/__dshn/login' && req.method === 'POST') return this.handleLogin(req, res, sub)

    const cookies = parseCookies(req.headers.cookie)
    if (!verify(this.opts.cookieSecret, sub, cookies[COOKIE_NAME] ?? '', this.opts.claims.sessionVersionOf(sub))) {
      return this.serveLogin(res, `${sub}.${this.opts.apex}`, false, 200)
    }

    // Multi-device endpoints, behind the login gate: the device list (JSON for
    // the in-page switcher, HTML for a human) and the selection setter.
    const bareUrl = url.split('?', 1)[0]
    if (bareUrl === '/__dshn/devices') return this.serveDevices(req, res, sub, cookies)
    if (bareUrl === '/__dshn/select' && req.method === 'POST') return this.handleSelect(req, res, sub)

    const route = this.resolveDevice(sub, cookies, isNavigation(req))
    if (route.kind === 'picker') return this.servePicker(res, sub, cookies)
    if (route.kind === 'offline') return this.fail(res, 502, route.message)
    const conn = route.conn

    const id = conn.allocId()
    const traffic = this.trafficOf(sub)
    traffic.requests++
    conn.responses.set(id, res)
    conn.activity.set(id, Date.now())
    conn.send({ t: 'req_head', id, method: req.method ?? 'GET', path: url, headers: headerList(req.rawHeaders) })
    req.on('data', (chunk: Buffer) => {
      traffic.bytesIn += chunk.length
      // Backpressure: a fast uploader waits for the agent socket to drain.
      if (!conn.sendData(DATA_REQ_BODY, id, chunk, () => req.resume())) req.pause()
    })
    req.on('end', () => conn.send({ t: 'req_end', id }))
    req.on('error', () => conn.send({ t: 'abort', id, reason: 'request stream error' }))
    res.on('close', () => {
      conn.activity.delete(id)
      if (conn.responses.delete(id)) conn.send({ t: 'abort', id, reason: 'client closed' })
    })
  }

  /**
   * The rate-limit keys: the real client IP (Cloudflare passes it as
   * `cf-connecting-ip`; the socket peer is CF's shared address, useless alone)
   * plus the subdomain — so a wrong-guess flood locks out only the attacker,
   * not the legitimate owner — AND the socket peer with a looser budget, so a
   * direct-to-origin client forging a fresh client IP per guess still runs
   * into a wall.
   */
  private loginKeys(req: http.IncomingMessage, sub: string): Array<{ key: string; max: number }> {
    return [
      { key: `${sub}|${this.clientIp(req)}`, max: LOGIN_FAIL_MAX },
      { key: `${sub}|peer|${this.peerIp(req)}`, max: LOGIN_PEER_FAIL_MAX },
    ]
  }

  /** The peer address of a request, IPv4-mapped forms normalized (`::ffff:1.2.3.4` → `1.2.3.4`). */
  private peerIp(req: http.IncomingMessage): string {
    return String(req.socket.remoteAddress ?? '').replace(/^::ffff:/i, '')
  }

  /** Whether a peer is a proxy whose forwarding headers we believe (the accelerator). */
  private isTrustedProxy(peer: string): boolean {
    const p = this.opts.premium
    if (p === undefined || peer === '') return false
    if (p.host === peer) return true
    return (p.trustedProxies ?? []).includes(peer)
  }

  /**
   * The real client IP. Behind Cloudflare it is `cf-connecting-ip`. From the
   * accelerator (a trusted proxy that is NOT Cloudflare) it is the LAST hop of
   * `X-Forwarded-For` — the one the accelerator itself appended; anything before
   * it (and any `cf-connecting-ip`) came from the client and is not believed.
   * Otherwise the socket peer.
   */
  private clientIp(req: http.IncomingMessage): string {
    const peer = this.peerIp(req)
    if (this.isTrustedProxy(peer)) {
      const hops = String(req.headers['x-forwarded-for'] ?? '').split(',').map((h) => h.trim()).filter((h) => h !== '')
      return hops.length > 0 ? hops[hops.length - 1] : peer
    }
    return String(req.headers['cf-connecting-ip'] ?? '') || peer || '?'
  }

  private handleLogin(req: http.IncomingMessage, res: http.ServerResponse, sub: string): void {
    const now = Date.now()
    const keys = this.loginKeys(req, sub)
    for (const { key } of keys) {
      const gate = this.loginGate.get(key)
      if (gate !== undefined && gate.until > now) {
        // Locked out after too many wrong guesses — the password guards a shell.
        const secs = Math.ceil((gate.until - now) / 1000)
        res.writeHead(429, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': String(secs), 'cache-control': 'no-store' })
        res.end(`Too many attempts. Try again in ${secs}s.\n`)
        return
      }
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
      void this.opts.claims.verifyLogin(sub, password).then((ok) => {
        if (ok) {
          for (const { key } of keys) this.loginGate.delete(key)
          res.writeHead(302, {
            'set-cookie': cookieHeader(sign(this.opts.cookieSecret, sub, undefined, this.opts.claims.sessionVersionOf(sub) ?? '')),
            location: '/',
          })
          res.end()
        } else {
          for (const { key, max } of keys) this.registerLoginFailure(key, max, now)
          this.serveLogin(res, host, true, 401)
        }
      }, () => this.fail(res, 500, 'Login failed'))
    })
  }

  /** Count a wrong password and lock the key out after a burst. */
  private registerLoginFailure(key: string, max: number, now: number): void {
    const g = this.loginGate.get(key)
    // Reset the counter if the last failure was long ago (a slow, honest retry).
    const fails = g !== undefined && now - g.last < LOGIN_FAIL_WINDOW_MS ? g.count + 1 : 1
    const until = fails >= max ? now + LOGIN_LOCKOUT_MS : 0
    this.loginGate.set(key, { count: fails, last: now, until })
  }

  // ── multi-device routing ──────────────────────────────────────────────────

  /**
   * Pick the device a public request should reach. One live device (and no
   * contrary selection) routes straight to it — the classic single-device path,
   * bit-for-bit the old behavior. With several devices, the `dshn_dev` cookie
   * decides; without one, a navigation gets the picker page while API/asset
   * requests keep flowing to the longest-connected device (the one that was
   * already serving before the second joined), so an open session never breaks
   * the moment another machine binds the same subdomain. A selection pointing
   * at a dead device fails closed rather than silently landing on a DIFFERENT
   * machine.
   */
  private resolveDevice(sub: string, cookies: Record<string, string>, nav: boolean): DeviceRoute {
    const group = this.agents.get(sub)
    const live = group?.size ?? 0
    const offline: DeviceRoute = { kind: 'offline', message: 'Tunnel offline — the device is not connected.' }
    const chosen = cookies[DEVICE_COOKIE] ?? ''
    if (chosen !== '') {
      const conn = group?.get(chosen)
      if (conn !== undefined) return { kind: 'conn', conn }
      if (live === 0) return offline
      return nav ? { kind: 'picker' } : { kind: 'offline', message: 'Selected device is offline — reload this page to pick another.' }
    }
    if (live === 0) return offline
    if (live === 1) return { kind: 'conn', conn: group!.values().next().value as AgentConnection }
    if (nav) return { kind: 'picker' }
    let oldest: AgentConnection | undefined
    for (const conn of group!.values()) {
      if (oldest === undefined || conn.connectedAt < oldest.connectedAt) oldest = conn
    }
    return { kind: 'conn', conn: oldest! }
  }

  /** Live + remembered devices of a subdomain, for the picker/JSON list. */
  private deviceList(sub: string, cookies: Record<string, string>): Array<PickerDevice & { lastSeen: number }> {
    const group = this.agents.get(sub)
    const chosen = cookies[DEVICE_COOKIE] ?? ''
    const out = new Map<string, PickerDevice & { lastSeen: number }>()
    for (const rec of this.opts.claims.devicesOf(sub)) {
      out.set(rec.id, { id: rec.id, name: rec.name, online: false, current: rec.id === chosen, lastSeen: rec.lastSeen })
    }
    for (const [id, conn] of group ?? []) {
      out.set(id, { id, name: conn.deviceName, online: true, current: id === chosen, lastSeen: conn.connectedAt })
    }
    return [...out.values()].sort((a, b) => Number(b.online) - Number(a.online) || b.lastSeen - a.lastSeen)
  }

  /** Serve the HTML device picker page. */
  private servePicker(res: http.ServerResponse, sub: string, cookies: Record<string, string>): void {
    const html = devicesPage(`${sub}.${this.opts.apex}`, this.deviceList(sub, cookies))
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    res.end(html)
  }

  /**
   * `GET /__dshn/devices`: the device list. JSON for the in-page switcher
   * (`accept: application/json`), the picker page for a human. `multi` is what
   * tells the switcher to appear at all — true only with ≥2 live devices.
   */
  private serveDevices(req: http.IncomingMessage, res: http.ServerResponse, sub: string, cookies: Record<string, string>): void {
    if (!String(req.headers.accept ?? '').includes('application/json')) return this.servePicker(res, sub, cookies)
    const devices = this.deviceList(sub, cookies)
    const live = this.agents.get(sub)?.size ?? 0
    const current = devices.find((d) => d.current)?.id ?? null
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    res.end(JSON.stringify({ multi: live >= 2, live, current, devices }))
  }

  /**
   * `POST /__dshn/select`: set the device-selection cookie. Accepts the picker
   * page's form (`device=<id>`, answered with a redirect home) and the in-page
   * switcher's JSON (`{"device":"<id>"}`, answered with JSON). Only a currently
   * known device may be selected.
   */
  private handleSelect(req: http.IncomingMessage, res: http.ServerResponse, sub: string): void {
    let body = ''
    let over = false
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString('utf8')
      if (body.length > MAX_LOGIN_BODY) { over = true; req.destroy() }
    })
    req.on('end', () => {
      if (over) return
      const asJson = String(req.headers['content-type'] ?? '').includes('application/json')
      let raw: unknown
      if (asJson) {
        try { raw = (JSON.parse(body) as { device?: unknown }).device } catch { raw = undefined }
      } else {
        raw = new URLSearchParams(body).get('device') ?? undefined
      }
      const id = sanitizeDeviceId(raw)
      const known = id !== null && (this.agents.get(sub)?.has(id) === true
        || this.opts.claims.devicesOf(sub).some((d) => d.id === id))
      if (id === null || !known) {
        res.writeHead(400, { 'content-type': 'application/json', 'cache-control': 'no-store' })
        res.end(JSON.stringify({ error: 'unknown device' }))
        return
      }
      if (asJson) {
        res.writeHead(200, { 'set-cookie': deviceCookieHeader(id), 'content-type': 'application/json', 'cache-control': 'no-store' })
        res.end(JSON.stringify({ ok: true, device: id }))
      } else {
        res.writeHead(302, { 'set-cookie': deviceCookieHeader(id), location: '/' })
        res.end()
      }
    })
  }

  // ── admin panel (bare apex, /__admin, only when a password is configured) ──

  /** The traffic counter of a subdomain, created on first touch. */
  private trafficOf(sub: string): Traffic {
    let t = this.traffic.get(sub)
    if (t === undefined) {
      t = { requests: 0, wsSessions: 0, bytesIn: 0, bytesOut: 0 }
      this.traffic.set(sub, t)
    }
    return t
  }

  /** Read a small request body under the same cap as the login gate; null = over cap. */
  private readSmallBody(req: http.IncomingMessage, cb: (body: string | null) => void): void {
    let body = ''
    let over = false
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString('utf8')
      if (body.length > MAX_LOGIN_BODY) { over = true; req.destroy() }
    })
    req.on('end', () => { if (!over) cb(body) })
  }

  /** Answer a JSON admin API response. */
  private json(res: http.ServerResponse, status: number, payload: unknown): void {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    res.end(JSON.stringify(payload))
  }

  /**
   * Route an apex `/__admin*` request. With no admin password configured every
   * path is a 404 — the panel is invisible, not merely locked. The dashboard
   * page doubles as the login page when the session cookie is absent/expired;
   * everything else requires the session.
   */
  private handleAdmin(req: http.IncomingMessage, res: http.ServerResponse, path: string): void {
    const pw = this.opts.adminPassword ?? ''
    if (pw === '') return this.fail(res, 404, 'Not found')
    if (path === '/__admin/login' && req.method === 'POST') return this.handleAdminLogin(req, res, pw)
    const authed = verify(this.opts.cookieSecret, ADMIN_SCOPE, parseCookies(req.headers.cookie)[ADMIN_COOKIE] ?? '')
    if (path === '/__admin' || path === '/__admin/') {
      if (req.method !== 'GET' && req.method !== 'HEAD') return this.fail(res, 405, 'Method not allowed')
      const html = authed ? adminPage(this.opts.apex) : adminLoginPage(this.opts.apex, false)
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(req.method === 'HEAD' ? undefined : html)
      return
    }
    if (!authed) return this.fail(res, 401, 'Unauthorized')
    if (path === '/__admin/logout' && req.method === 'POST') {
      res.writeHead(302, { 'set-cookie': adminCookieHeader(null), location: '/__admin' })
      res.end()
      return
    }
    if (path === '/__admin/api/state' && req.method === 'GET') return this.serveAdminState(res)
    if (path === '/__admin/api/history' && req.method === 'GET') return this.serveAdminHistory(res)
    if (req.method === 'POST') {
      if (path === '/__admin/api/premium') return this.handleAdminPremium(req, res)
      const action = { '/__admin/api/kick': 'kick', '/__admin/api/release': 'release', '/__admin/api/ban': 'ban', '/__admin/api/unban': 'unban' }[path]
      if (action !== undefined) return this.handleAdminAction(req, res, action as 'kick' | 'release' | 'ban' | 'unban')
    }
    this.fail(res, 404, 'Not found')
  }

  // ── premium route ─────────────────────────────────────────────────────────

  /** The public hostname of a subdomain — the name its dedicated DNS record carries. */
  private hostnameOf(sub: string): string {
    return `${sub}.${this.opts.apex}`
  }

  /** What an agent of a premium subdomain should dial. */
  private routeHostFor(sub: string): string {
    return this.opts.premium?.routeHost?.(sub) ?? this.hostnameOf(sub)
  }

  /** The route fields of a READY/ROUTE frame for a subdomain; empty when routes don't exist on this relay. */
  private routeFields(sub: string): { route?: TunnelRoute; routeHost?: string } {
    if (this.opts.premium === undefined) return {}
    const premium = this.opts.claims.premiumOf(sub) !== null
    return premium ? { route: 'premium', routeHost: this.routeHostFor(sub) } : { route: 'standard' }
  }

  /** Tell every live agent of a subdomain which route it is on now. */
  private notifyRoute(sub: string): void {
    const fields = this.routeFields(sub)
    if (fields.route === undefined) return
    for (const conn of this.agents.get(sub)?.values() ?? []) conn.send({ t: 'route', route: fields.route, routeHost: fields.routeHost })
  }

  /** The admin panel's view of a claim's premium state. */
  private premiumView(premium: PremiumRecord | null): { since: number; dns: { id: string; content: string } | null } | null {
    return premium === null ? null : { since: premium.since, dns: premium.dns ?? null }
  }

  /**
   * `POST /__admin/api/premium` `{ subdomain, enabled }`: move a claim onto or
   * off the premium route. With managed DNS the dedicated record is created or
   * removed FIRST and the claim only changes when that succeeded, so the store
   * never says "premium" while DNS still says otherwise; a DNS failure leaves
   * everything as it was and reports why. Live agents are told to re-route.
   */
  private handleAdminPremium(req: http.IncomingMessage, res: http.ServerResponse): void {
    this.readSmallBody(req, (body) => {
      if (body === null) return
      let sub: unknown
      let enabled: unknown
      try {
        const parsed = JSON.parse(body) as { subdomain?: unknown; enabled?: unknown }
        sub = parsed.subdomain
        enabled = parsed.enabled
      } catch { sub = undefined }
      if (typeof sub !== 'string' || sub === '' || sub.length > 64 || typeof enabled !== 'boolean') {
        return this.json(res, 400, { error: 'expected { subdomain, enabled }' })
      }
      void this.premiumSerial(sub, () => this.setPremiumRoute(sub, enabled)).then(
        (result) => this.json(res, result.status, result.body),
        (err: unknown) => this.json(res, 500, { error: (err as Error).message }),
      )
    })
  }

  /**
   * Run one premium/DNS operation for a subdomain after every earlier one for
   * that subdomain has settled. Enable, disable and the DNS removal on
   * release/ban all go through here, so two operators clicking at once — or
   * a release racing an enable — resolve in order instead of interleaving
   * their DNS calls and claim writes.
   */
  private premiumSerial<T>(sub: string, op: () => Promise<T>): Promise<T> {
    const prev = this.premiumOps.get(sub) ?? Promise.resolve()
    const run = prev.then(op, op)
    const settled = run.then(() => undefined, () => undefined)
    this.premiumOps.set(sub, settled)
    void settled.then(() => { if (this.premiumOps.get(sub) === settled) this.premiumOps.delete(sub) })
    return run
  }

  /** The premium toggle proper; see {@link handleAdminPremium}. */
  private async setPremiumRoute(sub: string, enabled: boolean): Promise<{ status: number; body: unknown }> {
    const p = this.opts.premium
    if (p === undefined) return { status: 409, body: { error: 'premium route is not configured on this relay' } }
    if (!this.opts.claims.isClaimed(sub)) return { status: 404, body: { error: 'no such claim' } }
    const name = this.hostnameOf(sub)
    const record = { type: 'A', name, content: p.host, proxied: false }
    const dnsMode = p.dns === undefined ? 'manual' : 'managed'
    const current = this.opts.claims.premiumOf(sub)
    if (enabled) {
      if (current === null) {
        let dns: PremiumRecord['dns']
        if (p.dns !== undefined) {
          try { dns = await p.dns.point(name, p.host) } catch (err) {
            return { status: 502, body: { error: `DNS update failed: ${(err as Error).message}` } }
          }
        }
        if (!this.opts.claims.setPremium(sub, { since: Date.now(), ...(dns === undefined ? {} : { dns }) })) {
          // The claim went away (released/banned) while DNS was being updated:
          // nothing may keep pointing a name nobody holds at the accelerator.
          if (p.dns !== undefined) {
            await p.dns.unpoint(name, dns?.id, p.host).catch((err: unknown) => {
              console.error(`dshn-relay: cannot remove the premium DNS record of "${sub}": ${(err as Error).message}`)
            })
          }
          return { status: 404, body: { error: 'no such claim' } }
        }
        this.notifyRoute(sub)
      }
    } else if (current !== null) {
      if (p.dns !== undefined) {
        try { await p.dns.unpoint(name, current.dns?.id, p.host) } catch (err) {
          return { status: 502, body: { error: `DNS update failed: ${(err as Error).message}` } }
        }
      }
      this.opts.claims.setPremium(sub, null)
      this.notifyRoute(sub)
    }
    return {
      status: 200,
      body: { ok: true, subdomain: sub, route: enabled ? 'premium' : 'standard', dns: dnsMode, record, premium: this.premiumView(this.opts.claims.premiumOf(sub)) },
    }
  }

  /**
   * Best-effort removal of a claim's dedicated DNS record when the claim itself
   * goes away (release / ban): a record left behind would keep pointing a name
   * nobody holds at the accelerator.
   */
  private dropPremiumDns(sub: string): void {
    const p = this.opts.premium
    const premium = this.opts.claims.premiumOf(sub)
    if (p?.dns === undefined || premium === null) return
    const dns = p.dns
    void this.premiumSerial(sub, () => dns.unpoint(this.hostnameOf(sub), premium.dns?.id, p.host)).catch((err: unknown) => {
      console.error(`dshn-relay: cannot remove the premium DNS record of "${sub}": ${(err as Error).message}`)
    })
  }

  /** Admin login POST: same brute-force gate as tunnel logins, keyed under the admin scope. */
  private handleAdminLogin(req: http.IncomingMessage, res: http.ServerResponse, pw: string): void {
    const now = Date.now()
    const keys = this.loginKeys(req, ADMIN_SCOPE)
    for (const { key } of keys) {
      const gate = this.loginGate.get(key)
      if (gate !== undefined && gate.until > now) {
        const secs = Math.ceil((gate.until - now) / 1000)
        res.writeHead(429, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': String(secs), 'cache-control': 'no-store' })
        res.end(`Too many attempts. Try again in ${secs}s.\n`)
        return
      }
    }
    this.readSmallBody(req, (body) => {
      if (body === null) return
      const password = new URLSearchParams(body).get('password') ?? ''
      if (password !== '' && constantTimeEqual(password, pw)) {
        for (const { key } of keys) this.loginGate.delete(key)
        res.writeHead(302, {
          'set-cookie': adminCookieHeader(sign(this.opts.cookieSecret, ADMIN_SCOPE, ADMIN_MAX_AGE_S)),
          location: '/__admin',
        })
        res.end()
      } else {
        for (const { key, max } of keys) this.registerLoginFailure(key, max, now)
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
        res.end(adminLoginPage(this.opts.apex, true))
      }
    })
  }

  /** Live connection totals across every subdomain. */
  private liveCounts(): { onlineDevices: number; inflightRequests: number; inflightSockets: number } {
    let onlineDevices = 0
    let inflightRequests = 0
    let inflightSockets = 0
    for (const group of this.agents.values()) {
      for (const conn of group.values()) {
        onlineDevices++
        inflightRequests += conn.responses.size
        inflightSockets += conn.sockets.size
      }
    }
    return { onlineDevices, inflightRequests, inflightSockets }
  }

  /** Platform-wide traffic counters, summed over every subdomain. */
  private totalTraffic(): Traffic {
    const total: Traffic = { requests: 0, wsSessions: 0, bytesIn: 0, bytesOut: 0 }
    for (const t of this.traffic.values()) {
      total.requests += t.requests
      total.wsSessions += t.wsSessions
      total.bytesIn += t.bytesIn
      total.bytesOut += t.bytesOut
    }
    return total
  }

  /** Append one history row (see {@link history} for the layout), bounded. */
  private sample(): void {
    const t = this.totalTraffic()
    const live = this.liveCounts()
    this.history.push([Date.now(), t.requests, t.wsSessions, t.bytesIn, t.bytesOut, live.onlineDevices, this.agents.size])
    if (this.history.length > HISTORY_MAX) this.history.splice(0, this.history.length - HISTORY_MAX)
  }

  /** `GET /__admin/api/history`: the trend samples for the dashboard charts. */
  private serveAdminHistory(res: http.ServerResponse): void {
    this.json(res, 200, {
      interval: HISTORY_INTERVAL_MS,
      columns: ['t', 'requests', 'wsSessions', 'bytesIn', 'bytesOut', 'onlineDevices', 'onlineSubdomains'],
      samples: this.history,
    })
  }

  /** `GET /__admin/api/state`: everything the dashboard renders, in one shot. */
  private serveAdminState(res: http.ServerResponse): void {
    const now = Date.now()
    const { onlineDevices, inflightRequests, inflightSockets } = this.liveCounts()
    const zero: Traffic = { requests: 0, wsSessions: 0, bytesIn: 0, bytesOut: 0 }
    let knownDevices = 0
    const claims = this.opts.claims.list().map((c) => {
      const group = this.agents.get(c.subdomain)
      // Merge remembered devices with live connections (live identity wins).
      const devices = new Map<string, { id: string; name: string; lastSeen: number; online: boolean }>()
      for (const d of c.devices) devices.set(d.id, { id: d.id, name: d.name, lastSeen: d.lastSeen, online: false })
      for (const [id, conn] of group ?? []) devices.set(id, { id, name: conn.deviceName, lastSeen: conn.connectedAt, online: true })
      const devs = [...devices.values()].sort((a, b) => Number(b.online) - Number(a.online) || b.lastSeen - a.lastSeen)
      knownDevices += devs.length
      return {
        subdomain: c.subdomain,
        createdAt: c.createdAt,
        online: (group?.size ?? 0) > 0,
        liveDevices: group?.size ?? 0,
        lastSeen: devs.length > 0 ? devs[0].lastSeen : c.createdAt,
        devices: devs,
        traffic: this.traffic.get(c.subdomain) ?? zero,
        premium: this.premiumView(c.premium),
      }
    }).sort((a, b) => Number(b.online) - Number(a.online) || b.lastSeen - a.lastSeen)
    this.json(res, 200, {
      now,
      startedAt: this.startedAt,
      apex: this.opts.apex,
      totals: {
        claims: claims.length,
        onlineSubdomains: this.agents.size,
        onlineDevices,
        knownDevices,
        inflightRequests,
        inflightSockets,
      },
      traffic: this.totalTraffic(),
      claims,
      banned: this.opts.claims.listBanned().sort(),
      premium: this.opts.premium === undefined
        ? null
        : { host: this.opts.premium.host, dns: this.opts.premium.dns === undefined ? 'manual' : 'managed', tunnels: claims.filter((c) => c.premium !== null).length },
    })
  }

  /** Admin actions on one subdomain: kick its agents, release its claim, ban, unban. */
  private handleAdminAction(req: http.IncomingMessage, res: http.ServerResponse, action: 'kick' | 'release' | 'ban' | 'unban'): void {
    this.readSmallBody(req, (body) => {
      if (body === null) return
      let sub: unknown
      try { sub = (JSON.parse(body) as { subdomain?: unknown }).subdomain } catch { sub = undefined }
      if (typeof sub !== 'string' || sub === '' || sub.length > 64) return this.json(res, 400, { error: 'missing subdomain' })
      switch (action) {
        case 'kick':
          return this.json(res, 200, { ok: true, kicked: this.kick(sub) })
        case 'release': {
          this.dropPremiumDns(sub)
          const released = this.opts.claims.remove(sub)
          const kicked = this.kick(sub)
          this.traffic.delete(sub)
          if (!released && kicked === 0) return this.json(res, 404, { error: 'no such claim' })
          return this.json(res, 200, { ok: true, released, kicked })
        }
        case 'ban': {
          this.dropPremiumDns(sub)
          const released = this.opts.claims.ban(sub)
          const kicked = this.kick(sub)
          this.traffic.delete(sub)
          return this.json(res, 200, { ok: true, released, kicked })
        }
        case 'unban': {
          if (!this.opts.claims.unban(sub)) return this.json(res, 404, { error: 'not banned' })
          return this.json(res, 200, { ok: true })
        }
      }
    })
  }

  /**
   * Terminate every live agent of a subdomain. The agents will try to
   * reconnect; whether they get back in is the claim store's call (a released
   * name re-claims, a banned one is denied).
   * @returns how many connections were dropped.
   */
  private kick(sub: string): number {
    const group = this.agents.get(sub)
    if (group === undefined) return 0
    const n = group.size
    for (const conn of group.values()) conn.ws.terminate()
    return n
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
      // Handshake budget, before any WebSocket state exists for the peer: a
      // bounded number of not-yet-authenticated sockets per peer, and a
      // per-minute HELLO rate by reported client IP and by peer.
      const peer = this.peerIp(req)
      const now = Date.now()
      const open = this.preHello.get(peer) ?? 0
      if (open >= PRE_HELLO_PER_PEER || !this.helloGate.admit(this.clientIp(req), now) || !this.helloPeerGate.admit(peer, now)) {
        socket.write('HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\n\r\n')
        socket.destroy()
        return
      }
      this.preHello.set(peer, open + 1)
      this.wss.handleUpgrade(req, socket, head, (ws) => this.registerAgent(ws, peer))
      return
    }
    const sub = subdomainOf(req.headers.host ?? '', this.opts.apex)
    const cookies = parseCookies(req.headers.cookie)
    if (sub === null || !verify(this.opts.cookieSecret, sub, cookies[COOKIE_NAME] ?? '', this.opts.claims.sessionVersionOf(sub))) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
      socket.destroy()
      return
    }
    // A WebSocket upgrade is never a navigation: it routes by the device cookie
    // (or the single/oldest live device) exactly like an API request.
    const route = this.resolveDevice(sub, cookies, false)
    if (route.kind !== 'conn') {
      socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      socket.destroy()
      return
    }
    this.wss.handleUpgrade(req, socket, head, (browser) => this.bridgeSocket(route.conn, browser, req))
  }

  private registerAgent(ws: WebSocket, peer: string): void {
    // Everything before HELLO is hostile until proven otherwise: an error
    // handler from the first moment (an unhandled 'error' would throw), a
    // deadline to say HELLO, and a schema check on what arrives. The peer's
    // pre-HELLO budget is released as soon as the socket is authenticated or gone.
    let released = false
    const release = (): void => {
      if (released) return
      released = true
      const n = (this.preHello.get(peer) ?? 1) - 1
      if (n <= 0) this.preHello.delete(peer)
      else this.preHello.set(peer, n)
    }
    ws.on('error', (err: Error) => {
      if (process.env.DSHN_DEBUG) console.error(`[relay] agent ws (pre-hello, ${peer}) ERROR ${err.message}`)
      ws.terminate()
    })
    ws.once('close', release)
    const deadline = setTimeout(() => {
      if (process.env.DSHN_DEBUG) console.error(`[relay] no HELLO from ${peer} within ${this.opts.helloTimeoutMs ?? HELLO_TIMEOUT_MS}ms — dropping`)
      ws.terminate()
    }, this.opts.helloTimeoutMs ?? HELLO_TIMEOUT_MS)
    const deny = (reason: string): void => {
      try { ws.send(encodeControl({ t: 'deny', reason })) } catch { /* socket already gone */ }
      ws.close()
    }
    // The first frame must be a valid HELLO or the socket is dropped.
    ws.once('message', (data: RawData, isBinary: boolean) => {
      clearTimeout(deadline)
      if (isBinary) return deny('expected hello')
      let raw: unknown
      try {
        raw = decodeControl(toBuf(data).toString('utf8'))
      } catch {
        return deny('malformed hello')
      }
      const checked = checkHello(raw)
      if (typeof checked === 'string') return deny(checked)
      const frame = checked
      this.opts.claims.claimOrVerify(frame.subdomain, frame.password, Date.now()).then((result) => {
        if (ws.readyState !== WebSocket.OPEN) return
        if (!result.ok) return deny(result.reason ?? 'rejected')
        release()
        this.admitAgent(ws, frame)
      }, (err: unknown) => {
        console.error(`dshn-relay: claim check failed: ${(err as Error).message}`)
        deny('relay error')
      })
    })
  }

  /** An authenticated agent: wire it into the routing tables and answer READY. */
  private admitAgent(ws: WebSocket, frame: HelloFrame): void {
    {
      const sub = frame.subdomain
      // Multi-device: several agents may hold one subdomain, keyed by device id.
      // Only the SAME device id supersedes (a reconnect); a legacy agent without
      // an id gets the shared LEGACY_DEVICE_ID, preserving the old
      // one-agent-per-subdomain behavior among legacy agents.
      const deviceId = sanitizeDeviceId(frame.deviceId) ?? LEGACY_DEVICE_ID
      const deviceName = sanitizeDeviceName(frame.device) ?? deviceId
      const group = this.agents.get(sub) ?? new Map<string, AgentConnection>()
      this.agents.set(sub, group)
      const previous = group.get(deviceId)
      if (previous !== undefined) {
        if (process.env.DSHN_DEBUG) console.error(`[relay] new agent for "${sub}"/${deviceId} — terminating previous (in-flight res=${previous.responses.size} ws=${previous.sockets.size})`)
        previous.ws.terminate() // one live agent per (subdomain, device)
      }

      const conn = new AgentConnection(sub, deviceId, deviceName, ws)
      group.set(deviceId, conn)
      this.opts.claims.touchDevice(sub, deviceId, deviceName, Date.now())
      ws.on('message', (d: RawData, bin: boolean) => this.onAgentFrame(conn, d, bin))
      ws.on('close', (code: number, reason: Buffer) => {
        if (process.env.DSHN_DEBUG) console.error(`[relay] agent ws "${sub}"/${deviceId} close code=${code} reason=${reason.toString('utf8')} bufferedAmount=${ws.bufferedAmount}`)
        const g = this.agents.get(sub)
        if (g?.get(deviceId) === conn) {
          g.delete(deviceId)
          if (g.size === 0) this.agents.delete(sub)
          this.opts.claims.touchDevice(sub, deviceId, deviceName, Date.now())
        }
        this.cleanup(conn)
      })
      // The pre-HELLO error handler (terminate) stays in place for the socket's life.
      const ready: ReadyFrame = { t: 'ready', subdomain: sub, publicUrl: `https://${sub}.${this.opts.apex}`, ...this.routeFields(sub) }
      ws.send(encodeControl(ready))
    }
  }

  private onAgentFrame(conn: AgentConnection, data: RawData, isBinary: boolean): void {
    // One tenant's malformed frame must never throw into the relay's event loop
    // and take down every other tenant's tunnel. But it is also a protocol
    // violation from a peer that has to speak our framing: rather than dropping
    // it and leaving whatever stream it addressed pending forever, the
    // connection is closed — cleanup fails its streams and the agent redials.
    try {
      this.dispatchAgentFrame(conn, data, isBinary)
    } catch (err) {
      if (process.env.DSHN_DEBUG) console.error(`[relay] agent "${conn.subdomain}" sent a malformed frame (${(err as Error).message}) — terminating`)
      conn.ws.terminate()
    }
  }

  private dispatchAgentFrame(conn: AgentConnection, data: RawData, isBinary: boolean): void {
    if (isBinary) {
      const frame = decodeData(toBuf(data))
      if (frame.kind === DATA_RES_BODY) {
        this.trafficOf(conn.subdomain).bytesOut += frame.payload.length
        const res = conn.responses.get(frame.id)
        if (res === undefined) return
        conn.activity.set(frame.id, Date.now())
        // No flow-control frame exists to slow the agent down, so a public
        // client that cannot keep up is dropped once its buffer is deep enough.
        if (res.writableLength > MAX_BUFFERED) {
          conn.responses.delete(frame.id)
          conn.activity.delete(frame.id)
          res.destroy()
          conn.send({ t: 'abort', id: frame.id, reason: 'client too slow' })
          return
        }
        res.write(Buffer.from(frame.payload))
      } else if (frame.kind === DATA_WS_TEXT || frame.kind === DATA_WS_BINARY) {
        this.trafficOf(conn.subdomain).bytesOut += frame.payload.length
        const sock = conn.sockets.get(frame.id)
        if (sock === undefined) return
        if (sock.bufferedAmount > MAX_BUFFERED) {
          conn.sockets.delete(frame.id)
          sock.close(1013, 'client too slow')
          conn.send({ t: 'ws_close', id: frame.id, code: 1013, reason: 'client too slow' })
          return
        }
        sock.send(Buffer.from(frame.payload), { binary: frame.kind === DATA_WS_BINARY })
      }
      return
    }
    // A control frame that is not JSON throws out to onAgentFrame (violation).
    const frame = decodeControl(toBuf(data).toString('utf8'))
    if (frame === null || typeof frame !== 'object' || typeof frame.t !== 'string') throw new Error('control frame is not an object')
    switch (frame.t) {
      case 'res_head': {
        const res = conn.responses.get(frame.id)
        conn.activity.set(frame.id, Date.now())
        if (res !== undefined && !res.headersSent) res.writeHead(frame.status, flatHeaders(frame.headers))
        break
      }
      case 'res_end':
        conn.responses.get(frame.id)?.end()
        conn.responses.delete(frame.id)
        conn.activity.delete(frame.id)
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
        conn.activity.delete(frame.id)
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
    const traffic = this.trafficOf(conn.subdomain)
    traffic.wsSessions++
    conn.sockets.set(id, browser)
    conn.send({ t: 'ws_open', id, path: req.url ?? '/', headers: headerList(req.rawHeaders) })
    browser.on('message', (data: RawData, isBinary: boolean) => {
      const buf = toBuf(data)
      traffic.bytesIn += buf.length
      // A browser socket cannot be paused; a sender that outruns the agent
      // uplink by a wide margin is dropped rather than buffered without bound.
      if (conn.ws.bufferedAmount > MAX_BUFFERED) {
        if (conn.sockets.delete(id)) conn.send({ t: 'ws_close', id, code: 1013, reason: 'uplink congested' })
        browser.close(1013, 'uplink congested')
        return
      }
      conn.sendData(isBinary ? DATA_WS_BINARY : DATA_WS_TEXT, id, buf)
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
    conn.activity.clear()
  }
}
