/**
 * Host half of the ds.hn agent — the dsh plugin that forwards this machine's
 * local dsh web service to the public internet.
 *
 * It opens one outbound WebSocket to the relay, claims a subdomain with the
 * (subdomain, password) the user typed in the setup dialog, and then replays
 * whatever the relay forwards against the local dsh server: HTTP over
 * `node:http`, and dsh's own downlink WebSockets (`/api/events.*`) over a
 * tunnelled `ws` client. Each replayed request has its Host/Origin rewritten to
 * loopback, so dsh's `/api` trust fence accepts it as a local same-origin
 * request for ANY public subdomain — no composition-time trustedHosts entry, and
 * access gated instead by the relay's login.
 *
 * The browser half (client.js) is the setup dialog + status widget; it drives
 * the `/dshn/status`, `/dshn/configure`, and `/dshn/disconnect` routes this half
 * registers on the dsh web server (all loopback-gated for configuration).
 */
import http from 'node:http'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, hostname } from 'node:os'
import { dirname, join } from 'node:path'
import z from '@deepseek-ai/schemastery'
import { WebSocket, type RawData } from 'ws'
import {
  AGENT_WS_PATH,
  isValidSubdomainLabel,
  DATA_REQ_BODY,
  DATA_RES_BODY,
  DATA_WS_BINARY,
  DATA_WS_TEXT,
  DSHN_PROTOCOL_VERSION,
  HEARTBEAT_TIMEOUT_MS,
  decodeControl,
  decodeData,
  encodeControl,
  encodeData,
  sanitizeCloseCode,
  sanitizeCloseReason,
  E2E_HEADER,
  E2E_MSG_BINARY,
  E2E_MSG_TEXT,
  E2E_PUB_PATH,
  type ControlFrame,
  type HeaderList,
  type TunnelRoute,
} from '@dshn/protocol'
import { deriveKey, newSalt, open as e2eOpen, seal as e2eSeal } from './crypto.js'

export const name = '@dshn/agent'

/**
 * Request header the agent stamps on EVERY request it replays from the tunnel to
 * local dsh. The loopback-only `/dshn/*` management routes treat any request
 * carrying it as non-local, which is the authoritative barrier against a remote
 * (authenticated) visitor reaching them via path confusion — the Host-based
 * loopback check alone cannot tell a replayed request from a genuinely local one,
 * because every replay's Host is rewritten to loopback.
 */
const TUNNEL_MARKER = 'x-dshn-forwarded'

/**
 * Injected services: the web server (listening port + our routes), and dsh's
 * settings service (so credentials persist into settings.yaml). Both are also
 * declared on the composition row — cordis reads the row's inject, so the module
 * list is mirrored there.
 */
export const inject = ['webServer', 'settings']

/** How often the agent pings the relay — for both liveness and a fresh latency reading. */
const LATENCY_PING_MS = 5_000

// schemastery is BUNDLED into the shipped plugin (esbuild inlines it): dsh
// resolves a plugin's imports from its own bare dist dir, so an external
// `@deepseek-ai/schemastery` won't resolve there — inlining a copy does, and
// dsh's settings service accepts the schema structurally. The composition row
// must also declare `inject: [settings]` (cordis reads the row's inject).

/**
 * Infrastructure config from the composition row (env-driven). Notably it holds
 * NO credentials: the subdomain and password are chosen at runtime in the UI and
 * persisted to {@link AgentConfig.statePath}, not baked into the composition.
 */
interface AgentConfig {
  enabled: boolean
  relayHost: string
  localHost: string
  localPort: number
  /** Path to a PEM cert to pin the origin against, when connecting direct (off-CF). */
  originCa: string
  /** File the chosen credentials persist to, so they survive a restart. */
  statePath: string
}

/**
 * Apply defaults to the raw composition-row config (no schema layer does it for
 * us). Everything here is infrastructure; credentials are set through the UI.
 * @param raw - the config object from the cordis entry, possibly partial.
 * @returns the normalized config.
 */
function normalizeConfig(raw: Partial<AgentConfig> | undefined): AgentConfig {
  const c = raw ?? {}
  return {
    enabled: c.enabled !== false,
    relayHost: typeof c.relayHost === 'string' && c.relayHost !== '' ? c.relayHost : 'relay.ds.hn',
    localHost: typeof c.localHost === 'string' && c.localHost !== '' ? c.localHost : '127.0.0.1',
    localPort: typeof c.localPort === 'number' ? c.localPort : 0,
    originCa: typeof c.originCa === 'string' ? c.originCa : '',
    statePath: typeof c.statePath === 'string' && c.statePath !== '' ? c.statePath : DEFAULT_STATE_PATH,
  }
}

/** Default state file: dsh's own config directory (next to settings.yaml). */
const DEFAULT_STATE_PATH = join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'dshn-agent.json')
/** Legacy state file (home root) the default path migrates from once. */
const LEGACY_STATE_PATH = join(homedir(), '.dshn-agent.json')

/** Persisted credentials the user set in the UI. */
interface Credentials {
  subdomain: string
  password: string
  /** Optional end-to-end password. When set, tunnel content is encrypted with it; never sent to the relay. */
  e2ePassword?: string
  /** Public salt for the e2e key derivation, generated once and persisted. */
  e2eSalt?: string
  /** Self-hosted relay authority (overrides the env/default `relay.ds.hn`); empty = default. */
  relayHost?: string
  /** PEM (inline content) to pin a self-signed self-hosted relay; empty = none. */
  originCa?: string
  /**
   * The authority the relay last told us to dial for the premium route (e.g.
   * `alice.ds.hn`). Remembered so a restart dials the fast path straight away;
   * cleared when the relay says the tunnel is back on the standard route.
   */
  routeHost?: string
}

/**
 * Where credentials live. Two implementations: dsh's own settings service
 * (settings.yaml, the default in a normal profile) and a plain file (headless
 * tests, and the migration source). Passwords are marked `role('secret')` in the
 * settings schema so dsh's own config surfaces redact them.
 */
export interface CredsStore {
  load(): Credentials | null
  save(creds: Credentials | null): void
}

/** Schemastery schema for the `dshn` settings namespace. */
const CREDS_SCHEMA = z.object({
  subdomain: z.string().default(''),
  password: z.string().role('secret').default(''),
  e2ePassword: z.string().role('secret').default(''),
  e2eSalt: z.string().default(''),
  relayHost: z.string().default(''),
  originCa: z.string().default(''),
  routeHost: z.string().default(''),
})

/** Read a credentials JSON file, or null. */
function readCredsFile(path: string): Credentials | null {
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<Credentials>
    if (typeof raw.subdomain === 'string' && typeof raw.password === 'string' && raw.subdomain !== '') {
      return {
        subdomain: raw.subdomain,
        password: raw.password,
        e2ePassword: typeof raw.e2ePassword === 'string' && raw.e2ePassword !== '' ? raw.e2ePassword : undefined,
        e2eSalt: typeof raw.e2eSalt === 'string' ? raw.e2eSalt : undefined,
        relayHost: typeof raw.relayHost === 'string' && raw.relayHost !== '' ? raw.relayHost : undefined,
        originCa: typeof raw.originCa === 'string' && raw.originCa !== '' ? raw.originCa : undefined,
        routeHost: typeof raw.routeHost === 'string' && raw.routeHost !== '' ? raw.routeHost : undefined,
      }
    }
  } catch {
    // Absent or unreadable.
  }
  return null
}

/** File-backed store (headless tests; also the legacy/default file path). */
export function fileStore(path: string): CredsStore {
  return {
    load: () => readCredsFile(path),
    save: (creds) => {
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(path, JSON.stringify(creds ?? {}), { mode: 0o600 })
    },
  }
}

/**
 * Settings-service store: credentials live in dsh's settings.yaml under the
 * `dshn` namespace. Reads are synchronous (resolved snapshot); writes go through
 * the async `update`, fire-and-forget (the in-memory state is already current).
 * On first use it migrates an existing local file into settings, then removes it.
 * @param scope - the registered SettingsScope for the `dshn` namespace.
 * @param migrateFrom - candidate file paths to import once, in order.
 */
export function settingsStore(scope: any, migrateFrom: string[]): CredsStore {
  const store: CredsStore = {
    load: () => {
      const v = scope.get() ?? {}
      return typeof v.subdomain === 'string' && v.subdomain !== ''
        ? { subdomain: v.subdomain, password: v.password ?? '', e2ePassword: v.e2ePassword || undefined, e2eSalt: v.e2eSalt || undefined, relayHost: v.relayHost || undefined, originCa: v.originCa || undefined, routeHost: v.routeHost || undefined }
        : null
    },
    save: (creds) => {
      Promise.resolve(scope.update({
        subdomain: creds?.subdomain ?? '',
        password: creds?.password ?? '',
        e2ePassword: creds?.e2ePassword ?? '',
        e2eSalt: creds?.e2eSalt ?? '',
        relayHost: creds?.relayHost ?? '',
        originCa: creds?.originCa ?? '',
        routeHost: creds?.routeHost ?? '',
      })).catch(() => {})
    },
  }
  if (store.load() === null) {
    for (const path of migrateFrom) {
      const legacy = readCredsFile(path)
      if (legacy !== null) {
        store.save(legacy)
        // Only remove the source once the settings snapshot actually reflects the
        // migrated creds. `save` is fire-and-forget (async disk flush): if it
        // silently dropped, or the service updates its in-memory snapshot only
        // after the flush, `load()` stays null and we KEEP the file as the durable
        // copy rather than delete the user's only credentials.
        if (store.load() !== null) {
          try { rmSync(path, { force: true }) } catch { /* best effort */ }
        }
        break
      }
    }
  }
  return store
}

/** Live tunnel state, surfaced to the browser widget through `/dshn/status`. */
interface TunnelStatus {
  enabled: boolean
  /** Whether credentials have been set (via the UI or a prior session). */
  configured: boolean
  connected: boolean
  publicUrl: string | null
  subdomain: string | null
  lastError: string | null
  /** The route the relay assigned (null until the first READY on a route-aware relay). */
  route: TunnelRoute | null
}

/**
 * Consecutive failed dials of the premium host before the agent falls back to
 * its default relay host for a while. The relay then re-announces the route on
 * READY, so the premium path is retried automatically each fallback period.
 */
const ROUTE_FAIL_MAX = 3
/** How long a failed premium host is left alone before it is dialled again. */
const ROUTE_FALLBACK_MS = 5 * 60_000

/**
 * A relay-supplied route host must be a plain authority (`host[:port]`) or a
 * `ws(s)://` URL — nothing that could smuggle a path or credentials into the
 * dial. Hostname chars only; the relay is trusted, the shape is checked.
 */
function isValidRouteHost(raw: unknown): raw is string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 253) return false
  const bare = raw.replace(/^wss?:\/\//, '')
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/i.test(bare)
}

/** Coerce a `ws` message payload to a single Buffer. */
function toBuf(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data
  if (Array.isArray(data)) return Buffer.concat(data)
  return Buffer.from(data as ArrayBuffer)
}

/** Hop-by-hop headers that must not cross a proxy boundary; dropped both ways. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'te',
  'trailer',
])

/**
 * Filter a header list for replay, dropping hop-by-hop headers while preserving
 * order and duplicates (e.g. multiple `set-cookie`).
 * @param headers - the source header list.
 * @param drop - extra header names to drop, lowercased.
 * @returns the filtered list.
 */
function filterHeaders(headers: HeaderList, drop: Set<string> = HOP_BY_HOP): HeaderList {
  return headers.filter(([name]) => !drop.has(name.toLowerCase()))
}

/**
 * Collect a node response/request header bag into an ordered list, expanding
 * `set-cookie` (which node exposes as an array) into one pair per cookie.
 * @param raw - `res.rawHeaders`-style flat array of alternating name/value.
 * @returns the header list.
 */
function headerListFromRaw(raw: string[]): HeaderList {
  const out: HeaderList = []
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i], raw[i + 1]])
  return out
}

/** WebSocket handshake headers that `ws` regenerates per hop and must not be forwarded. */
const WS_STRIP = new Set([
  'connection',
  'upgrade',
  'sec-websocket-key',
  'sec-websocket-version',
  'sec-websocket-extensions',
  'sec-websocket-accept',
  'host',
  'origin',
  'content-length',
])

/**
 * One outbound tunnel: owns the control socket, its reconnect loop, and every
 * in-flight replayed stream. A single instance lives for the plugin's lifetime.
 * Exported so an integration test can drive it directly, without a dsh context.
 */
export class AgentTunnel {
  private control: WebSocket | null = null
  private stopped = false
  private backoffMs = 1_000
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private lastPong = 0

  /** Local dsh HTTP requests we are currently streaming a body into, by stream id. */
  private readonly requests = new Map<number, http.ClientRequest>()
  /** E2E requests being buffered (body collected whole so it can be decrypted), by stream id. */
  private readonly reqE2E = new Map<number, { method: string; path: string; headers: http.OutgoingHttpHeaders; marked: boolean; chunks: Buffer[] }>()
  /** Tunnelled local dsh WebSockets, by stream id. */
  private readonly sockets = new Map<number, WebSocket>()
  /** Derived AES key when an e2e password is set; null when E2E is off. */
  private e2eKey: Buffer | null = null
  /** Public salt for the current e2e key. */
  private e2eSalt = ''

  /**
   * Stable device identity for multi-device: several machines may bind the same
   * subdomain, and the relay tells them apart by this id. Derived, not stored:
   * hashing the hostname with the state path gives an id that survives restarts
   * and disconnects, distinguishes two profiles on one machine (different
   * DSH_HOME/DSHN_STATE), and needs no schema or migration. Two agents sharing
   * one profile dir collide — deliberately, since sharing a profile already
   * means fighting over the same credentials.
   */
  readonly deviceId: string
  /** Human-readable device name shown in the relay's switcher (env override, else hostname). */
  readonly deviceName: string

  readonly status: TunnelStatus
  private creds: Credentials | null = null
  /** ms epoch the current tunnel became live (READY), or null when down. */
  private connectedSince: number | null = null
  /** Count of public HTTP requests replayed to local dsh this process. */
  private served = 0
  /** Round-trip latency of the control socket (agent↔relay), or null if unknown. */
  private latencyMs: number | null = null
  /** ms epoch the outstanding latency ping was sent (0 = none in flight). */
  private pingSentAt = 0
  /** The authority the current control socket was dialled through. */
  private dialledHost: string | null = null
  /** Consecutive dials of the premium host that died before READY. */
  private routeFails = 0
  /** Until when (ms epoch) the premium host is skipped in favour of the default relay. */
  private routeFallbackUntil = 0

  constructor(private readonly config: AgentConfig, private readonly localPort: () => number, private readonly store: CredsStore) {
    this.deviceId = createHash('sha256').update(`${hostname()}|${config.statePath}`).digest('hex').slice(0, 12)
    this.deviceName = (process.env.DSHN_DEVICE_NAME ?? hostname()).trim().slice(0, 40) || this.deviceId
    this.creds = this.store.load()
    this.refreshE2E()
    this.status = {
      enabled: config.enabled,
      configured: this.creds !== null,
      connected: false,
      publicUrl: null,
      subdomain: this.creds?.subdomain ?? null,
      lastError: null,
      route: null,
    }
  }

  /**
   * (Re)derive the e2e key from the stored e2e password, minting and persisting
   * a salt on first use. Off (key = null) when no e2e password is set.
   */
  private refreshE2E(): void {
    const pw = this.creds?.e2ePassword
    if (this.creds !== null && typeof pw === 'string' && pw.length > 0) {
      if (typeof this.creds.e2eSalt !== 'string' || this.creds.e2eSalt === '') {
        this.creds.e2eSalt = newSalt()
        this.saveCreds(this.creds)
      }
      this.e2eSalt = this.creds.e2eSalt
      this.e2eKey = deriveKey(pw, this.e2eSalt)
    } else {
      this.e2eKey = null
      this.e2eSalt = ''
    }
  }

  /** Persist credentials through the configured store. */
  private saveCreds(creds: Credentials | null): void {
    try {
      this.store.save(creds)
    } catch (err) {
      this.status.lastError = `cannot save config: ${(err as Error).message}`
    }
  }

  /**
   * Set (or replace) the credentials from the UI and reconnect. Validation
   * mirrors the relay's so the user sees the error locally before a round trip.
   * @returns null on success, or a human-readable error.
   */
  configure(subdomain: string, password: string, relayHost?: string, originCa?: string): string | null {
    const label = String(subdomain).trim().toLowerCase()
    if (!isValidSubdomainLabel(label)) return 'Invalid subdomain: 4–32 lowercase letters, digits or hyphens (not reserved).'
    if (String(password).length < 8) return 'Password must be at least 8 characters.'
    // Self-hosted relay overrides (optional): a passed string replaces the setting
    // (empty clears it → back to the env/default relay); undefined keeps the
    // current one. Lets a self-hoster point at their own relay from the UI.
    const rh = typeof relayHost === 'string' ? relayHost.trim() : (this.creds?.relayHost ?? '')
    const ca = typeof originCa === 'string' ? originCa.trim() : (this.creds?.originCa ?? '')
    // The e2e password is managed independently (setE2E); a subdomain/password
    // change preserves it untouched.
    // A different subdomain (or relay) may be on a different route: forget the
    // remembered premium host and let the relay announce it again on READY.
    const sameTarget = this.creds?.subdomain === label && (this.creds?.relayHost ?? '') === (rh || '')
    this.creds = { subdomain: label, password: String(password), e2ePassword: this.creds?.e2ePassword, e2eSalt: this.creds?.e2eSalt, relayHost: rh || undefined, originCa: ca || undefined, routeHost: sameTarget ? this.creds?.routeHost : undefined }
    this.status.route = null
    this.refreshE2E()
    this.saveCreds(this.creds)
    this.status.configured = true
    this.status.subdomain = label
    this.status.lastError = null
    // Drop any existing socket and connect fresh with the new credentials.
    this.control?.close()
    this.control = null
    this.backoffMs = 1_000
    this.connect()
    return null
  }

  /**
   * Set, change, or clear the end-to-end password INDEPENDENTLY of the main
   * config. It only re-derives the content key — the tunnel connection to the
   * relay does not depend on it, so this never drops or reconnects the tunnel.
   * @param e2ePassword - the new e2e password; empty/null turns E2E off.
   * @returns null on success, or a human-readable error.
   */
  setE2E(e2ePassword: string | null): string | null {
    if (this.creds === null) return 'Set up the tunnel first, then add an end-to-end password.'
    const e2e = typeof e2ePassword === 'string' ? e2ePassword.trim() : ''
    if (e2e !== '' && e2e.length < 8) return 'End-to-end password must be at least 8 characters.'
    const next = e2e === '' ? undefined : e2e
    // A changed password gets a fresh salt (drop it so refreshE2E mints one);
    // an unchanged one keeps its salt so already-unlocked browsers stay valid.
    const changed = this.creds.e2ePassword !== next
    this.creds = { ...this.creds, e2ePassword: next, e2eSalt: changed ? undefined : this.creds.e2eSalt }
    this.refreshE2E()
    this.saveCreds(this.creds)
    return null
  }

  /**
   * The saved password, for the local UI's "reveal" — the cloud only stores a
   * hash and offers no recovery, so this local copy is the only way back to a
   * forgotten password. Callers MUST gate this on a loopback request.
   */
  revealPassword(): string | null {
    return this.creds?.password ?? null
  }

  /** The saved e2e password, for the local UI's reveal (loopback callers only). */
  revealE2EPassword(): string | null {
    return this.creds?.e2ePassword ?? null
  }

  /** Whether end-to-end encryption is on, and the public salt browsers derive from. */
  e2eInfo(): { enabled: boolean; salt: string } {
    return { enabled: this.e2eKey !== null, salt: this.e2eSalt }
  }

  /** The relay authority actually dialled: the user's self-hosted override if set, else the env/default. */
  private effectiveRelayHost(): string {
    const c = this.creds?.relayHost
    return typeof c === 'string' && c !== '' ? c : this.config.relayHost
  }

  /** The origin CA to pin, as PEM bytes: inline PEM from the UI, or an env-configured file path. */
  private effectiveOriginCa(): Buffer | null {
    const raw = (this.creds?.originCa && this.creds.originCa !== '') ? this.creds.originCa : this.config.originCa
    if (raw === '' || raw === undefined) return null
    if (raw.includes('BEGIN CERTIFICATE')) return Buffer.from(raw) // inline PEM pasted in the UI
    try { return readFileSync(raw) } catch { return null } // a file path (env DSHN_ORIGIN_CA)
  }

  /** The raw self-hosted overrides, for the settings UI to pre-fill (loopback callers only). */
  relaySettings(): { relayHost: string; originCa: string } {
    return { relayHost: this.creds?.relayHost ?? '', originCa: this.creds?.originCa ?? '' }
  }

  /** Connection details for the local panel (relay, mode, uptime, latency, throughput). */
  info(): { relayHost: string; direct: boolean; route: TunnelRoute | null; routeHost: string | null; connectedSince: number | null; served: number; localPort: number; latencyMs: number | null } {
    const host = this.effectiveRelayHost()
    const direct = /^wss?:\/\//.test(host) || this.effectiveOriginCa() !== null
    // Once connected, report the authority actually in use (the premium host
    // when on that route), not just the configured default.
    const live = this.status.connected && this.dialledHost !== null ? this.dialledHost : host
    return {
      relayHost: live.replace(/^wss?:\/\//, '').replace(/\/.*$/, ''),
      direct,
      route: this.status.route,
      routeHost: this.creds?.routeHost ?? null,
      connectedSince: this.connectedSince,
      served: this.served,
      localPort: this.localPort(),
      latencyMs: this.latencyMs,
    }
  }

  /** Forget the credentials, disconnect, and stop reconnecting until reconfigured. */
  disconnect(): void {
    this.creds = null
    this.saveCreds(null)
    this.status.configured = false
    this.status.connected = false
    this.status.publicUrl = null
    this.status.subdomain = null
    this.status.route = null
    this.routeFails = 0
    this.routeFallbackUntil = 0
    if (this.reconnectTimer !== null) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null }
    this.control?.close()
    this.control = null
  }

  start(): void {
    if (!this.config.enabled || this.creds === null) return
    this.connect()
  }

  stop(): void {
    this.stopped = true
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer)
    if (this.heartbeatTimer !== null) clearInterval(this.heartbeatTimer)
    for (const req of this.requests.values()) req.destroy()
    for (const sock of this.sockets.values()) sock.close()
    this.requests.clear()
    this.sockets.clear()
    this.control?.close()
    this.control = null
    this.status.connected = false
  }

  /**
   * Which authority to dial: the relay-assigned premium host when one is
   * remembered and not in a fallback period, else the default relay host. The
   * premium host is only ever set by a route announcement from the relay.
   */
  private dialHost(): string {
    const route = this.creds?.routeHost
    if (route !== undefined && route !== '' && Date.now() >= this.routeFallbackUntil) return route
    return this.effectiveRelayHost()
  }

  /** Whether the live control socket was dialled through the remembered premium host. */
  private onPremiumPath(): boolean {
    const route = this.creds?.routeHost
    return route !== undefined && route !== '' && this.dialledHost === route
  }

  /** Whether the premium host is currently being skipped after repeated failures. */
  private inRouteFallback(): boolean {
    return Date.now() < this.routeFallbackUntil
  }

  /**
   * Apply a route announcement (READY or a mid-session ROUTE frame).
   *
   * `status.route` reflects the OPERATOR'S ASSIGNMENT, because that is what a
   * public visitor experiences: enabling premium points the subdomain's DNS at
   * the accelerator, so browser traffic is accelerated no matter which host the
   * agent's own control socket happens to use. Moving the control socket onto
   * the premium host too is a best-effort bonus for the uplink — it may briefly
   * fail while the fresh DNS record propagates, and if the host stays
   * unreachable the agent quietly keeps its control socket on the default relay.
   * Neither case changes the displayed route or breaks the tunnel.
   *
   * - `premium` with a usable host: show premium, remember the host, and (unless
   *   in a fallback window) redial through it to accelerate the uplink as well.
   * - `standard`: the operator withdrew the fast path — show standard, forget
   *   the host, and return the control socket to the default relay.
   */
  private applyRoute(route: unknown, routeHost: unknown): void {
    if (this.creds === null) return
    if (route === 'premium' && isValidRouteHost(routeHost)) {
      this.status.route = 'premium'
      if (this.creds.routeHost !== routeHost) {
        this.creds = { ...this.creds, routeHost }
        this.saveCreds(this.creds)
      }
      // Move the uplink onto the premium host too, when it's worth a redial and
      // not currently being skipped after repeated failures.
      if (!this.inRouteFallback() && this.dialledHost !== routeHost) this.redial()
      return
    }
    if (route === 'standard' || route === 'premium') {
      // Standard (or premium the relay could not give a usable host for).
      this.status.route = 'standard'
      this.routeFallbackUntil = 0
      this.routeFails = 0
      const hadRoute = this.creds.routeHost !== undefined && this.creds.routeHost !== ''
      if (hadRoute) {
        this.creds = { ...this.creds, routeHost: undefined }
        this.saveCreds(this.creds)
        if (this.dialledHost !== this.effectiveRelayHost()) this.redial()
      }
    }
  }

  /** Drop the live socket and dial again right away (route change). */
  private redial(): void {
    if (process.env.DSHN_DEBUG) console.error(`[dshn-agent] route change → redialling via ${this.dialHost()}`)
    this.backoffMs = 1_000
    const ws = this.control
    this.control = null
    ws?.close()
    // The closed socket's handler sees it is no longer `this.control` and stays
    // quiet; this fresh connect owns the reconnect chain from here.
    this.connect()
  }

  private connect(): void {
    if (this.stopped || this.creds === null) return
    // Never run two control sockets at once. A stale reconnect timer firing while
    // a socket is already connecting/open would create an overlap that the relay
    // resolves by terminating one — which then schedules another reconnect, a
    // self-sustaining cascade that fails in-flight requests every cycle.
    if (this.control !== null
      && (this.control.readyState === WebSocket.CONNECTING || this.control.readyState === WebSocket.OPEN)) {
      return
    }
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    // Bare host → wss:// (behind Cloudflare in production); a full ws(s):// URL
    // is honoured as-is so a loopback test can drive a plain-ws relay. The host is
    // the user's self-hosted override when set, else the env/default relay.
    const relayHost = this.dialHost()
    const base = relayHost.includes('://') ? relayHost : `wss://${relayHost}`
    this.dialledHost = relayHost
    const wsOpts: Record<string, unknown> = { maxPayload: 512 * 1024 * 1024 }
    // Pin a self-signed relay's cert (as the sole CA) so validation stays strict
    // without a public CA. Also used for a direct off-Cloudflare origin. The PEM
    // is either pasted inline in the UI or an env-configured file path.
    const ca = this.effectiveOriginCa()
    if (ca !== null) wsOpts.ca = ca
    const ws = new WebSocket(`${base}${AGENT_WS_PATH}`, wsOpts)
    this.control = ws
    if (process.env.DSHN_DEBUG) console.error(`[dshn-agent] connect() opening new ws (backoff=${this.backoffMs})`)

    ws.on('open', () => {
      if (process.env.DSHN_DEBUG) console.error('[dshn-agent] ws open → hello')
      if (this.creds !== null) {
        this.send({
          t: 'hello',
          subdomain: this.creds.subdomain,
          password: this.creds.password,
          agent: `dshn-agent/${DSHN_PROTOCOL_VERSION}`,
          protocol: DSHN_PROTOCOL_VERSION,
          deviceId: this.deviceId,
          device: this.deviceName,
        })
      }
      this.lastPong = Date.now()
      this.startHeartbeat()
    })
    ws.on('message', (data: RawData, isBinary: boolean) => this.onMessage(data, isBinary))
    ws.on('close', (code: number, reason: Buffer) => {
      if (process.env.DSHN_DEBUG) console.error(`[dshn-agent] ws close code=${code} reason=${reason.toString('utf8')}`)
      // Only the live control socket's close drives a reconnect. A superseded
      // socket closing (should not happen with the overlap guard, but belt and
      // suspenders) must not schedule its own reconnect.
      if (ws === this.control) this.onClose()
    })
    ws.on('error', (err: Error) => {
      if (process.env.DSHN_DEBUG) console.error(`[dshn-agent] ws error ${err.message}`)
      this.status.lastError = err.message
      // 'close' fires after 'error' and owns the reconnect; nothing to do here.
    })
  }

  /** Send a latency ping and mark when, so the pong can measure the round trip. */
  private sendPing(): void {
    if (this.control?.readyState !== WebSocket.OPEN) return
    this.pingSentAt = Date.now()
    this.send({ t: 'ping' })
  }

  private startHeartbeat(): void {
    if (this.heartbeatTimer !== null) clearInterval(this.heartbeatTimer)
    // Ping every few seconds (well under Cloudflare's ~100s idle cut): this keeps
    // the tunnel alive AND refreshes the latency reading shown on the pill.
    this.heartbeatTimer = setInterval(() => {
      if (this.control === null || this.control.readyState !== WebSocket.OPEN) return
      if (Date.now() - this.lastPong > HEARTBEAT_TIMEOUT_MS) {
        // The relay (or the path through Cloudflare) went quiet; force a rebuild.
        this.control.terminate()
        return
      }
      // Assigned premium but the uplink is still on the default relay and the
      // fallback window has passed: retry the premium host now (the DNS record
      // has had time to propagate, or the accelerator has recovered).
      if (this.status.route === 'premium' && this.creds?.routeHost && !this.onPremiumPath() && !this.inRouteFallback()) {
        this.redial()
        return
      }
      this.sendPing()
    }, LATENCY_PING_MS)
  }

  private onClose(): void {
    // A premium-host dial that died before READY counts against that host; after
    // a few in a row the agent keeps its control socket on the default relay for
    // a while (the premium DNS record may just be propagating). Browser traffic
    // is unaffected — it reaches the accelerator by DNS regardless — so this is
    // silent: the displayed route stays on the operator's assignment.
    if (!this.status.connected && this.onPremiumPath()) {
      this.routeFails++
      if (this.routeFails >= ROUTE_FAIL_MAX) {
        this.routeFails = 0
        this.routeFallbackUntil = Date.now() + ROUTE_FALLBACK_MS
      }
    }
    this.status.connected = false
    this.connectedSince = null
    this.latencyMs = null
    this.pingSentAt = 0
    this.control = null
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
    for (const req of this.requests.values()) req.destroy()
    for (const sock of this.sockets.values()) sock.close()
    this.requests.clear()
    this.sockets.clear()
    if (this.stopped) return
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer)
    // Exponential backoff, capped, so a down relay is not hammered.
    this.reconnectTimer = setTimeout(() => this.connect(), this.backoffMs)
    this.backoffMs = Math.min(this.backoffMs * 2, 30_000)
  }

  private send(frame: ControlFrame): void {
    if (this.control?.readyState === WebSocket.OPEN) this.control.send(encodeControl(frame))
  }

  private sendData(kind: 1 | 2 | 3 | 4, id: number, payload: Uint8Array): void {
    if (this.control?.readyState === WebSocket.OPEN) this.control.send(encodeData(kind, id, payload))
  }

  private onMessage(data: RawData, isBinary: boolean): void {
    // A single malformed or hostile frame must never throw into ws's event
    // loop: an uncaught throw here crashes the whole dsh process this plugin
    // runs inside. Every frame is handled under one guard.
    try {
      this.dispatch(data, isBinary)
    } catch (err) {
      this.status.lastError = `frame handling error: ${(err as Error).message}`
    }
  }

  private dispatch(data: RawData, isBinary: boolean): void {
    const buf = toBuf(data)
    if (isBinary) {
      const frame = decodeData(buf)
      if (frame.kind === DATA_REQ_BODY) {
        const buffered = this.reqE2E.get(frame.id)
        if (buffered !== undefined) buffered.chunks.push(Buffer.from(frame.payload))
        else this.requests.get(frame.id)?.write(Buffer.from(frame.payload))
      } else if (frame.kind === DATA_WS_TEXT || frame.kind === DATA_WS_BINARY) {
        this.sockets.get(frame.id)?.send(Buffer.from(frame.payload), { binary: frame.kind === DATA_WS_BINARY })
      }
      return
    }
    const frame = decodeControl(buf.toString('utf8'))
    switch (frame.t) {
      case 'ready':
        this.backoffMs = 1_000
        this.routeFails = 0
        this.status.connected = true
        this.status.publicUrl = frame.publicUrl
        this.status.subdomain = frame.subdomain
        this.status.lastError = null
        this.connectedSince = Date.now()
        this.sendPing() // measure latency immediately, don't wait a full interval
        // A route-aware relay says which path this tunnel is on; an older relay
        // says nothing and the tunnel simply stays where it dialled.
        if (frame.route !== undefined) this.applyRoute(frame.route, frame.routeHost)
        break
      case 'route':
        this.applyRoute(frame.route, frame.routeHost)
        break
      case 'deny':
        // Wrong password / taken subdomain won't fix itself on retry, but the
        // user can reconfigure — so pause reconnection by forgetting creds
        // rather than tearing down the plugin. The error stays visible in the UI.
        this.status.lastError = frame.reason
        this.creds = null
        this.status.configured = false
        this.status.connected = false
        this.control?.close()
        break
      case 'pong':
        this.lastPong = Date.now()
        if (this.pingSentAt !== 0) {
          this.latencyMs = Date.now() - this.pingSentAt
          this.pingSentAt = 0
        }
        break
      case 'ping':
        this.send({ t: 'pong' })
        this.lastPong = Date.now()
        break
      case 'req_head':
        this.openRequest(frame.id, frame.method, frame.path, frame.headers)
        break
      case 'req_end': {
        const buffered = this.reqE2E.get(frame.id)
        if (buffered !== undefined) this.finishE2ERequest(frame.id)
        else this.requests.get(frame.id)?.end()
        break
      }
      case 'ws_open':
        this.openSocket(frame.id, frame.path, frame.headers)
        break
      case 'ws_close':
        this.sockets.get(frame.id)?.close(sanitizeCloseCode(frame.code), sanitizeCloseReason(frame.reason))
        break
      case 'abort':
        this.requests.get(frame.id)?.destroy()
        this.reqE2E.delete(frame.id)
        this.sockets.get(frame.id)?.close()
        break
      default:
        break
    }
  }

  /** The loopback authority local dsh is actually reached on (Host/Origin value). */
  private loopbackAuthority(): string {
    return `${this.config.localHost}:${this.localPort()}`
  }

  /**
   * Build the outgoing header bag for a replayed request: hop-by-hop stripped,
   * duplicates preserved, and Host/Origin rewritten to the local loopback
   * authority so dsh's /api fence accepts it as a local same-origin request for
   * any public subdomain (access is gated by the relay login, not the fence).
   */
  private loopbackHeaders(headers: HeaderList): http.OutgoingHttpHeaders {
    const out: http.OutgoingHttpHeaders = {}
    for (const [k, v] of filterHeaders(headers)) {
      const key = k.toLowerCase()
      const existing = out[key]
      if (existing === undefined) out[key] = v
      else if (Array.isArray(existing)) existing.push(v)
      else out[key] = [existing as string, v]
    }
    const authority = this.loopbackAuthority()
    out.host = authority
    if (out.origin !== undefined) out.origin = `http://${authority}`
    // Mark every replayed tunnel request. The /dshn/* management routes treat any
    // request bearing this header as NON-local — so even a path-confusion bypass
    // of the /dshn/ guard (e.g. `/api/../dshn/status` or `/%2e/dshn/status`, which
    // dsh normalizes back to `/dshn/status`) cannot reach the loopback-only
    // surface that reveals the password / e2e password / reconfigures the tunnel.
    // This boundary is independent of how the path is parsed or normalized.
    out[TUNNEL_MARKER] = '1'
    return out
  }

  /** Replay one HTTP request against local dsh and stream the response back. */
  private openRequest(id: number, method: string, path: string, headers: HeaderList): void {
    // The agent's own /dshn/* management routes must NEVER be reachable through
    // the tunnel — the loopback rewrite would otherwise make them look local and
    // leak the password / allow remote reconfigure. The TUNNEL_MARKER header is
    // the authoritative barrier; this normalized-path guard is defense-in-depth,
    // rejecting dot-segment / percent-encoded forms (`/api/../dshn/status`,
    // `/%2e/dshn/status`) that dsh would normalize back to `/dshn/…` before the
    // request even reaches dsh. (The /dshn-e2e info route is a different,
    // deliberately-public prefix and stays reachable.)
    if (targetsManagementRoute(path)) {
      this.send({ t: 'res_head', id, status: 404, headers: [['content-type', 'text/plain']] })
      this.sendData(DATA_RES_BODY, id, Buffer.from('not found'))
      this.send({ t: 'res_end', id })
      return
    }
    this.served += 1
    const bare = path.split('?', 1)[0]
    const outHeaders = this.loopbackHeaders(headers)

    // When E2E is on, /api bodies are sealed: buffer the request whole so it can
    // be decrypted at req_end, and seal the response before it leaves. Only /api
    // is sealed — the app shell and plugin bundles must stay plaintext so the
    // browser can bootstrap the very code that does the decryption.
    if (this.e2eKey !== null && bare.startsWith('/api')) {
      outHeaders['accept-encoding'] = 'identity' // seal plaintext, not gzip/br
      const marked = headers.some(([k]) => k.toLowerCase() === E2E_HEADER)
      this.reqE2E.set(id, { method, path, headers: outHeaders, marked, chunks: [] })
      return
    }

    const req = http.request(
      { host: this.config.localHost, port: this.localPort(), method, path, headers: outHeaders },
      (res) => {
        this.send({
          t: 'res_head',
          id,
          status: res.statusCode ?? 502,
          headers: filterHeaders(headerListFromRaw(res.rawHeaders)),
        })
        res.on('data', (chunk: Buffer) => this.sendData(DATA_RES_BODY, id, chunk))
        res.on('end', () => this.send({ t: 'res_end', id }))
        res.on('error', () => this.send({ t: 'abort', id, reason: 'response stream error' }))
      },
    )
    req.on('error', (err: Error) => {
      this.requests.delete(id)
      this.send({ t: 'res_head', id, status: 502, headers: [['content-type', 'text/plain']] })
      this.sendData(DATA_RES_BODY, id, Buffer.from(`dsh unreachable: ${err.message}`))
      this.send({ t: 'res_end', id })
    })
    req.on('close', () => this.requests.delete(id))
    this.requests.set(id, req)
  }

  /**
   * Finish a buffered E2E /api request: decrypt the request body (if the browser
   * sealed it), replay it against local dsh, then seal the whole response body
   * before sending it back. The relay only ever sees ciphertext for these.
   */
  private finishE2ERequest(id: number): void {
    const pending = this.reqE2E.get(id)
    this.reqE2E.delete(id)
    if (pending === undefined || this.e2eKey === null) return
    let body: Buffer = Buffer.concat(pending.chunks)
    if (pending.marked && body.length > 0) {
      try {
        body = e2eOpen(this.e2eKey, body)
      } catch {
        // Wrong key / tampered request — refuse without touching dsh.
        this.send({ t: 'res_head', id, status: 400, headers: [['content-type', 'text/plain']] })
        this.sendData(DATA_RES_BODY, id, Buffer.from('e2e: cannot decrypt request'))
        this.send({ t: 'res_end', id })
        return
      }
    }
    delete pending.headers[E2E_HEADER]
    pending.headers['content-length'] = String(body.length)
    const req = http.request(
      { host: this.config.localHost, port: this.localPort(), method: pending.method, path: pending.path, headers: pending.headers },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          const sealed = e2eSeal(this.e2eKey as Buffer, Buffer.concat(chunks))
          // Drop length/encoding of the plaintext; the sealed blob has its own.
          const resHeaders = filterHeaders(headerListFromRaw(res.rawHeaders),
            new Set([...HOP_BY_HOP, 'content-length', 'content-encoding']))
          resHeaders.push([E2E_HEADER, '1'], ['content-length', String(sealed.length)])
          this.send({ t: 'res_head', id, status: res.statusCode ?? 502, headers: resHeaders })
          this.sendData(DATA_RES_BODY, id, sealed)
          this.send({ t: 'res_end', id })
        })
        res.on('error', () => this.send({ t: 'abort', id, reason: 'response stream error' }))
      },
    )
    req.on('error', (err: Error) => {
      this.send({ t: 'res_head', id, status: 502, headers: [['content-type', 'text/plain']] })
      this.sendData(DATA_RES_BODY, id, Buffer.from(`dsh unreachable: ${err.message}`))
      this.send({ t: 'res_end', id })
    })
    req.end(body)
  }

  /** Open a tunnelled WebSocket against local dsh, presented as a loopback upgrade. */
  private openSocket(id: number, path: string, headers: HeaderList): void {
    const authority = this.loopbackAuthority()
    const forwarded: Record<string, string> = {}
    for (const [k, v] of headers) {
      if (!WS_STRIP.has(k.toLowerCase())) forwarded[k] = v
    }
    // Same loopback rewrite as HTTP: the upgrade passes dsh's fence as a
    // loopback, same-origin request, for any public subdomain.
    forwarded.host = authority
    forwarded.origin = `http://${authority}`
    const url = `ws://${this.config.localHost}:${this.localPort()}${path}`
    const sock = new WebSocket(url, { headers: forwarded, origin: forwarded.origin })

    // dsh's event sockets are downlink-only (`/api/events.*`), so we seal each
    // message the agent pushes to the browser when E2E is on. The type byte
    // preserves text-vs-binary through the (always-binary) ciphertext frame.
    const sealMessages = this.e2eKey !== null && path.split('?', 1)[0].startsWith('/api')
    sock.on('open', () => this.send({ t: 'ws_ready', id }))
    sock.on('message', (data: RawData, isBinary: boolean) => {
      const raw = toBuf(data)
      if (sealMessages && this.e2eKey !== null) {
        const typed = Buffer.concat([Buffer.from([isBinary ? E2E_MSG_BINARY : E2E_MSG_TEXT]), raw])
        this.sendData(DATA_WS_BINARY, id, e2eSeal(this.e2eKey, typed))
      } else {
        this.sendData(isBinary ? DATA_WS_BINARY : DATA_WS_TEXT, id, raw)
      }
    })
    sock.on('close', (code: number, reason: Buffer) => {
      this.sockets.delete(id)
      this.send({ t: 'ws_close', id, code: sanitizeCloseCode(code), reason: sanitizeCloseReason(reason.toString('utf8')) })
    })
    sock.on('unexpected-response', (_req, res) => {
      this.sockets.delete(id)
      this.send({ t: 'ws_reject', id, status: res.statusCode ?? 502 })
    })
    sock.on('error', () => {
      if (this.sockets.has(id)) {
        this.sockets.delete(id)
        this.send({ t: 'ws_close', id, code: 1011, reason: 'local socket error' })
      }
    })
    this.sockets.set(id, sock)
  }
}

/**
 * Whether a request reached us over loopback. Configuration is only permitted
 * from the local machine: when the tunnel is up, the same routes are reachable
 * over the public URL, and a public visitor (already past the relay login) must
 * not be able to read or change the credentials.
 */
/**
 * Whether a tunnelled request path targets the agent's own `/dshn/*` management
 * routes after the kind of normalization dsh applies — percent-decoding and
 * resolving `.`/`..`/`//` segments. A naive `startsWith('/dshn/')` misses
 * `/api/../dshn/status`, `/%2e/dshn/status`, etc., which dsh normalizes back to
 * `/dshn/status`. Only the routing decision uses this; the original path is still
 * forwarded verbatim to dsh.
 */
export function targetsManagementRoute(rawPath: string): boolean {
  let p = rawPath.split('?', 1)[0].split('#', 1)[0]
  try { p = decodeURIComponent(p) } catch { /* malformed %-escape: judge the raw form */ }
  p = p.replace(/\\/g, '/')
  const segs: string[] = []
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') { segs.pop(); continue }
    segs.push(seg)
  }
  const norm = '/' + segs.join('/')
  return norm === '/dshn' || norm.startsWith('/dshn/')
}

export function isLoopbackRequest(req: http.IncomingMessage): boolean {
  // A request the agent itself replayed from the tunnel is NEVER local — however
  // its Host was rewritten to loopback and however dsh normalized its path. This
  // marker (set on every replay in loopbackHeaders) is the authoritative boundary
  // for the password-revealing management routes; the Host check below alone is
  // not, because replayed requests all carry a loopback Host.
  if (req.headers[TUNNEL_MARKER] !== undefined) return false
  const host = String(req.headers.host ?? '')
  // Strip the port and any IPv6 brackets, then match the loopback hostnames.
  const hostname = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase()
  return hostname === 'localhost' || hostname === '::1' || hostname.startsWith('127.')
}

/**
 * The public apex a subdomain will live under, derived from the dial host for
 * the setup form's live preview. `relay.ds.hn` / `origin.ds.hn:8787` → `ds.hn`;
 * a bare apex is returned as-is. The relay is authoritative once connected
 * (READY carries the real publicUrl); this is only the pre-connect hint.
 */
function publicApex(relayHost: string): string {
  const bare = relayHost.replace(/^wss?:\/\//, '').replace(/:\d+$/, '')
  const parts = bare.split('.')
  if (parts.length > 2 && (parts[0] === 'relay' || parts[0] === 'origin')) return parts.slice(1).join('.')
  return bare
}

/** Read a small JSON request body, bounded so the route can't buffer memory. */
function readJsonBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let body = ''
    let over = false
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString('utf8')
      if (body.length > 8192) { over = true; req.destroy() }
    })
    req.on('end', () => {
      if (over) return resolve(null)
      try { resolve(JSON.parse(body)) } catch { resolve(null) }
    })
    req.on('error', () => resolve(null))
  })
}

/**
 * Plugin entry. Starts the tunnel and registers the widget's control routes
 * under `/dshn/*` (our own routes, never the `/api` fence).
 * @param ctx - cordis context with the injected web server.
 * @param rawConfig - the composition-row infrastructure config.
 */
export function apply(ctx: any, rawConfig: Partial<AgentConfig> | undefined): void {
  const config = normalizeConfig(rawConfig)
  const localPort = () => (config.localPort !== 0 ? config.localPort : ctx.webServer.port)
  // Credentials live in dsh's settings.yaml (namespace `dshn`, passwords marked
  // secret). On first run it migrates a legacy JSON file into settings, then
  // deletes it. The migration sources are scoped to WHICH state path is in play:
  // a custom DSHN_STATE migrates only from its own file — it must never read or
  // delete the shared dsh-dir default or the old home-root file. Only the default
  // location inherits (and cleans up) those two legacy paths.
  // A file store is the fallback only if the settings service is somehow absent.
  let store: CredsStore
  try {
    const scope = ctx.settings.register('dshn', CREDS_SCHEMA)
    const migrate = config.statePath === DEFAULT_STATE_PATH
      ? [DEFAULT_STATE_PATH, LEGACY_STATE_PATH]
      : [config.statePath]
    store = settingsStore(scope, migrate)
  } catch {
    store = fileStore(config.statePath)
  }
  const tunnel = new AgentTunnel(config, localPort, store)
  const json = (res: http.ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    res.end(JSON.stringify(body))
  }

  // Status: the widget polls this. `configurable` tells the UI whether to offer
  // the setup form (only over loopback); the password is never echoed back.
  const disposeStatus = ctx.webServer.register({
    kind: 'exact',
    path: '/dshn/status',
    handler: (req: http.IncomingMessage, res: http.ServerResponse) => {
      const loopback = isLoopbackRequest(req)
      const info = tunnel.info()
      json(res, 200, {
        enabled: tunnel.status.enabled,
        configured: tunnel.status.configured,
        connected: tunnel.status.connected,
        publicUrl: tunnel.status.publicUrl,
        subdomain: tunnel.status.subdomain,
        lastError: tunnel.status.lastError,
        configurable: loopback,
        apex: publicApex(info.relayHost),
        // This machine's identity in the multi-device switcher.
        deviceId: tunnel.deviceId,
        deviceName: tunnel.deviceName,
        // The saved password is the only recoverable copy (cloud stores a hash).
        // Only ever handed to a loopback caller — the local machine's owner.
        password: loopback ? tunnel.revealPassword() : null,
        e2ePassword: loopback ? tunnel.revealE2EPassword() : null,
        e2eEnabled: tunnel.e2eInfo().enabled,
        // Self-hosted relay overrides, so the settings UI can pre-fill them
        // (loopback only). `defaultRelayHost` is what an empty override falls back
        // to, shown as the field's placeholder.
        relaySettings: loopback ? tunnel.relaySettings() : null,
        defaultRelayHost: config.relayHost,
        // Connection details for the panel.
        relayHost: info.relayHost,
        mode: info.direct ? 'direct' : 'cloudflare',
        // Which path the relay assigned: 'premium' (accelerated, via routeHost)
        // or 'standard'; null until a route-aware relay has said.
        route: info.route,
        routeHost: info.routeHost,
        connectedSince: info.connectedSince,
        served: info.served,
        localPort: info.localPort,
        latencyMs: info.latencyMs,
      })
    },
  })

  // Public E2E info, deliberately under a NON-blocked prefix so it is reachable
  // through the tunnel: it tells the browser whether content is encrypted and
  // hands it the (non-secret) salt to derive the key. Never returns the password.
  const disposeE2E = ctx.webServer.register({
    kind: 'exact',
    path: E2E_PUB_PATH,
    handler: (_req: http.IncomingMessage, res: http.ServerResponse) => {
      const e = tunnel.e2eInfo()
      // `device` lets the browser key its remembered e2e password per DEVICE,
      // not just per host — on a multi-device subdomain each machine has its own
      // e2e password, and one saved copy must not clobber another's.
      json(res, 200, { enabled: e.enabled, salt: e.enabled ? e.salt : null, device: tunnel.deviceId })
    },
  })

  // Configure: the setup dialog POSTs { subdomain, password } here (plus optional
  // { relayHost, originCa } for self-hosted relays). Loopback only — a public
  // caller must never set another machine's credentials or relay target.
  const disposeConfigure = ctx.webServer.register({
    kind: 'exact',
    path: '/dshn/configure',
    handler: async (req: http.IncomingMessage, res: http.ServerResponse) => {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST only' })
      if (!isLoopbackRequest(req)) return json(res, 403, { error: 'configuration is local-only' })
      const body = await readJsonBody(req)
      if (body === null || typeof body.subdomain !== 'string' || typeof body.password !== 'string') {
        return json(res, 400, { error: 'expected { subdomain, password }' })
      }
      const relayHost = typeof body.relayHost === 'string' ? body.relayHost : undefined
      const originCa = typeof body.originCa === 'string' ? body.originCa : undefined
      const err = tunnel.configure(body.subdomain, body.password, relayHost, originCa)
      if (err !== null) return json(res, 400, { error: err })
      json(res, 200, { ok: true, subdomain: tunnel.status.subdomain })
    },
  })

  // Set/change/clear the end-to-end password on its own — independent of the
  // main config, and without reconnecting the tunnel. Loopback only.
  const disposeSetE2E = ctx.webServer.register({
    kind: 'exact',
    path: '/dshn/e2e',
    handler: async (req: http.IncomingMessage, res: http.ServerResponse) => {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST only' })
      if (!isLoopbackRequest(req)) return json(res, 403, { error: 'local-only' })
      const body = await readJsonBody(req)
      if (body === null || (body.e2ePassword != null && typeof body.e2ePassword !== 'string')) {
        return json(res, 400, { error: 'expected { e2ePassword } (string, or null/empty to disable)' })
      }
      const err = tunnel.setE2E(typeof body.e2ePassword === 'string' ? body.e2ePassword : null)
      if (err !== null) return json(res, 400, { error: err })
      json(res, 200, { ok: true, enabled: tunnel.e2eInfo().enabled })
    },
  })

  // Disconnect: forget credentials and stop the tunnel. Loopback only.
  const disposeDisconnect = ctx.webServer.register({
    kind: 'exact',
    path: '/dshn/disconnect',
    handler: (req: http.IncomingMessage, res: http.ServerResponse) => {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST only' })
      if (!isLoopbackRequest(req)) return json(res, 403, { error: 'local-only' })
      tunnel.disconnect()
      json(res, 200, { ok: true })
    },
  })

  tunnel.start()
  ctx.on('dispose', () => {
    disposeStatus()
    disposeE2E()
    disposeConfigure()
    disposeSetE2E()
    disposeDisconnect()
    tunnel.stop()
  })
}
