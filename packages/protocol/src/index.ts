/**
 * @dshn/protocol — the wire contract shared by the local agent (a dsh plugin)
 * and the relay (the server behind Cloudflare). Both ends compile against this
 * package, so a change to a frame shape is a compile error on the side that
 * hasn't caught up — the whole reason the two live in one monorepo.
 *
 * One WebSocket carries everything between an agent and the relay. Over it we
 * multiplex three things by stream id: ordinary HTTP request/response pairs
 * replayed against the local dsh, WebSocket upgrades tunnelled to dsh's own
 * downlink sockets (`/api/events.mux`, `/api/events.host`), and heartbeats.
 *
 * Framing splits by WebSocket message type, which is lossless and needs no
 * length prefixes: TEXT messages are JSON {@link ControlFrame}s (heads, ends,
 * lifecycle), BINARY messages are {@link DataFrame}s (a 5-byte header + raw
 * body/message bytes, so a streamed tool result never pays base64 tax).
 *
 * The relay is the only side that opens streams (every stream originates from a
 * public request it received), so it is the sole allocator of stream ids and
 * the agent never invents one. That removes any id-collision handshake.
 */

/** Bumped when a frame shape changes incompatibly; the agent sends it in {@link HelloFrame}. */
export const DSHN_PROTOCOL_VERSION = 1

/**
 * Application heartbeat period. Cloudflare closes a proxied WebSocket after
 * ~100s with no data in either direction; a 25s ping keeps both the agent's
 * control socket and any tunnelled browser socket comfortably under that.
 */
export const HEARTBEAT_INTERVAL_MS = 25_000

/** A peer silent for this long is treated as dead and its socket is dropped. */
export const HEARTBEAT_TIMEOUT_MS = 70_000

/** Relay path the agent's control WebSocket dials (behind the CF-proxied relay host). */
export const AGENT_WS_PATH = '/dshn-agent'

// ── optional end-to-end encryption ──────────────────────────────────────────
// When the user sets a SEPARATE e2e password (never sent to the relay), the
// agent encrypts the sensitive tunnel payloads — /api request/response bodies
// and the downlink event-socket messages — with a key derived from it. The
// browser derives the same key from the password the visitor types, so the
// relay only ever moves ciphertext for those. Both ends must agree on the
// format below; the KDF/AEAD themselves are platform-specific (node crypto vs
// Web Crypto) but produce interoperable output.

/** PBKDF2-SHA256 iterations deriving the AES key from the e2e password. */
export const E2E_PBKDF2_ITERS = 210_000
/** Salt length (bytes). Not secret — served plaintext so the browser can derive the same key. */
export const E2E_SALT_BYTES = 16
/** AES-GCM IV length (bytes); a fresh random IV prefixes every ciphertext. */
export const E2E_IV_BYTES = 12
/** AES-GCM tag length (bytes), appended by the AEAD. */
export const E2E_TAG_BYTES = 16
/** HTTP header marking a request/response body as an e2e envelope. */
export const E2E_HEADER = 'x-dshn-e2e'
/** Plaintext, forwarded (not under the blocked /dshn/) route exposing `{enabled, salt}`. */
export const E2E_PUB_PATH = '/dshn-e2e'
/** First byte of a decrypted event-socket envelope: was the original message text or binary. */
export const E2E_MSG_TEXT = 0
export const E2E_MSG_BINARY = 1

// ── binary data-frame kinds ────────────────────────────────────────────────
// Plain numeric consts rather than a TS enum: `isolatedModules` forbids const
// enums, and a value union keeps the codec dependency-free.

/** Bytes of an HTTP request body, relay → agent. */
export const DATA_REQ_BODY = 1
/** Bytes of an HTTP response body, agent → relay. */
export const DATA_RES_BODY = 2
/** A tunnelled WebSocket text message, either direction. */
export const DATA_WS_TEXT = 3
/** A tunnelled WebSocket binary message, either direction. */
export const DATA_WS_BINARY = 4

/** The four binary payload kinds. */
export type DataKind = 1 | 2 | 3 | 4

/** Fixed binary-frame header: one kind byte plus a uint32 stream id. */
export const DATA_HEADER_BYTES = 5

// ── HTTP header lists ──────────────────────────────────────────────────────
// A tuple list, not a map: `set-cookie` legitimately repeats (dsh sets session
// cookies, and the relay sets its own auth cookie), and collapsing duplicates
// into one key would corrupt exactly the headers this product depends on.

/** Ordered `[name, value]` pairs, preserving duplicates such as `set-cookie`. */
export type HeaderList = Array<[string, string]>

// ── control frames (JSON over TEXT messages) ───────────────────────────────

/**
 * Agent → relay, first frame on a fresh control socket: claim (or re-claim) a
 * subdomain with a password. The credential is the (subdomain, password) pair
 * the user typed — no pre-provisioned tokens. First claim of a free subdomain
 * sets its password; later connects must present the same one. That password is
 * also what a browser types to open the public URL.
 */
export interface HelloFrame {
  t: 'hello'
  /** The flat subdomain label the user chose, e.g. `alice`. */
  subdomain: string
  /** The password guarding this subdomain (claim secret + browser access). */
  password: string
  /** Agent build string, for the relay's logs. */
  agent: string
  /** {@link DSHN_PROTOCOL_VERSION} the agent speaks. */
  protocol: number
  /**
   * Stable per-install device id (multi-device). Several agents may hold the
   * SAME subdomain concurrently as long as their device ids differ; a repeat
   * of an id supersedes that device's previous connection. Absent on legacy
   * agents, which the relay treats as one shared id — preserving the old
   * one-agent-per-subdomain behavior for them.
   */
  deviceId?: string
  /** Human-readable device name for the relay's device switcher (e.g. the hostname). */
  device?: string
}

/** Relay → agent: the token was accepted; the tunnel is live. */
export interface ReadyFrame {
  t: 'ready'
  /** The subdomain label (e.g. `alice` for `alice.ds.hn`). */
  subdomain: string
  /** The full public URL the browser uses. */
  publicUrl: string
}

/** Relay → agent: the token was rejected; the agent should stop, not retry blindly. */
export interface DenyFrame {
  t: 'deny'
  reason: string
}

/** Relay → agent: an HTTP request arrived; body (if any) follows as {@link DATA_REQ_BODY} frames. */
export interface ReqHeadFrame {
  t: 'req_head'
  id: number
  method: string
  /** Path with query string, as received from the browser. */
  path: string
  headers: HeaderList
}

/** Relay → agent: the request body is complete (or there was none). */
export interface ReqEndFrame {
  t: 'req_end'
  id: number
}

/** Agent → relay: the local dsh answered; body follows as {@link DATA_RES_BODY} frames. */
export interface ResHeadFrame {
  t: 'res_head'
  id: number
  status: number
  headers: HeaderList
}

/** Agent → relay: the response body is complete. */
export interface ResEndFrame {
  t: 'res_end'
  id: number
}

/** Either direction: abandon this stream (client hung up, local dsh errored, timeout). */
export interface AbortFrame {
  t: 'abort'
  id: number
  reason?: string
}

/** Relay → agent: a browser opened a WebSocket; open the matching one against local dsh. */
export interface WsOpenFrame {
  t: 'ws_open'
  id: number
  /** Path with query string of the upgrade request. */
  path: string
  headers: HeaderList
}

/** Agent → relay: the local dsh accepted the upgrade; messages may flow. */
export interface WsReadyFrame {
  t: 'ws_ready'
  id: number
}

/** Agent → relay: the local dsh refused the upgrade; the relay fails the browser handshake. */
export interface WsRejectFrame {
  t: 'ws_reject'
  id: number
  /** HTTP status to hand the browser (e.g. 403 when dsh's trust fence rejected it). */
  status: number
}

/** Either direction: this tunnelled WebSocket closed. */
export interface WsCloseFrame {
  t: 'ws_close'
  id: number
  code: number
  reason: string
}

/** Either direction: liveness ping. */
export interface PingFrame {
  t: 'ping'
}

/** Either direction: liveness pong. */
export interface PongFrame {
  t: 'pong'
}

/** Every JSON control frame. */
export type ControlFrame =
  | HelloFrame
  | ReadyFrame
  | DenyFrame
  | ReqHeadFrame
  | ReqEndFrame
  | ResHeadFrame
  | ResEndFrame
  | AbortFrame
  | WsOpenFrame
  | WsReadyFrame
  | WsRejectFrame
  | WsCloseFrame
  | PingFrame
  | PongFrame

/** A decoded binary data frame. */
export interface DataFrame {
  kind: DataKind
  id: number
  payload: Uint8Array
}

// ── codec ──────────────────────────────────────────────────────────────────

/**
 * Serialize a control frame for a TEXT WebSocket message.
 * @param frame - the control frame.
 * @returns its JSON string.
 */
export function encodeControl(frame: ControlFrame): string {
  return JSON.stringify(frame)
}

/**
 * Parse a TEXT WebSocket message into a control frame. The caller is trusted
 * (the peer is past the token handshake), so this does not re-validate shape
 * beyond the JSON parse; a malformed frame throws and drops the socket.
 * @param text - the received TEXT payload.
 * @returns the control frame.
 */
export function decodeControl(text: string): ControlFrame {
  return JSON.parse(text) as ControlFrame
}

/**
 * Frame a binary payload as `[kind][uint32 id][payload]`.
 * @param kind - one of the {@link DataKind} values.
 * @param id - the stream id the payload belongs to.
 * @param payload - the raw bytes (body chunk or WS message).
 * @returns the encoded binary frame.
 */
export function encodeData(kind: DataKind, id: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(DATA_HEADER_BYTES + payload.length)
  const view = new DataView(out.buffer)
  out[0] = kind
  view.setUint32(1, id >>> 0, false)
  out.set(payload, DATA_HEADER_BYTES)
  return out
}

/**
 * Decode a binary WebSocket message into its data frame. The payload is a
 * subarray view over the same backing buffer — copy it if it must outlive the
 * message handler.
 * @param buf - the received binary payload.
 * @returns the decoded data frame.
 */
export function decodeData(buf: Uint8Array): DataFrame {
  if (buf.length < DATA_HEADER_BYTES) throw new Error('dshn: binary frame shorter than its header')
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  return {
    kind: buf[0] as DataKind,
    id: view.getUint32(1, false),
    payload: buf.subarray(DATA_HEADER_BYTES),
  }
}

// ── WebSocket close sanitization ────────────────────────────────────────────
// A close code/reason travels across the tunnel and is eventually replayed into
// a `ws` `.close(code, reason)` call on the far side. `ws` throws — synchronously,
// inside an event handler, crashing the process — if the code is not a valid
// *sendable* status code, or if the reason exceeds 123 UTF-8 bytes. A browser or
// server routinely closes with 1005/1006 (reserved: observed, never sent), so
// forwarding those verbatim is a guaranteed crash. Both ends sanitize before
// calling `.close()`.

/** Longest close reason `ws` will accept (RFC 6455 control-frame payload minus 2). */
const MAX_CLOSE_REASON_BYTES = 123

/**
 * Map any close code to one that is valid to *send*. Sendable codes are
 * 1000–1014 except the reserved 1004/1005/1006, plus the 3000–4999 app range;
 * everything else (including 1006 "abnormal", 1015 "TLS", 0) becomes 1000.
 * @param code - the received close code.
 * @returns a code safe to pass to `WebSocket.close`.
 */
export function sanitizeCloseCode(code: number): number {
  if ((code >= 1000 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006) || (code >= 3000 && code <= 4999)) {
    return code
  }
  return 1000
}

/**
 * Truncate a close reason to `ws`'s 123-byte limit, on a UTF-8 char boundary so
 * the trimmed value stays valid text.
 * @param reason - the received reason.
 * @returns a reason safe to pass to `WebSocket.close`.
 */
export function sanitizeCloseReason(reason: string): string {
  let out = reason
  while (Buffer.byteLength(out, 'utf8') > MAX_CLOSE_REASON_BYTES) out = out.slice(0, -1)
  return out
}

// ── subdomain helpers ──────────────────────────────────────────────────────

/**
 * The subdomain label for a request Host, or null when the Host is not a
 * single label under the tunnel apex. Ports are stripped; comparison is
 * case-insensitive. Used by the relay to route and by the agent to sanity-check
 * the Host it forwards.
 * @param host - a request `Host` header value (may include a port).
 * @param apex - the tunnel apex, e.g. `ds.hn`.
 * @returns the label (e.g. `alice`) or null.
 */
export function subdomainOf(host: string, apex: string): string | null {
  const bare = host.toLowerCase().split(':', 1)[0].replace(/\.$/, '')
  const suffix = '.' + apex.toLowerCase().replace(/\.$/, '')
  if (!bare.endsWith(suffix)) return null
  const label = bare.slice(0, -suffix.length)
  // One flat label only: Universal SSL covers `*.ds.hn` a single level deep.
  if (label === '' || label.includes('.')) return null
  return label
}

/** Subdomain labels reserved for infrastructure — never claimable by a user. */
export const RESERVED_SUBDOMAINS = new Set([
  'origin', 'relay', 'www', 'api', 'admin', 'ns', 'mail', 'ds', 'app', 'cdn',
])

/** Minimum claimable subdomain length. Short labels are scarce and squat-prone. */
export const MIN_SUBDOMAIN_LEN = 4

/**
 * Whether a user-chosen subdomain label is claimable: a single DNS label, 4–32
 * chars of lowercase alphanumerics and hyphens, not hyphen-bounded, and not
 * reserved for infrastructure. Universal SSL only covers one label deep, so
 * anything with a dot is rejected here too.
 * @param label - the candidate label (already lowercased by the caller, ideally).
 * @returns true when the label may be claimed.
 */
export function isValidSubdomainLabel(label: string): boolean {
  // 4–32 chars: first/last alphanumeric, hyphens allowed only in between.
  if (!/^[a-z0-9][a-z0-9-]{2,30}[a-z0-9]$/.test(label)) return false
  return !RESERVED_SUBDOMAINS.has(label)
}
