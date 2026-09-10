/**
 * Gzip for the tunnel hop.
 *
 * The agent→relay WebSocket is the slow, expensive link in the whole path: a
 * home uplink, often an order of magnitude narrower than the relay's downlink to
 * the visitor. Everything the tunnel carries crosses it once, uncompressed —
 * dsh's own web server compresses nothing by default (`compression: 'none'`),
 * and a cold app load is ~1.3 MB of JavaScript and CSS.
 *
 * So the agent compresses on the way out instead of forwarding plaintext and
 * letting the edge compress a hop too late. gzip level 1 takes that same cold
 * load to ~440 KB (3×) for a few milliseconds of CPU per response, and the
 * browser unpacks it natively — `content-encoding` rides through the relay
 * verbatim, so nothing downstream needs to know.
 *
 * Deliberately NOT compressed: anything dsh already encoded, bodies with a
 * `content-range`, `text/event-stream` (a stream whose point is prompt
 * delivery), responses with no body, types that are already compressed (images,
 * fonts, archives), and end-to-end-sealed payloads (ciphertext does not
 * compress, and the browser shim would have to unpack it).
 */
import { createGzip, gzipSync, type Gzip } from 'node:zlib'

/**
 * Level 1. The tunnel wants bytes off the uplink NOW: level 1 reaches ~3× on
 * dsh's bundles, and level 9 buys another ~12% for several times the CPU, which
 * on a machine also running an agent loop is the wrong trade.
 */
const GZIP_LEVEL = 1
/** Below this known length, the gzip framing and the round of CPU are not worth it. */
const MIN_BYTES = 1024

/**
 * Content types worth compressing: text and the structured text families. An
 * unknown or absent type is NOT compressed — dsh labels everything it serves, so
 * a missing type means an opaque body rather than an opportunity.
 */
function isCompressibleType(contentType: string): boolean {
  const type = contentType.split(';', 1)[0].trim().toLowerCase()
  if (type === '') return false
  if (type === 'text/event-stream') return false // a live stream; latency beats size
  if (type.startsWith('text/')) return true
  if (type === 'image/svg+xml') return true
  if (type === 'application/json' || type === 'application/javascript' || type === 'application/xml') return true
  if (type === 'application/manifest+json' || type === 'application/wasm') return true
  return type.startsWith('application/') && (type.endsWith('+json') || type.endsWith('+xml'))
}

/** Whether a visitor's `accept-encoding` actually offers gzip (and has not forbidden it). */
export function acceptsGzip(acceptEncoding: string | undefined): boolean {
  if (acceptEncoding === undefined) return false
  for (const part of acceptEncoding.split(',')) {
    const [name, ...params] = part.split(';').map((s) => s.trim().toLowerCase())
    if (name !== 'gzip' && name !== '*') continue
    // `gzip;q=0` is an explicit refusal.
    const q = params.find((p) => p.startsWith('q='))
    if (q !== undefined && Number.parseFloat(q.slice(2)) === 0) continue
    return true
  }
  return false
}

/** What the decision needs to know about one response from local dsh. */
export interface ResponseFacts {
  status: number
  /** Lowercased header lookup over the response dsh produced. */
  header: (name: string) => string | undefined
}

/**
 * Whether this response should be gzipped before it goes into the tunnel.
 * @param facts - the response as local dsh produced it.
 * @param method - the replayed request's method (HEAD carries no body).
 * @param acceptEncoding - the visitor's `accept-encoding`.
 * @returns true when compressing is both safe and worthwhile.
 */
export function shouldGzip(facts: ResponseFacts, method: string, acceptEncoding: string | undefined): boolean {
  if (method === 'HEAD') return false
  // 204/304 carry no body; 1xx never reach here. A 206 is a byte range whose
  // offsets describe the identity bytes.
  if (facts.status === 204 || facts.status === 304 || facts.status === 206) return false
  if (facts.header('content-range') !== undefined) return false
  // Already encoded by dsh (its own gzip is on): leave it exactly as it is.
  const encoded = facts.header('content-encoding')
  if (encoded !== undefined && encoded.trim() !== '' && encoded.trim().toLowerCase() !== 'identity') return false
  if (!acceptsGzip(acceptEncoding)) return false
  if (!isCompressibleType(facts.header('content-type') ?? '')) return false
  const length = Number(facts.header('content-length'))
  // A known-small body is not worth it; an unknown length (streamed) is.
  return !(Number.isFinite(length) && length < MIN_BYTES)
}

/** A gzip stream configured for the tunnel's trade-off (speed over ratio). */
export function tunnelGzip(): Gzip {
  return createGzip({ level: GZIP_LEVEL })
}

/**
 * Compress a body the agent already holds whole — the rewritten app shell. The
 * caller knows it is HTML, so only the visitor's offer and the size are in
 * question.
 * @param body - the complete body.
 * @param acceptEncoding - the visitor's `accept-encoding`.
 * @returns the gzipped body, or null to send it as-is.
 */
export function gzipBody(body: Buffer, acceptEncoding: string | undefined): Buffer | null {
  if (!acceptsGzip(acceptEncoding) || body.length < MIN_BYTES) return null
  return gzipSync(body, { level: GZIP_LEVEL })
}

/**
 * Headers that stop describing the body once it is compressed, plus the ones we
 * replace. `content-length` goes because the compressed length is not yet known
 * (the body streams out); the validators stay valid — the resource is the same,
 * only its transfer encoding changed — but `vary` must record that the bytes
 * depend on `accept-encoding`.
 */
export const GZIP_DROP_HEADERS: readonly string[] = ['content-length']
