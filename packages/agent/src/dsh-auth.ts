/**
 * Browser-session authentication for the traffic the agent replays to local dsh.
 *
 * dsh ≥ 0.1.2-rc.1 puts a signed, authority-bound cookie in front of the app
 * shell AND every `/api` request — the plain HTTP ones and the
 * `/api/remote.mux` upgrade alike. A browser earns that cookie by opening the
 * launch URL dsh prints (`http://127.0.0.1:PORT/?token=…`), which 303s back a
 * `Set-Cookie: dsh-auth-<base64url(sha256(authority))>=v1.…` bound to the
 * authority it was minted for.
 *
 * A public visitor arriving through the tunnel can never hold it: their browser
 * keeps cookies for the PUBLIC authority, while every replay's Host is
 * rewritten to loopback — and the cookie is checked against the Host it arrives
 * on. Without the stamp below, dsh answers the whole app with
 * `401 dsh web authentication required` and the tunnel faithfully forwards a
 * dead page.
 *
 * The agent runs inside the dsh process, so it can ask dsh's own `connection`
 * service for this process's launch token, spend it over loopback once, and
 * stamp the resulting cookie onto every replay. The cookie never leaves this
 * machine: neither the relay nor the visitor's browser ever sees it, and access
 * stays gated by the relay's login exactly as before.
 *
 * On a dsh that predates the fence (no `connection` service, or one without
 * `authenticatedUrl`) every method here is inert and the agent behaves as it
 * always did.
 */
import http from 'node:http'

/** Cookie-name prefix dsh mints its browser-session cookie under. */
export const DSH_AUTH_COOKIE_PREFIX = 'dsh-auth-'

/** How long before the cookie's own expiry we mint a fresh one. */
const RENEW_BEFORE_MS = 24 * 60 * 60_000
/** Attempts per exchange before giving up and letting requests through unstamped. */
const EXCHANGE_TRIES = 5
/** Delay between those attempts (dsh may still be settling at plugin-apply time). */
const EXCHANGE_RETRY_MS = 500
/** Ceiling on the loopback exchange, so a wedged dsh cannot park requests forever. */
const EXCHANGE_TIMEOUT_MS = 5_000

/** The sliver of dsh's `connection` service this needs; absent on a pre-fence dsh. */
export interface DshConnection {
  /** Returns the app URL carrying this process's launch token as its query. */
  authenticatedUrl?: (baseUrl: string) => string
}

/** What the authenticator reads from its host, late-bound so the port can settle first. */
export interface DshAuthDeps {
  /** dsh's `connection` service, or undefined on a dsh that has none. */
  connection: () => DshConnection | undefined
  /** The loopback authority replays are addressed to, e.g. `127.0.0.1:3000`. */
  authority: () => string
  /** Host to dial for the exchange (the same loopback interface replays use). */
  host: () => string
  /** Port to dial for the exchange. */
  port: () => number
}

/**
 * Strip every `dsh-auth-*` pair from a visitor's `Cookie` header. A remote
 * visitor's own cookies are for the public authority and mean nothing to the
 * loopback replay; dropping them also stops a crafted one from shadowing ours
 * (`cookieValue` returns the FIRST match, so a visitor-supplied pair placed
 * ahead of ours would otherwise decide the check).
 * @param header - the incoming cookie header, if any.
 * @returns the remaining pairs as a cookie header, or undefined when none are left.
 */
function withoutDshAuth(header: string | undefined): string | undefined {
  if (header === undefined || header === '') return undefined
  const kept = header
    .split(';')
    .map((pair) => pair.trim())
    .filter((pair) => pair !== '' && !pair.toLowerCase().startsWith(DSH_AUTH_COOKIE_PREFIX))
  return kept.length > 0 ? kept.join('; ') : undefined
}

/**
 * Read the expiry out of a `v1.<base64url(json)>.<sig>` cookie value. Purely so
 * a long-lived process can renew before the cookie lapses — the signature is
 * dsh's to verify, and an unreadable payload simply means "no known expiry".
 * @param value - the cookie value.
 * @returns the expiry in ms epoch, or 0 when it cannot be read.
 */
function expiryOf(value: string): number {
  const body = value.split('.')[1]
  if (body === undefined) return 0
  try {
    const json = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as { expiresAt?: unknown }
    return typeof json.expiresAt === 'number' ? json.expiresAt : 0
  } catch {
    return 0
  }
}

/** Pick dsh's browser-session cookie out of a `Set-Cookie` list, as a `name=value` pair. */
function sessionPairFrom(setCookie: string[] | undefined): string | null {
  for (const line of setCookie ?? []) {
    if (!line.toLowerCase().startsWith(DSH_AUTH_COOKIE_PREFIX)) continue
    const pair = line.split(';', 1)[0].trim()
    if (pair.includes('=')) return pair
  }
  return null
}

/**
 * Holds (and renews) the one dsh browser-session cookie the agent stamps on
 * every replayed request and tunnelled upgrade.
 */
export class DshAuth {
  /** The live `name=value` pair, or null when unavailable (pre-fence dsh, or the exchange failed). */
  private pair: string | null = null
  /** Expiry of {@link pair} in ms epoch; 0 when unknown. */
  private expiresAt = 0
  /** The in-flight exchange, so concurrent callers share one round trip. */
  private inflight: Promise<void> | null = null
  /**
   * Whether this dsh has no fence to satisfy (no `connection` service, or one
   * without `authenticatedUrl`). Then there is nothing to wait for and nothing
   * to stamp, and the agent behaves exactly as it did before the fence existed.
   */
  private inert = false

  constructor(private readonly deps: DshAuthDeps) {}

  /** Whether a replay can go out now: we hold a cookie, or none is needed. */
  ready(): boolean {
    return this.inert || this.pair !== null
  }

  /**
   * Resolves once a replay can go out. A failed exchange still resolves — a
   * visible 401 beats a request parked forever — and the next caller tries
   * again, so a dsh that was simply slow to listen recovers on its own.
   */
  async whenReady(): Promise<void> {
    if (this.ready()) return
    await this.refresh()
  }

  /**
   * Stamp dsh's session cookie onto a replayed request's `Cookie` header,
   * replacing any `dsh-auth-*` the visitor sent. Also renews opportunistically:
   * a cookie near its expiry kicks a background exchange while the current one
   * is still stamped, so a month-old dsh process never serves a 401.
   * @param cookieHeader - the visitor's cookie header, if any.
   * @returns the header to replay with, or undefined when there is none to send.
   */
  stamp(cookieHeader: string | undefined): string | undefined {
    const visitor = withoutDshAuth(cookieHeader)
    const pair = this.pair
    if (pair === null) return visitor
    if (this.expiresAt !== 0 && Date.now() > this.expiresAt - RENEW_BEFORE_MS) void this.refresh()
    return visitor === undefined ? pair : `${visitor}; ${pair}`
  }

  /**
   * Drop the cached cookie and mint a fresh one. Called when local dsh rejects a
   * replay as unauthenticated, which means the cookie went stale under us (a
   * rotated signing secret, or an expiry we could not read).
   */
  invalidate(): void {
    this.pair = null
    this.expiresAt = 0
    void this.refresh()
  }

  /**
   * Run (or join) one token-for-cookie exchange against local dsh.
   * @returns a promise settling when the exchange has finished, either way.
   */
  refresh(): Promise<void> {
    if (this.inflight !== null) return this.inflight
    const run = this.exchange()
      .catch(() => { /* a failed exchange leaves `pair` null; requests go unstamped and visibly 401 */ })
      .finally(() => {
        this.inflight = null
      })
    this.inflight = run
    return run
  }

  /** Spend this process's launch token for a session cookie, with bounded retries. */
  private async exchange(): Promise<void> {
    const connection = this.deps.connection()
    const mint = connection?.authenticatedUrl
    // A dsh without the fence has nothing to authenticate against: stay inert.
    if (typeof mint !== 'function') {
      this.inert = true
      return
    }
    this.inert = false
    for (let attempt = 0; attempt < EXCHANGE_TRIES; attempt++) {
      const authority = this.deps.authority()
      let query: string
      try {
        const launch = new URL(mint.call(connection, `http://${authority}`))
        query = `${launch.pathname}${launch.search}`
      } catch {
        return // the service handed us something unparseable; nothing to spend
      }
      const pair = await this.spend(query, authority)
      if (pair !== null) {
        this.pair = pair
        this.expiresAt = expiryOf(pair.slice(pair.indexOf('=') + 1))
        return
      }
      if (attempt + 1 < EXCHANGE_TRIES) await new Promise((done) => setTimeout(done, EXCHANGE_RETRY_MS))
    }
  }

  /**
   * One loopback GET of the launch URL, read for its `Set-Cookie`.
   * @param query - path plus token query to request.
   * @param authority - Host header to present, the authority the cookie binds to.
   * @returns the `name=value` pair, or null when this attempt did not yield one.
   */
  private spend(query: string, authority: string): Promise<string | null> {
    return new Promise((resolve) => {
      let done = false
      const finish = (pair: string | null): void => {
        if (done) return
        done = true
        resolve(pair)
      }
      const req = http.request(
        {
          host: this.deps.host(),
          port: this.deps.port(),
          method: 'GET',
          path: query,
          // The cookie is minted for the Host it is requested on; present the
          // very authority the replays will carry.
          headers: { host: authority, accept: 'text/html' },
          timeout: EXCHANGE_TIMEOUT_MS,
        },
        (res) => {
          const pair = sessionPairFrom(res.headers['set-cookie'])
          res.resume() // drain the 303 body so the socket is reusable
          finish(pair)
        },
      )
      req.on('timeout', () => { req.destroy(); finish(null) })
      req.on('error', () => finish(null))
      req.end()
    })
  }
}
