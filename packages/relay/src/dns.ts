/**
 * DNS control for the premium route. Enabling the route for a subdomain means
 * pointing that ONE hostname at the accelerator node with a dedicated,
 * un-proxied record that shadows the CDN'd wildcard; disabling removes it so
 * the wildcard takes over again. The relay only ever touches records it
 * created for this purpose (matched by name, type A, and either the
 * accelerator IP or the comment it stamps on them); a same-name record of the
 * operator's makes enabling fail with a message instead.
 *
 * The provider is an interface so the relay can run with no DNS credentials at
 * all (the operator then sets the record by hand — the admin panel tells them
 * what to add) and so tests can drive it with a fake.
 */

/** The record the relay manages for one premium subdomain. */
export interface DnsRecordRef {
  id: string
  content: string
}

/** DNS operations the premium route needs. */
export interface PremiumDns {
  /**
   * Ensure `name` is an un-proxied A record pointing at `ip`, creating or
   * updating as needed.
   * @returns the record the relay should remember.
   */
  point(name: string, ip: string): Promise<DnsRecordRef>
  /**
   * Remove the record for `name`: by id when known, else every A record of that
   * name pointing at `ip`. Resolves normally when nothing is there anymore.
   */
  unpoint(name: string, id: string | undefined, ip: string): Promise<void>
}

/** TTL for the dedicated record: short, so a route change propagates quickly. */
const PREMIUM_TTL_S = 120

/** Comment stamped on records the relay creates — the ownership mark it later trusts. */
export const RECORD_COMMENT = 'dshn premium route (managed by the relay)'

/** Cloudflare API call budget. */
const CF_TIMEOUT_MS = 15_000

interface CfEnvelope<T> {
  success: boolean
  errors?: Array<{ code?: number; message?: string }>
  result?: T
}

interface CfRecord {
  id: string
  type: string
  name: string
  content: string
  proxied: boolean
  comment?: string | null
}

/** Cloudflare DNS, through a zone-scoped API token (Zone → DNS → Edit). */
export class CloudflareDns implements PremiumDns {
  constructor(
    private readonly token: string,
    private readonly zoneId: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetchImpl(`https://api.cloudflare.com/client/v4/zones/${this.zoneId}/dns_records${path}`, {
      method,
      headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      // A hung API call must not hold an admin request (and the per-subdomain
      // DNS queue behind it) open forever.
      signal: AbortSignal.timeout(CF_TIMEOUT_MS),
    })
    let env: CfEnvelope<T>
    try {
      env = (await res.json()) as CfEnvelope<T>
    } catch {
      throw new Error(`Cloudflare API ${method} ${path}: HTTP ${res.status}`)
    }
    if (!env.success) {
      const why = (env.errors ?? []).map((e) => `${e.code ?? ''} ${e.message ?? ''}`.trim()).join('; ') || `HTTP ${res.status}`
      throw new Error(`Cloudflare API ${method} ${path}: ${why}`)
    }
    return env.result as T
  }

  private async findA(name: string): Promise<CfRecord[]> {
    return this.call<CfRecord[]>('GET', `?type=A&name=${encodeURIComponent(name)}&per_page=50`)
  }

  /** Whether a record is one of ours: the comment the relay stamps is the ownership mark. */
  private owned(rec: CfRecord, name: string): boolean {
    return rec.type === 'A' && rec.name === name && rec.comment === RECORD_COMMENT
  }

  async point(name: string, ip: string): Promise<DnsRecordRef> {
    const existing = await this.findA(name)
    // Ownership is the comment, never the target: a record the operator set by
    // hand that happens to point at the accelerator is still theirs. Ours is
    // reused (retargeted or un-proxied as needed) so the name never has two
    // answers; anything else of that exact name makes enabling fail with a
    // message, because adding beside it would round-robin the name and
    // rewriting it would destroy something the relay did not create.
    const ours = existing.find((r) => this.owned(r, name))
    const foreign = existing.filter((r) => !this.owned(r, name))
    if (foreign.length > 0) {
      const targets = foreign.map((r) => r.content).join(', ')
      throw new Error(`"${name}" already has an A record (${targets}) not managed by the relay; remove it (or stamp it with the comment "${RECORD_COMMENT}" to adopt it) first`)
    }
    if (ours !== undefined && ours.content === ip && !ours.proxied) return { id: ours.id, content: ours.content }
    const payload = { type: 'A', name, content: ip, proxied: false, ttl: PREMIUM_TTL_S, comment: RECORD_COMMENT }
    const rec = ours === undefined
      ? await this.call<CfRecord>('POST', '', payload)
      : await this.call<CfRecord>('PATCH', `/${ours.id}`, payload)
    return { id: rec.id, content: rec.content }
  }

  async unpoint(name: string, id: string | undefined, _ip: string): Promise<void> {
    if (id !== undefined) {
      // Re-read the record before deleting by id: an id remembered from an
      // earlier life of the name may now belong to a record the operator made.
      let rec: CfRecord | null = null
      try {
        rec = await this.call<CfRecord>('GET', `/${id}`)
      } catch (err) {
        if (!/\b(81044|404|not found)\b/i.test((err as Error).message)) throw err
      }
      if (rec !== null) {
        if (!this.owned(rec, name)) throw new Error(`DNS record ${id} is not the relay's record for "${name}" (${rec.name} → ${rec.content}); not deleting it`)
        await this.call<unknown>('DELETE', `/${id}`)
        return
      }
      // Gone already (deleted by hand) → sweep by name below, a no-op then.
    }
    for (const rec of await this.findA(name)) {
      if (this.owned(rec, name)) await this.call<unknown>('DELETE', `/${rec.id}`)
    }
  }
}
