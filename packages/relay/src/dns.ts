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

/** Comment stamped on records the relay creates, so an operator can tell them apart. */
const RECORD_COMMENT = 'dshn premium route (managed by the relay)'

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

  async point(name: string, ip: string): Promise<DnsRecordRef> {
    const existing = await this.findA(name)
    const ours = existing.find((r) => r.content === ip)
    if (ours !== undefined && !ours.proxied) return { id: ours.id, content: ours.content }
    // Reuse a record of ours (same target, or stamped with our comment from an
    // earlier accelerator address) rather than leaving two answers. Any OTHER A
    // record of that exact name belongs to the operator: adding ours beside it
    // would round-robin the name between two targets, and rewriting it would
    // destroy something the relay did not create — so refuse and say why.
    const reuse = ours ?? existing.find((r) => r.comment === RECORD_COMMENT)
    if (reuse === undefined && existing.length > 0) {
      const targets = existing.map((r) => r.content).join(', ')
      throw new Error(`"${name}" already has an A record (${targets}) not managed by the relay; remove it first`)
    }
    const payload = { type: 'A', name, content: ip, proxied: false, ttl: PREMIUM_TTL_S, comment: RECORD_COMMENT }
    const rec = reuse === undefined
      ? await this.call<CfRecord>('POST', '', payload)
      : await this.call<CfRecord>('PATCH', `/${reuse.id}`, payload)
    return { id: rec.id, content: rec.content }
  }

  async unpoint(name: string, id: string | undefined, ip: string): Promise<void> {
    if (id !== undefined) {
      try {
        await this.call<unknown>('DELETE', `/${id}`)
        return
      } catch (err) {
        // Already gone (deleted by hand) → fall through to the name lookup, which
        // is also a no-op then. Any other failure is reported.
        if (!/\b(81044|404|not found)\b/i.test((err as Error).message)) throw err
      }
    }
    for (const rec of await this.findA(name)) {
      if (rec.content === ip) await this.call<unknown>('DELETE', `/${rec.id}`)
    }
  }
}
