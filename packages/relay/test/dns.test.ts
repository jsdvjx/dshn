/**
 * CloudflareDns against a fake Cloudflare API: the relay only ever creates,
 * reuses, or deletes records of its own (matched by target or by the comment it
 * stamps), and refuses to add beside or rewrite an operator's record.
 */
import { describe, expect, it } from 'vitest'
import { CloudflareDns } from '../src/dns.js'

interface Rec { id: string; type: string; name: string; content: string; proxied: boolean; ttl?: number; comment?: string }

/** A fake of the zone's dns_records endpoint, seeded with records. */
function fakeCloudflare(seed: Rec[]): { dns: CloudflareDns; records: Rec[]; calls: string[] } {
  const records = [...seed]
  const calls: string[] = []
  let seq = 100
  const ok = (result: unknown): Response => new Response(JSON.stringify({ success: true, result }), { status: 200 })
  const fail = (code: number, message: string, status = 400): Response =>
    new Response(JSON.stringify({ success: false, errors: [{ code, message }] }), { status })
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input))
    const method = init?.method ?? 'GET'
    const tail = url.pathname.replace(/^.*\/dns_records/, '')
    calls.push(`${method} ${tail}${url.search}`)
    if (method === 'GET') {
      if (tail.startsWith('/')) {
        const rec = records.find((r) => r.id === tail.slice(1))
        return rec === undefined ? fail(81044, 'Record does not exist.', 404) : ok(rec)
      }
      const name = url.searchParams.get('name')
      return ok(records.filter((r) => r.type === url.searchParams.get('type') && r.name === name))
    }
    const body = init?.body === undefined ? {} : JSON.parse(String(init.body)) as Partial<Rec>
    if (method === 'POST') {
      const rec: Rec = { id: `r${seq++}`, type: body.type!, name: body.name!, content: body.content!, proxied: body.proxied ?? false, ttl: body.ttl, comment: body.comment }
      records.push(rec)
      return ok(rec)
    }
    const id = tail.slice(1)
    const idx = records.findIndex((r) => r.id === id)
    if (idx < 0) return fail(81044, 'Record does not exist.', 404)
    if (method === 'PATCH') { records[idx] = { ...records[idx], ...body }; return ok(records[idx]) }
    if (method === 'DELETE') { const [gone] = records.splice(idx, 1); return ok({ id: gone.id }) }
    return fail(1, `unexpected ${method}`)
  }) as typeof fetch
  return { dns: new CloudflareDns('token', 'zone', fetchImpl), records, calls }
}

const NAME = 'alice.example.test'
const IP = '203.0.113.9'
const COMMENT = 'dshn premium route (managed by the relay)'

describe('CloudflareDns', () => {
  it('creates an un-proxied, commented A record when the name has none', async () => {
    const cf = fakeCloudflare([])
    const ref = await cf.dns.point(NAME, IP)
    expect(cf.records).toHaveLength(1)
    expect(cf.records[0]).toMatchObject({ id: ref.id, name: NAME, content: IP, proxied: false, ttl: 120, comment: COMMENT })
  })

  it('reuses its own record and un-proxies it if needed', async () => {
    const cf = fakeCloudflare([{ id: 'own', type: 'A', name: NAME, content: IP, proxied: true, comment: COMMENT }])
    const ref = await cf.dns.point(NAME, IP)
    expect(ref.id).toBe('own')
    expect(cf.records).toHaveLength(1)
    expect(cf.records[0].proxied).toBe(false)
    // Already right → nothing to change.
    cf.calls.length = 0
    await cf.dns.point(NAME, IP)
    expect(cf.calls.filter((c) => !c.startsWith('GET'))).toHaveLength(0)
  })

  it('retargets a record it created for an earlier accelerator address', async () => {
    const cf = fakeCloudflare([{ id: 'old', type: 'A', name: NAME, content: '198.51.100.1', proxied: false, comment: COMMENT }])
    const ref = await cf.dns.point(NAME, IP)
    expect(ref.id).toBe('old')
    expect(cf.records).toHaveLength(1)
    expect(cf.records[0].content).toBe(IP)
  })

  it("refuses to touch or add beside an operator's record of the same name", async () => {
    const cf = fakeCloudflare([{ id: 'theirs', type: 'A', name: NAME, content: '198.51.100.1', proxied: true, comment: 'set by hand' }])
    await expect(cf.dns.point(NAME, IP)).rejects.toThrow(/not managed by the relay/)
    expect(cf.records).toEqual([{ id: 'theirs', type: 'A', name: NAME, content: '198.51.100.1', proxied: true, comment: 'set by hand' }])
  })

  it('does not adopt a same-target record that lacks the relay comment', async () => {
    const cf = fakeCloudflare([{ id: 'manual', type: 'A', name: NAME, content: IP, proxied: false }])
    await expect(cf.dns.point(NAME, IP)).rejects.toThrow(/not managed by the relay/)
    expect(cf.records).toHaveLength(1)
    expect(cf.records[0].id).toBe('manual')
    expect(cf.records[0].comment).toBeUndefined()
  })

  it('refuses to delete by a remembered id when that record is no longer ours', async () => {
    // The relay's record was removed by hand and the operator later created
    // their own; a stale id must not take theirs down.
    const cf = fakeCloudflare([{ id: 'reused', type: 'A', name: NAME, content: '198.51.100.1', proxied: true, comment: 'set by hand' }])
    await expect(cf.dns.unpoint(NAME, 'reused', IP)).rejects.toThrow(/not the relay's record/)
    expect(cf.records).toHaveLength(1)
  })

  it('a stale id falls back to sweeping the name for records of ours', async () => {
    const cf = fakeCloudflare([{ id: 'own2', type: 'A', name: NAME, content: IP, proxied: false, comment: COMMENT }])
    await cf.dns.unpoint(NAME, 'long-gone', IP)
    expect(cf.records).toHaveLength(0)
  })

  it('removes by id, and is a no-op when the record is already gone', async () => {
    const cf = fakeCloudflare([{ id: 'own', type: 'A', name: NAME, content: IP, proxied: false, comment: COMMENT }])
    await cf.dns.unpoint(NAME, 'own', IP)
    expect(cf.records).toHaveLength(0)
    await expect(cf.dns.unpoint(NAME, 'own', IP)).resolves.toBeUndefined()
  })

  it('without an id removes only the records pointing at the accelerator', async () => {
    const cf = fakeCloudflare([
      { id: 'own', type: 'A', name: NAME, content: IP, proxied: false, comment: COMMENT },
      { id: 'theirs', type: 'A', name: NAME, content: '198.51.100.1', proxied: true },
    ])
    await cf.dns.unpoint(NAME, undefined, IP)
    expect(cf.records.map((r) => r.id)).toEqual(['theirs'])
  })

  it('surfaces API errors with the code and message', async () => {
    const cf = fakeCloudflare([])
    const dns = new CloudflareDns('token', 'zone', (async () => new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: 'Authentication error' }] }), { status: 403 })) as typeof fetch)
    void cf
    await expect(dns.point(NAME, IP)).rejects.toThrow(/10000 Authentication error/)
  })
})
