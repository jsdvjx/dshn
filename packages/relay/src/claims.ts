/**
 * Claim store — the relay's authority on "who owns which subdomain". Replaces
 * the old pre-provisioned token registry with trust-on-first-use: the first
 * agent to present a free subdomain with a password claims it (the password is
 * hashed and persisted); later connects and browser logins must present the
 * same password. This is what lets a user just type a prefix + password in a
 * dialog with no server-side provisioning step.
 *
 * Passwords are stored as scrypt hashes with a per-claim random salt, never in
 * clear. Verification is constant-time. The store persists to a JSON file with
 * an atomic write so a crash mid-write cannot corrupt it.
 */
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto'
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs'
import { promisify } from 'node:util'
import { isValidSubdomainLabel } from '@dshn/protocol'

const scrypt = promisify(scryptCb) as (password: string, salt: Buffer, keylen: number) => Promise<Buffer>

interface ClaimRecord {
  /** Hex scrypt hash of the password. */
  hash: string
  /** Hex salt fed to scrypt. */
  salt: string
  /** First-claim timestamp (ms), passed in by the caller (the store never clocks). */
  createdAt: number
  /**
   * Devices that have held this claim, by device id — so the device picker can
   * list a machine that is currently offline. Bounded (oldest dropped) so a
   * claim's record cannot grow without limit.
   */
  devices?: Record<string, DeviceRecord>
  /** Operator-assigned premium route, when this claim rides the accelerated path. */
  premium?: PremiumRecord
}

/**
 * A claim's premium-route assignment. Only the operator sets it (admin panel);
 * the store just remembers it, plus the DNS record the relay created for it so
 * the record can be removed again when the route is withdrawn.
 */
export interface PremiumRecord {
  /** When the operator enabled the route (ms). */
  since: number
  /** The dedicated DNS record the relay manages for it (absent when DNS is manual). */
  dns?: { id: string; content: string }
}

/** One device's last-known identity under a claim. */
export interface DeviceRecord {
  /** Human-readable name the agent reported (e.g. its hostname). */
  name: string
  /** Last connect/disconnect timestamp (ms), caller-supplied. */
  lastSeen: number
}

/** Most devices remembered per claim; the least recently seen are dropped. */
const MAX_DEVICES_PER_CLAIM = 20

/** Result of a claim-or-verify attempt. */
export interface ClaimResult {
  ok: boolean
  /** True when this call created the claim (first use of a free subdomain). */
  claimed: boolean
  /** Present when ok is false: why. */
  reason?: string
}

const SCRYPT_KEYLEN = 32

/** Longest password the store will hash (scrypt cost is per byte of input too). */
const MAX_PASSWORD_LENGTH = 256

/** How long device-touch persists are coalesced before hitting the disk. */
const LAZY_PERSIST_MS = 500

/**
 * Hash a password with a fresh or given salt. Async: scrypt runs on the
 * libuv threadpool, so a burst of HELLOs cannot stall every tenant's frames.
 */
function hashPassword(password: string, saltHex: string): Promise<string> {
  return scrypt(password, Buffer.from(saltHex, 'hex'), SCRYPT_KEYLEN).then((buf) => buf.toString('hex'))
}

const HEX = /^[0-9a-f]+$/i

/**
 * Validate one on-disk claim record. The store is the relay's authority on
 * ownership, so a record it cannot vouch for is a startup error, never an
 * "empty" claim that would let the name be taken over.
 */
function checkRecord(subdomain: string, raw: unknown): ClaimRecord {
  const bad = (why: string): never => { throw new Error(`claim "${subdomain}": ${why}`) }
  if (raw === null || typeof raw !== 'object') return bad('not an object')
  const r = raw as Record<string, unknown>
  if (typeof r.hash !== 'string' || r.hash.length !== SCRYPT_KEYLEN * 2 || !HEX.test(r.hash)) return bad('bad hash')
  if (typeof r.salt !== 'string' || r.salt.length < 16 || !HEX.test(r.salt)) return bad('bad salt')
  if (typeof r.createdAt !== 'number' || !Number.isFinite(r.createdAt)) return bad('bad createdAt')
  const out: ClaimRecord = { hash: r.hash, salt: r.salt, createdAt: r.createdAt }
  if (r.devices !== undefined) {
    if (r.devices === null || typeof r.devices !== 'object') return bad('bad devices')
    const devices: Record<string, DeviceRecord> = {}
    for (const [id, d] of Object.entries(r.devices as Record<string, unknown>)) {
      if (d === null || typeof d !== 'object') return bad(`bad device ${id}`)
      const dev = d as Record<string, unknown>
      if (typeof dev.name !== 'string' || typeof dev.lastSeen !== 'number') return bad(`bad device ${id}`)
      devices[id] = { name: dev.name, lastSeen: dev.lastSeen }
    }
    out.devices = devices
  }
  if (r.premium !== undefined) {
    if (r.premium === null || typeof r.premium !== 'object') return bad('bad premium')
    const p = r.premium as Record<string, unknown>
    if (typeof p.since !== 'number') return bad('bad premium.since')
    const premium: PremiumRecord = { since: p.since }
    if (p.dns !== undefined) {
      const dns = p.dns as Record<string, unknown> | null
      if (dns === null || typeof dns !== 'object' || typeof dns.id !== 'string' || typeof dns.content !== 'string') return bad('bad premium.dns')
      premium.dns = { id: dns.id, content: dns.content }
    }
    out.premium = premium
  }
  return out
}

/** Constant-time hex-string compare. */
function hexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
}

export class ClaimStore {
  private readonly claims = new Map<string, ClaimRecord>()
  /** Subdomains an admin has banned: never claimable until unbanned. */
  private readonly banned = new Set<string>()

  constructor(private readonly path: string, seed?: Record<string, ClaimRecord>, banned?: string[]) {
    if (seed !== undefined) for (const [k, v] of Object.entries(seed)) this.claims.set(k, v)
    if (banned !== undefined) for (const b of banned) this.banned.add(b)
  }

  /**
   * Load a claim store from disk. An ABSENT file is a fresh install (empty
   * store; the first claim creates it). A file that exists but cannot be read,
   * parsed, or validated is a hard error: starting with an empty store would
   * silently make every existing name claimable by anyone. Move the file aside
   * deliberately if a reset is really wanted.
   * @param path - JSON file backing the store.
   * @returns the store.
   */
  static fromFile(path: string): ClaimStore {
    if (!existsSync(path)) return new ClaimStore(path)
    let raw: { claims?: unknown; banned?: unknown }
    try {
      raw = JSON.parse(readFileSync(path, 'utf8')) as { claims?: unknown; banned?: unknown }
    } catch (err) {
      throw new Error(`claims file ${path} is unreadable or not JSON (${(err as Error).message}); refusing to start with an empty store — move it aside to reset`)
    }
    if (raw === null || typeof raw !== 'object') throw new Error(`claims file ${path}: not an object`)
    const claims: Record<string, ClaimRecord> = {}
    if (raw.claims !== undefined) {
      if (raw.claims === null || typeof raw.claims !== 'object') throw new Error(`claims file ${path}: "claims" is not an object`)
      for (const [sub, rec] of Object.entries(raw.claims as Record<string, unknown>)) {
        try {
          claims[sub] = checkRecord(sub, rec)
        } catch (err) {
          throw new Error(`claims file ${path}: ${(err as Error).message}; refusing to start — move it aside to reset`)
        }
      }
    }
    const banned: string[] = []
    if (raw.banned !== undefined) {
      if (!Array.isArray(raw.banned) || raw.banned.some((b) => typeof b !== 'string')) throw new Error(`claims file ${path}: "banned" is not a list of names`)
      banned.push(...(raw.banned as string[]))
    }
    return new ClaimStore(path, claims, banned)
  }

  private lazyTimer: ReturnType<typeof setTimeout> | null = null

  /**
   * Persist atomically and durably: write a temp file, fsync it, then rename
   * over the target. An IO failure (disk full, permissions) must not throw into
   * the caller — persist runs inside WebSocket event handlers, where an
   * uncaught throw would take the relay down. The in-memory map stays
   * authoritative and the next successful persist writes everything.
   *
   * Ownership changes (claim, release, ban, premium) hit the disk at once.
   * Device-touch bookkeeping is `lazy`: coalesced for a moment so a reconnect
   * storm does not rewrite the file per socket — it carries no ownership.
   */
  private persist(lazy = false): void {
    if (lazy) {
      if (this.lazyTimer === null) this.lazyTimer = setTimeout(() => { this.lazyTimer = null; this.persist() }, LAZY_PERSIST_MS)
      return
    }
    if (this.lazyTimer !== null) { clearTimeout(this.lazyTimer); this.lazyTimer = null }
    try {
      const body = JSON.stringify({ claims: Object.fromEntries(this.claims), banned: [...this.banned] })
      const tmp = `${this.path}.tmp`
      const fd = openSync(tmp, 'w', 0o600)
      try {
        writeSync(fd, body)
        fsyncSync(fd)
      } finally {
        closeSync(fd)
      }
      renameSync(tmp, this.path)
    } catch (err) {
      console.error(`dshn-relay: cannot persist claims to ${this.path}: ${(err as Error).message}`)
    }
  }

  /** Write any coalesced changes now (shutdown). */
  flush(): void {
    if (this.lazyTimer !== null) this.persist()
  }

  /**
   * Claim a free subdomain, or verify the password of a claimed one. Called on
   * every agent HELLO.
   * @param subdomain - the requested label.
   * @param password - the presented password.
   * @param now - current time in ms (the store never reads the clock itself).
   * @returns whether the agent may hold the subdomain.
   */
  async claimOrVerify(subdomain: string, password: string, now: number): Promise<ClaimResult> {
    if (typeof subdomain !== 'string' || !isValidSubdomainLabel(subdomain)) return { ok: false, claimed: false, reason: 'invalid or reserved subdomain' }
    if (this.banned.has(subdomain)) return { ok: false, claimed: false, reason: 'subdomain is banned' }
    if (typeof password !== 'string' || password.length < 8) return { ok: false, claimed: false, reason: 'password too short (min 8)' }
    if (password.length > MAX_PASSWORD_LENGTH) return { ok: false, claimed: false, reason: `password too long (max ${MAX_PASSWORD_LENGTH})` }
    const existing = this.claims.get(subdomain)
    if (existing === undefined) {
      const salt = randomBytes(16).toString('hex')
      const hash = await hashPassword(password, salt)
      // Re-check after the await: a concurrent HELLO may have claimed it first.
      const race = this.claims.get(subdomain)
      if (race !== undefined) {
        return hexEqual(await hashPassword(password, race.salt), race.hash)
          ? { ok: true, claimed: false }
          : { ok: false, claimed: false, reason: 'wrong password for this subdomain' }
      }
      if (this.banned.has(subdomain)) return { ok: false, claimed: false, reason: 'subdomain is banned' }
      this.claims.set(subdomain, { hash, salt, createdAt: now })
      this.persist()
      return { ok: true, claimed: true }
    }
    if (hexEqual(await hashPassword(password, existing.salt), existing.hash)) return { ok: true, claimed: false }
    return { ok: false, claimed: false, reason: 'wrong password for this subdomain' }
  }

  /**
   * Verify a browser login password against a claimed subdomain. Unlike
   * {@link claimOrVerify} this never creates a claim: an unclaimed subdomain has
   * no valid password.
   * @param subdomain - the label from the request Host.
   * @param password - the presented password.
   * @returns whether the password is correct for an existing claim.
   */
  async verifyLogin(subdomain: string, password: string): Promise<boolean> {
    const existing = this.claims.get(subdomain)
    if (existing === undefined || typeof password !== 'string' || password.length > MAX_PASSWORD_LENGTH) return false
    return hexEqual(await hashPassword(password, existing.salt), existing.hash)
  }

  /** Whether a subdomain has been claimed (an agent may be offline). */
  isClaimed(subdomain: string): boolean {
    return this.claims.has(subdomain)
  }

  /**
   * The session version of a claim: what a browser session cookie is bound to.
   * It changes whenever the claim is re-created (release/ban + re-claim), so
   * every session minted for the previous owner stops verifying at once —
   * a cookie is never a key to whoever holds the name next.
   * @returns the version, or null when the name is not claimed (no session can be valid).
   */
  sessionVersionOf(subdomain: string): string | null {
    const claim = this.claims.get(subdomain)
    return claim === undefined ? null : `${claim.createdAt}.${claim.salt.slice(0, 8)}`
  }

  /**
   * Record that a device connected (or disconnected) under a claim, updating its
   * name and last-seen time. Called on agent register and close — rare events,
   * so the synchronous persist is fine here.
   * @param subdomain - the claimed label the device holds.
   * @param deviceId - the device's stable id.
   * @param name - the device's display name as reported in HELLO.
   * @param now - current time in ms.
   */
  touchDevice(subdomain: string, deviceId: string, name: string, now: number): void {
    const claim = this.claims.get(subdomain)
    if (claim === undefined) return
    const devices = claim.devices ?? (claim.devices = {})
    devices[deviceId] = { name, lastSeen: now }
    const ids = Object.keys(devices)
    if (ids.length > MAX_DEVICES_PER_CLAIM) {
      ids.sort((a, b) => devices[a].lastSeen - devices[b].lastSeen)
      for (const id of ids.slice(0, ids.length - MAX_DEVICES_PER_CLAIM)) delete devices[id]
    }
    this.persist(true)
  }

  /** Known devices of a claim (connected or not), for the device picker. */
  devicesOf(subdomain: string): Array<{ id: string } & DeviceRecord> {
    const devices = this.claims.get(subdomain)?.devices ?? {}
    return Object.entries(devices).map(([id, d]) => ({ id, name: d.name, lastSeen: d.lastSeen }))
  }

  /** The premium-route assignment of a claim, or null (unclaimed, or standard route). */
  premiumOf(subdomain: string): PremiumRecord | null {
    return this.claims.get(subdomain)?.premium ?? null
  }

  /**
   * Assign or withdraw the premium route of a claim. Admin-only — an agent has
   * no path to this; the route is the operator's to grant.
   * @param subdomain - the claimed label.
   * @param premium - the assignment, or null to return to the standard route.
   * @returns false when no such claim exists.
   */
  setPremium(subdomain: string, premium: PremiumRecord | null): boolean {
    const claim = this.claims.get(subdomain)
    if (claim === undefined) return false
    if (premium === null) delete claim.premium
    else claim.premium = premium
    this.persist()
    return true
  }

  /** Every claim, without password material — for the admin panel. */
  list(): Array<{ subdomain: string; createdAt: number; devices: Array<{ id: string } & DeviceRecord>; premium: PremiumRecord | null }> {
    return [...this.claims.entries()].map(([subdomain, c]) => ({
      subdomain,
      createdAt: c.createdAt,
      devices: Object.entries(c.devices ?? {}).map(([id, d]) => ({ id, name: d.name, lastSeen: d.lastSeen })),
      premium: c.premium ?? null,
    }))
  }

  /**
   * Release a claim: the subdomain becomes free to claim again with a new
   * password. Admin-only — there is deliberately no self-service path to this.
   * @param subdomain - the claimed label to release.
   * @returns whether a claim existed and was removed.
   */
  remove(subdomain: string): boolean {
    const existed = this.claims.delete(subdomain)
    if (existed) this.persist()
    return existed
  }

  /**
   * Ban a subdomain: its claim (if any) is deleted and no agent may claim the
   * label again until it is unbanned. Note this bans the *name*, not the person
   * — the relay knows users only as claims. Admin-only.
   * @param subdomain - the label to ban.
   * @returns whether a live claim was deleted in the process.
   */
  ban(subdomain: string): boolean {
    const existed = this.claims.delete(subdomain)
    this.banned.add(subdomain)
    this.persist()
    return existed
  }

  /**
   * Lift a ban; the label becomes claimable again (by anyone).
   * @param subdomain - the banned label.
   * @returns whether it was banned.
   */
  unban(subdomain: string): boolean {
    const existed = this.banned.delete(subdomain)
    if (existed) this.persist()
    return existed
  }

  /** The banned labels, for the admin panel. */
  listBanned(): string[] {
    return [...this.banned]
  }
}
