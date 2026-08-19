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
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { readFileSync, writeFileSync, renameSync } from 'node:fs'
import { isValidSubdomainLabel } from '@dshn/protocol'

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

/** Hash a password with a fresh or given salt. */
function hashPassword(password: string, saltHex: string): string {
  return scryptSync(password, Buffer.from(saltHex, 'hex'), SCRYPT_KEYLEN).toString('hex')
}

/** Constant-time hex-string compare. */
function hexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
}

export class ClaimStore {
  private readonly claims = new Map<string, ClaimRecord>()

  constructor(private readonly path: string, seed?: Record<string, ClaimRecord>) {
    if (seed !== undefined) for (const [k, v] of Object.entries(seed)) this.claims.set(k, v)
  }

  /**
   * Load a claim store from disk, or start empty if the file is absent.
   * @param path - JSON file backing the store.
   * @returns the store.
   */
  static fromFile(path: string): ClaimStore {
    try {
      const raw = JSON.parse(readFileSync(path, 'utf8')) as { claims?: Record<string, ClaimRecord> }
      return new ClaimStore(path, raw.claims ?? {})
    } catch {
      // Absent or unreadable → a fresh store; first claim will create the file.
      return new ClaimStore(path)
    }
  }

  /**
   * Persist atomically: write a temp file, then rename over the target. An IO
   * failure (disk full, permissions) must not throw into the caller — persist
   * runs inside WebSocket event handlers, where an uncaught throw would take
   * the relay down. The in-memory map stays authoritative and the next
   * successful persist writes everything.
   */
  private persist(): void {
    try {
      const body = JSON.stringify({ claims: Object.fromEntries(this.claims) })
      const tmp = `${this.path}.tmp`
      writeFileSync(tmp, body, { mode: 0o600 })
      renameSync(tmp, this.path)
    } catch (err) {
      console.error(`dshn-relay: cannot persist claims to ${this.path}: ${(err as Error).message}`)
    }
  }

  /**
   * Claim a free subdomain, or verify the password of a claimed one. Called on
   * every agent HELLO.
   * @param subdomain - the requested label.
   * @param password - the presented password.
   * @param now - current time in ms (the store never reads the clock itself).
   * @returns whether the agent may hold the subdomain.
   */
  claimOrVerify(subdomain: string, password: string, now: number): ClaimResult {
    if (!isValidSubdomainLabel(subdomain)) return { ok: false, claimed: false, reason: 'invalid or reserved subdomain' }
    if (password.length < 8) return { ok: false, claimed: false, reason: 'password too short (min 8)' }
    const existing = this.claims.get(subdomain)
    if (existing === undefined) {
      const salt = randomBytes(16).toString('hex')
      this.claims.set(subdomain, { hash: hashPassword(password, salt), salt, createdAt: now })
      this.persist()
      return { ok: true, claimed: true }
    }
    if (hexEqual(hashPassword(password, existing.salt), existing.hash)) return { ok: true, claimed: false }
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
  verifyLogin(subdomain: string, password: string): boolean {
    const existing = this.claims.get(subdomain)
    if (existing === undefined) return false
    return hexEqual(hashPassword(password, existing.salt), existing.hash)
  }

  /** Whether a subdomain has been claimed (an agent may be offline). */
  isClaimed(subdomain: string): boolean {
    return this.claims.has(subdomain)
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
    this.persist()
  }

  /** Known devices of a claim (connected or not), for the device picker. */
  devicesOf(subdomain: string): Array<{ id: string } & DeviceRecord> {
    const devices = this.claims.get(subdomain)?.devices ?? {}
    return Object.entries(devices).map(([id, d]) => ({ id, name: d.name, lastSeen: d.lastSeen }))
  }
}
