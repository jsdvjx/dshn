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
}

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

  /** Persist atomically: write a temp file, then rename over the target. */
  private persist(): void {
    const body = JSON.stringify({ claims: Object.fromEntries(this.claims) })
    const tmp = `${this.path}.tmp`
    writeFileSync(tmp, body, { mode: 0o600 })
    renameSync(tmp, this.path)
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
}
