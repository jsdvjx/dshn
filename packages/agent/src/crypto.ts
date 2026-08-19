/**
 * Node half of the end-to-end crypto (the browser half uses Web Crypto with the
 * same parameters). A key is derived from the user's e2e password + a public
 * salt via PBKDF2-SHA256; payloads are sealed with AES-256-GCM. Wire format of a
 * sealed blob is `IV(12) || ciphertext || tag(16)` — exactly what Web Crypto's
 * AES-GCM produces once the IV is prefixed, so the two ends interoperate.
 *
 * The e2e password never leaves the machine it was set on and is never sent to
 * the relay; only the salt (not secret) is. A wrong password fails the GCM auth
 * check on decrypt, so ciphertext is unreadable without it.
 */
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto'
import { E2E_IV_BYTES, E2E_PBKDF2_ITERS, E2E_SALT_BYTES, E2E_TAG_BYTES } from '@dshn/protocol'

/** A fresh random salt, hex-encoded, generated once per agent and served to browsers. */
export function newSalt(): string {
  return randomBytes(E2E_SALT_BYTES).toString('hex')
}

/**
 * Derive the AES-256 key from the e2e password and salt.
 * @param password - the user's e2e password (never transmitted).
 * @param saltHex - the hex salt (public).
 * @returns the 32-byte key.
 */
export function deriveKey(password: string, saltHex: string): Buffer {
  return pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), E2E_PBKDF2_ITERS, 32, 'sha256')
}

/**
 * Seal a payload: `IV || ciphertext || tag`.
 * @param key - the derived key.
 * @param plain - the plaintext bytes.
 * @returns the sealed blob.
 */
export function seal(key: Buffer, plain: Uint8Array): Buffer {
  const iv = randomBytes(E2E_IV_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([cipher.update(plain), cipher.final()])
  return Buffer.concat([iv, ct, cipher.getAuthTag()])
}

/**
 * Open a sealed blob. Throws if the key is wrong or the blob was tampered.
 * @param key - the derived key.
 * @param blob - `IV || ciphertext || tag`.
 * @returns the plaintext bytes.
 */
export function open(key: Buffer, blob: Uint8Array): Buffer {
  if (blob.length < E2E_IV_BYTES + E2E_TAG_BYTES) throw new Error('e2e: blob too short')
  const buf = Buffer.from(blob.buffer, blob.byteOffset, blob.byteLength)
  const iv = buf.subarray(0, E2E_IV_BYTES)
  const tag = buf.subarray(buf.length - E2E_TAG_BYTES)
  const ct = buf.subarray(E2E_IV_BYTES, buf.length - E2E_TAG_BYTES)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ct), decipher.final()])
}
