import { describe, it, expect } from 'vitest'
import {
  DATA_RES_BODY,
  decodeControl,
  decodeData,
  encodeControl,
  encodeData,
  sanitizeCloseCode,
  sanitizeCloseReason,
  subdomainOf,
  isValidSubdomainLabel,
  type ControlFrame,
} from '../src/index.js'

describe('control codec', () => {
  it('round-trips a request head with duplicate headers preserved', () => {
    const frame: ControlFrame = {
      t: 'req_head',
      id: 7,
      method: 'GET',
      path: '/api?x=1',
      headers: [
        ['host', 'alice.ds.hn'],
        ['set-cookie', 'a=1'],
        ['set-cookie', 'b=2'],
      ],
    }
    const back = decodeControl(encodeControl(frame))
    expect(back).toEqual(frame)
  })
})

describe('data codec', () => {
  it('round-trips kind, id, and payload bytes', () => {
    const payload = new Uint8Array([0, 255, 16, 200])
    const frame = decodeData(encodeData(DATA_RES_BODY, 4_000_000_000, payload))
    expect(frame.kind).toBe(DATA_RES_BODY)
    // id exercises the top bit — uint32, not a signed int32.
    expect(frame.id).toBe(4_000_000_000)
    expect(Array.from(frame.payload)).toEqual([0, 255, 16, 200])
  })

  it('rejects a frame shorter than its header', () => {
    expect(() => decodeData(new Uint8Array([1, 2]))).toThrow()
  })
})

describe('sanitizeCloseCode', () => {
  it('passes valid sendable codes through', () => {
    for (const c of [1000, 1001, 1011, 1014, 3000, 4999]) expect(sanitizeCloseCode(c)).toBe(c)
  })

  it('maps the reserved/observed-only codes that crash ws.close to 1000', () => {
    // These are exactly what a browser emits on a plain or abnormal close, and
    // forwarding them verbatim crashed the host before the fix.
    for (const c of [0, 1004, 1005, 1006, 1015, 1016, 2999, 5000]) expect(sanitizeCloseCode(c)).toBe(1000)
  })
})

describe('sanitizeCloseReason', () => {
  it('leaves a short reason untouched', () => {
    expect(sanitizeCloseReason('bye')).toBe('bye')
  })

  it('truncates an over-long reason under the 123-byte ws limit', () => {
    const out = sanitizeCloseReason('x'.repeat(500))
    expect(Buffer.byteLength(out, 'utf8')).toBeLessThanOrEqual(123)
  })

  it('truncates multi-byte reasons on a char boundary, staying valid UTF-8', () => {
    const out = sanitizeCloseReason('界'.repeat(100)) // 3 bytes each → 300 bytes
    expect(Buffer.byteLength(out, 'utf8')).toBeLessThanOrEqual(123)
    expect(out).toBe(Buffer.from(out, 'utf8').toString('utf8')) // no replacement chars
  })
})

describe('isValidSubdomainLabel', () => {
  it('accepts labels of 4–32 chars', () => {
    for (const s of ['alice', 'abcd', 'my-box', 'a1b2', 'a'.repeat(32)]) expect(isValidSubdomainLabel(s)).toBe(true)
  })

  it('rejects short (<4), malformed, too-long, and reserved labels', () => {
    for (const s of ['', 'a', 'ab', 'abc', '-abc', 'abc-', 'Abcd', 'a_bc', 'a.bc', 'a'.repeat(33), 'origin', 'relay']) {
      expect(isValidSubdomainLabel(s)).toBe(false)
    }
  })
})

describe('subdomainOf', () => {
  it('extracts one flat label under the apex, ignoring port and case', () => {
    expect(subdomainOf('Alice.ds.hn:443', 'ds.hn')).toBe('alice')
  })

  it('rejects the apex itself, deeper names, and foreign hosts', () => {
    expect(subdomainOf('ds.hn', 'ds.hn')).toBeNull()
    expect(subdomainOf('a.b.ds.hn', 'ds.hn')).toBeNull()
    expect(subdomainOf('alice.example.com', 'ds.hn')).toBeNull()
  })
})
