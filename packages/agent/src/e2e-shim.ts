/**
 * The browser half of end-to-end encryption, as a script the HOST injects into
 * the app shell's `<head>` — ahead of every dsh script — whenever E2E is on.
 *
 * Why injected and not part of client.js: dsh boots its connection and first
 * `/api` calls in parallel with loading plugin client modules, so a shim that
 * arrives as a module installs a few hundred ms after the app has already
 * opened `/api/events.mux` and asked for its inventory. Those early requests
 * bypassed the shim and the app saw ciphertext ("dropping malformed WebSocket
 * frame: binary", "... is not valid JSON"). Injected into the shell, the shim
 * patches `fetch` and `WebSocket` before any dsh code runs, and both wait on
 * the unlock gate from the first byte of the page — which is the whole point.
 *
 * The public salt and device id come inline (no async discovery): the host
 * only injects when E2E is on, so the browser has nothing to ask.
 *
 * Kept as plain JS in a raw string so it stays byte-identical to what runs in
 * the browser; it must not use backticks or `${`.
 */
const SHIM_BODY = String.raw`
  if (window.__dshnE2E) return // already installed (double injection / legacy module)
  const E2E_HEADER = 'x-dshn-e2e'
  const E2E_ITERS = 210000
  window.__dshnE2E = { stage: 'entered', host: (typeof location !== 'undefined' ? location.hostname : '?') }
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) { window.__dshnE2E.stage = 'no-subtle'; return }
  const host = location.hostname
  const loopback = host === 'localhost' || host === '::1' || /^127\./.test(host)
  window.__dshnE2E.remote = !loopback
  if (loopback) { window.__dshnE2E.stage = 'loopback-skip'; return } // local access talks straight to dsh; nothing is encrypted

  const realFetch = window.fetch.bind(window)
  const RealWS = window.WebSocket
  const enc = new TextEncoder()
  let key = null          // CryptoKey once the visitor unlocks; null = pass-through
  let active = false      // agent reports E2E on
  let resolveReady
  const ready = new Promise((r) => { resolveReady = r })
  const hexToBytes = (hx) => { const a = new Uint8Array(hx.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(hx.substr(i * 2, 2), 16); return a }
  const isApi = (url) => { try { const u = new URL(url, location.href); return u.origin === location.origin && u.pathname.startsWith('/api') } catch { return false } }

  async function deriveKey(password, saltHex) {
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: E2E_ITERS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  }
  async function sealBytes(bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes))
    const out = new Uint8Array(iv.length + ct.length); out.set(iv); out.set(ct, iv.length); return out
  }
  async function openBytes(k, blob) {
    const iv = blob.subarray(0, 12)
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, blob.subarray(12))
    return new Uint8Array(pt)
  }

  // fetch: seal /api request bodies, decrypt marked responses. Non-/api and
  // (once ready) the E2E-off case pass straight through.
  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input)
    if (!isApi(url)) return realFetch(input, init)
    await ready
    if (!key) return realFetch(input, init)
    const req = new Request(input, init)
    const headers = new Headers(req.headers)
    let body = null
    const buf = await req.clone().arrayBuffer()
    if (buf.byteLength > 0) { body = await sealBytes(new Uint8Array(buf)); headers.set(E2E_HEADER, '1') }
    else headers.set(E2E_HEADER, '1')
    const res = await realFetch(url, { method: req.method, headers, body, credentials: 'include', mode: req.mode, cache: req.cache })
    if (res.headers.get(E2E_HEADER) !== '1') return res
    const sealed = new Uint8Array(await res.arrayBuffer())
    let plain
    try { plain = await openBytes(key, sealed) } catch { return new Response(null, { status: 502, statusText: 'e2e decrypt failed' }) }
    const outH = new Headers(res.headers); outH.delete(E2E_HEADER); outH.delete('content-length')
    return new Response(plain, { status: res.status, statusText: res.statusText, headers: outH })
  }

  // WebSocket: connect normally, but decrypt the sealed downlink messages in
  // arrival order once the key is ready. Everything else proxies through.
  const E2EWebSocket = class extends EventTarget {
    constructor(url, protocols) {
      super()
      this._ws = new RealWS(url, protocols)
      this._q = Promise.resolve()
      this._api = isApi(String(url))
      for (const t of ['open', 'error']) this._ws.addEventListener(t, (e) => this._emit(t, e))
      this._ws.addEventListener('close', (e) => this._emit('close', e))
      this._ws.addEventListener('message', (e) => { this._q = this._q.then(() => this._msg(e)) })
    }
    get url() { return this._ws.url }
    get readyState() { return this._ws.readyState }
    get bufferedAmount() { return this._ws.bufferedAmount }
    get protocol() { return this._ws.protocol }
    get extensions() { return this._ws.extensions }
    get binaryType() { return this._ws.binaryType }
    set binaryType(v) { this._ws.binaryType = v }
    set onopen(f) { this._onopen = f } get onopen() { return this._onopen }
    set onclose(f) { this._onclose = f } get onclose() { return this._onclose }
    set onerror(f) { this._onerror = f } get onerror() { return this._onerror }
    set onmessage(f) { this._onmessage = f } get onmessage() { return this._onmessage }
    send(d) { this._ws.send(d) }
    close(c, r) { this._ws.close(c, r) }
    _emit(type, orig) {
      const ev = type === 'close' ? new CloseEvent('close', { code: orig.code, reason: orig.reason, wasClean: orig.wasClean }) : new Event(type)
      const on = this['_on' + type]; if (on) try { on.call(this, ev) } catch {}
      this.dispatchEvent(ev)
    }
    async _msg(e) {
      let data = e.data
      if (this._api) {
        await ready
        if (active && key) {
          try {
            const raw = data instanceof ArrayBuffer ? new Uint8Array(data)
              : data instanceof Blob ? new Uint8Array(await data.arrayBuffer())
              : new Uint8Array(await new Blob([data]).arrayBuffer())
            const opened = await openBytes(key, raw)
            data = opened[0] === 0 ? new TextDecoder().decode(opened.subarray(1)) : opened.subarray(1).buffer
          } catch { return } // drop messages we can't decrypt
        }
      }
      const ev = new MessageEvent('message', { data })
      if (this._onmessage) try { this._onmessage.call(this, ev) } catch {}
      this.dispatchEvent(ev)
    }
  }
  for (const [k, v] of [['CONNECTING', 0], ['OPEN', 1], ['CLOSING', 2], ['CLOSED', 3]]) {
    E2EWebSocket[k] = v; E2EWebSocket.prototype[k] = v
  }
  window.WebSocket = E2EWebSocket

  // The host injected this script only because E2E is ON, with the public
  // salt and device id inline — so there is nothing to discover and no
  // window in which dsh's own traffic could slip past the gate: fetch and
  // WebSocket wait on the ready promise from the first byte of the page.
  ;(async () => {
    try {
      active = true
      window.__dshnE2E.enabled = true
      window.__dshnE2E.stage = 'gating'
      await unlockGate(__dshnInfo.salt, __dshnInfo.device)
      window.__dshnE2E.stage = 'unlocked'
    } catch (e) { window.__dshnE2E.stage = 'error'; window.__dshnE2E.error = String(e && e.message || e) }
    resolveReady()
  })()

  // A blocking DOM overlay (not React — must appear before the app mounts)
  // asking for the e2e password; verified by a sealed probe to /api.
  function unlockGate(salt, deviceKey) {
    return new Promise((resolve) => {
      const zh = String(document.documentElement.lang || navigator.language || 'en').toLowerCase().indexOf('zh') === 0
      const L = zh
        ? { t: '端到端加密', s: '本页内容已端到端加密。输入端到端密码解锁——密码不会发送到云端。', p: '端到端密码', u: '解锁', bad: '密码错误，无法解密。',
            save: '在此设备记住密码', stale: '已保存的密码无法解锁（可能已被更改），请重新输入。' }
        : { t: 'End-to-end encrypted', s: 'This session is end-to-end encrypted. Enter the e2e password to unlock — it is never sent to the cloud.', p: 'E2E password', u: 'Unlock', bad: 'Wrong password — cannot decrypt.',
            save: 'Remember on this device', stale: 'The saved password no longer works (it may have been changed). Enter it again.' }
      // Remembered password lives in localStorage, per public host AND per
      // device, on THIS browser only — never transmitted (E2E is intact).
      // The device part matters on a multi-device subdomain: each machine
      // has its own e2e password, and one saved copy must not clobber (or be
      // probed against) another device's. Keyed by host+device (not salt) so
      // a changed e2e password is detected and re-prompted. The old
      // host-only key is read once as a fallback and migrated on success.
      const LEGACY_KEY = 'dshn:e2e:' + location.hostname
      const STORE_KEY = LEGACY_KEY + (deviceKey ? ':' + deviceKey : '')
      const readSaved = () => {
        try { return localStorage.getItem(STORE_KEY) || (STORE_KEY !== LEGACY_KEY ? localStorage.getItem(LEGACY_KEY) : null) } catch { return null }
      }
      const writeSaved = (v) => {
        try {
          if (v == null) localStorage.removeItem(STORE_KEY); else localStorage.setItem(STORE_KEY, v)
          if (STORE_KEY !== LEGACY_KEY) localStorage.removeItem(LEGACY_KEY)
        } catch { /* storage may be blocked */ }
      }

      // Derive from a password string and probe /api with a sealed body; on a
      // correct key set the live key and return true. A wrong key → agent 400
      // (or the response fails to open), so return false.
      const attempt = async (pwStr) => {
        try {
          const cand = await deriveKey(pwStr, salt)
          const iv = crypto.getRandomValues(new Uint8Array(12))
          const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cand, enc.encode('{}')))
          const probeBody = new Uint8Array(iv.length + ct.length); probeBody.set(iv); probeBody.set(ct, iv.length)
          const r = await realFetch('/api/host.describe', { method: 'POST', headers: { [E2E_HEADER]: '1', 'content-type': 'application/json' }, body: probeBody, credentials: 'include' })
          if (r.status === 400) return false
          if (r.headers.get(E2E_HEADER) === '1') { await openBytes(cand, new Uint8Array(await r.arrayBuffer())) }
          key = cand
          return true
        } catch { return false }
      }

      ;(async () => {
        // 1. A remembered password unlocks silently — the gate never appears.
        let stale = false
        const saved = readSaved()
        if (saved) {
          if (await attempt(saved)) {
            writeSaved(saved) // re-write so a legacy host-only entry migrates to the per-device key
            window.__dshnE2E.autounlock = true; resolve(); return
          }
          writeSaved(null); stale = true // the saved one no longer works → drop it and tell the user
        }

        // 2. Otherwise show the unlock gate, themed with dsh's own tokens so it
        // matches the app (light/dark aware; dark fallbacks if vars are absent).
        const V = {
          mask: 'var(--dsw-alias-bg-mask-1, rgba(8,10,14,.55))', blur: 'var(--dsw-mask-blur, blur(4px))',
          card: 'var(--dsw-alias-bg-layer-2, #171a1f)', fg: 'var(--dsw-alias-label-primary, #e8eaed)',
          sub: 'var(--dsw-alias-label-tertiary, #9aa0aa)', bd: 'var(--dsw-alias-border-l1, rgba(128,134,142,.35))',
          shadow: 'var(--dsw-shadow-lv3, 0 24px 64px rgba(0,0,0,.5))',
          accent: 'var(--dsw-alias-button-primary-fill, #4176e6)', accentFg: 'var(--dsw-alias-label-primary-foreground, #fff)',
          err: 'var(--dsw-alias-state-error-primary, #e5484d)', warn: 'var(--dsw-alias-state-warn-primary, #d98324)',
          focus: 'var(--dsw-alias-label-primary-bluish, #4176e6)',
        }
        const ov = document.createElement('div')
        ov.setAttribute('style', 'position:fixed;inset:0;z-index:2147483000;display:grid;place-items:center;background:' + V.mask + ';backdrop-filter:' + V.blur + ';font-family:var(--dsw-font-family, system-ui, -apple-system, sans-serif)')
        ov.innerHTML =
          '<form style="width:min(360px,92vw);box-sizing:border-box;padding:22px;border-radius:16px;background:' + V.card + ';color:' + V.fg + ';border:1px solid ' + V.bd + ';box-shadow:' + V.shadow + '">'
          + '<div style="font-size:15px;font-weight:600;margin-bottom:6px">🔒 ' + L.t + '</div>'
          + '<div style="font-size:12.5px;color:' + V.sub + ';margin-bottom:16px;line-height:1.5">' + L.s + '</div>'
          + '<div id="dshn-e2e-err" style="display:none;font-size:12px;margin-bottom:10px;line-height:1.5"></div>'
          + '<input id="dshn-e2e-pw" type="password" placeholder="' + L.p + '" autocomplete="off" style="width:100%;box-sizing:border-box;padding:10px 12px;border-radius:10px;border:1px solid ' + V.bd + ';background:transparent;color:inherit;font-size:14.5px;outline:none">'
          + '<label style="display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12.5px;color:' + V.sub + ';cursor:pointer;user-select:none">'
          + '<input id="dshn-e2e-remember" type="checkbox" checked style="width:15px;height:15px;margin:0;accent-color:' + V.accent + ';cursor:pointer">' + L.save + '</label>'
          + '<button type="submit" style="width:100%;margin-top:16px;padding:10px;border:0;border-radius:10px;background:' + V.accent + ';color:' + V.accentFg + ';font-size:14.5px;font-weight:500;cursor:pointer">' + L.u + '</button></form>'
        const mount = () => document.body.appendChild(ov)
        if (document.body) mount(); else document.addEventListener('DOMContentLoaded', mount)
        const form = ov.querySelector('form'), pw = ov.querySelector('#dshn-e2e-pw'), err = ov.querySelector('#dshn-e2e-err'), remember = ov.querySelector('#dshn-e2e-remember')
        pw.addEventListener('focus', () => { pw.style.borderColor = V.focus })
        pw.addEventListener('blur', () => { pw.style.borderColor = V.bd })
        const showErr = (msg, color) => { err.textContent = msg; err.style.color = color; err.style.display = 'block' }
        if (stale) showErr(L.stale, V.warn) // the "saved password no longer works" notice
        form.addEventListener('submit', async (e) => {
          e.preventDefault()
          const btn = form.querySelector('button'); btn.disabled = true
          if (await attempt(pw.value)) {
            writeSaved(remember.checked ? pw.value : null)
            ov.remove()
            resolve()
          } else { showErr(L.bad, V.err); btn.disabled = false; pw.select() }
        })
        setTimeout(() => pw.focus(), 50)
      })()
    })
  }
`

/** What the injected script needs to know. */
export interface E2EBootstrapInfo {
  /** Hex salt browsers derive the key from. */
  salt: string
  /** The agent's device id (keys the remembered password per device). */
  device: string
}

/** The `<script>` tag to inject into an HTML document's head. */
export function e2eBootstrapTag(info: E2EBootstrapInfo): string {
  // `</script>` / `<!--` cannot appear in a JSON of hex + [a-z0-9] strings, but
  // escape `<` regardless so the payload can never close the tag.
  const json = JSON.stringify({ salt: info.salt, device: info.device }).replace(/</g, '\\u003c')
  return `<script>(function (__dshnInfo) {${SHIM_BODY}})(${json})</script>`
}

/**
 * Insert the bootstrap tag as the first thing inside `<head>` (or `<html>`, or
 * at the very start when neither is present), so it runs before any script the
 * document itself carries.
 */
export function injectE2EBootstrap(html: string, info: E2EBootstrapInfo): string {
  const tag = e2eBootstrapTag(info)
  const head = /<head(\s[^>]*)?>/i.exec(html)
  if (head !== null) return html.slice(0, head.index + head[0].length) + tag + html.slice(head.index + head[0].length)
  const root = /<html(\s[^>]*)?>/i.exec(html)
  if (root !== null) return html.slice(0, root.index + root[0].length) + tag + html.slice(root.index + root[0].length)
  return tag + html
}
