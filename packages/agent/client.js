// Browser half of dshn-agent, hand-authored in the factory format
// dsh-client-modules serves (the same shape tsdown emits, no build step).
//
// ONE panel does everything (the "connection control"):
//  - No saved credentials → registration: subdomain + password + confirm +
//    strength meter, to claim a fresh subdomain. Pops up as a prominent modal
//    the first time an unconfigured dsh is opened locally.
//  - Saved credentials → the same panel pre-filled with the previous subdomain
//    and password, as a connect/reconnect control (no confirm — not a claim).
// The saved password is always one click to copy (the cloud keeps only a hash;
// this local copy is the only recovery). A bottom-left pill reflects status and
// opens the panel; the panel has an explicit ✕ to close.
window.__ModuleLoader__.load({
  id: '@dshn/agent',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })
    const react = require('react')
    const h = react.createElement

    const ID = 'dshn'
    const POLL_MS = 2500
    const MIN_PW = 8
    const E2E_HEADER = 'x-dshn-e2e'
    const E2E_PUB_PATH = '/dshn-e2e'
    const E2E_ITERS = 210000

    // ── end-to-end decryption shim ────────────────────────────────────────────
    // Runs only when the page is opened THROUGH the tunnel (a public host, not
    // loopback) and the agent reports E2E on. It patches fetch + WebSocket so
    // /api request bodies are sealed and responses / event messages are decrypted
    // with a key derived from an e2e password the visitor types — a password that
    // never reaches the relay. dsh's own traffic is gated until that key is ready.
    ;(function installE2E() {
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
          this._seal = active && isApi(String(url))
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
          if (this._seal) {
            await ready
            if (key) {
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

      // Discover E2E state, then (if on) show the unlock gate and derive the key.
      // If E2E is OFF (the default), restore the native fetch/WebSocket entirely
      // so nothing here sits in the normal path — the feature is truly opt-in.
      ;(async () => {
        try {
          window.__dshnE2E.stage = 'checking'
          const info = await realFetch(E2E_PUB_PATH, { cache: 'no-store' }).then((r) => r.json())
          window.__dshnE2E.stage = 'checked'; window.__dshnE2E.enabled = info && info.enabled
          if (!info || !info.enabled || !info.salt) { window.fetch = realFetch; window.WebSocket = RealWS; window.__dshnE2E.stage = 'off-restored'; resolveReady(); return }
          active = true
          window.__dshnE2E.stage = 'gating'
          await unlockGate(info.salt, info.device)
          window.__dshnE2E.stage = 'unlocked'
        } catch (e) { window.fetch = realFetch; window.WebSocket = RealWS; window.__dshnE2E.stage = 'error'; window.__dshnE2E.error = String(e && e.message || e) }
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
    })()

    const CSS = `
.dshn-root.dshn-root { position: fixed; left: 12px; bottom: 12px; z-index: 40;
  font-size: 12px; line-height: 1.4; color: var(--dsw-alias-label-primary, #1c1e21); pointer-events: auto; }
.dshn-pill { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px;
  border: 1px solid var(--dsw-alias-border-l1, rgba(128,134,142,.3)); border-radius: 999px;
  background: var(--dsw-alias-bg-layer-2, #f4f5f7); cursor: pointer; user-select: none; }
.dshn-pill svg { display: block; }
/* A full-width footer row that mirrors dsh's own "设置" entry (42px, 16px icon,
   8px gap, radius 12px), sitting directly above it: globe + label on the left,
   the live latency (or connection state) as a muted mono value on the right. */
.dshn-frow { display: flex; flex-direction: row; align-items: center; gap: 8px; flex: 1 1 auto; box-sizing: border-box;
  height: 42px; margin: 2px -2px 0; padding: 0 10px 0 8px; border: 0; border-radius: 12px; background: transparent; cursor: pointer;
  color: var(--dsw-alias-label-primary, #1c1e21); font-size: 14px; font-weight: 400; text-align: left; }
.dshn-frow:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(128,134,142,.12)); }
.dshn-frow svg { display: block; }
.dshn-frow-ic { display: inline-flex; flex: 0 0 auto; }
.dshn-frow-label { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dshn-frow-trail { flex: 0 0 auto; font-size: 11px; line-height: 1; font-variant-numeric: tabular-nums; font-family: ui-monospace, Menlo, monospace; }
.dshn-section { max-width: 460px; }
.dshn-section-intro { color: var(--dsw-alias-label-tertiary, #8b9099); font-size: 12.5px; margin-bottom: 16px; line-height: 1.5; }
.dshn-panel[data-mode="section"] { border: 0; box-shadow: none; width: 100%; padding: 0; background: transparent; }
.dshn-pill-lat { display: inline-flex; align-items: center; gap: 5px; font-variant-numeric: tabular-nums; }
.dshn-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; background: var(--dsw-alias-label-tertiary, #8b9099); }
.dshn-dot[data-on="1"] { background: var(--dsw-alias-state-success-primary, #3aa675); }
.dshn-dot[data-warn="1"] { background: var(--dsw-alias-state-warn-primary, #d98324); }
.dshn-dot[data-err="1"] { background: var(--dsw-alias-state-error-primary, #e5484d); }

.dshn-backdrop { position: fixed; inset: 0; z-index: 60; display: grid; place-items: center;
  background: rgba(8,10,14,.52); backdrop-filter: blur(2px); }
.dshn-panel { box-sizing: border-box; border-radius: 13px; background: var(--dsw-alias-bg-layer-3, #fff);
  border: 1px solid var(--dsw-alias-border-l1, rgba(128,134,142,.25)); }
.dshn-panel[data-mode="modal"] { width: min(400px, 92vw); padding: 20px 22px 18px; box-shadow: 0 24px 64px rgba(0,0,0,.34); }
.dshn-panel[data-mode="card"] { width: 308px; margin-top: 8px; padding: 14px 15px 13px; box-shadow: 0 8px 24px rgba(0,0,0,.16); }
.dshn-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; margin-bottom: 9px; }
.dshn-htitle { font-size: 14.5px; font-weight: 650; }
.dshn-hsub { color: var(--dsw-alias-label-tertiary, #8b9099); font-size: 11.5px; margin-top: 2px; }
.dshn-x { border: 0; background: transparent; cursor: pointer; font-size: 17px; line-height: 1; padding: 2px 4px;
  color: var(--dsw-alias-label-tertiary, #8b9099); flex: none; }
.dshn-x:hover { color: var(--dsw-alias-label-primary, #1c1e21); }

.dshn-status { display: flex; align-items: center; gap: 7px; margin-bottom: 11px; font-size: 12px; }
.dshn-url { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.dshn-addr { display: flex; align-items: center; gap: 6px; margin-bottom: 8px; padding: 6px 8px 6px 11px;
  border: 1px solid var(--dsw-alias-border-l2, rgba(128,134,142,.25)); border-radius: 10px;
  background: var(--dsw-alias-bg-layer-2, #f4f5f7); }
.dshn-addr-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; background: var(--dsw-alias-label-tertiary, #8b9099); }
.dshn-addr-dot[data-on="1"] { background: var(--dsw-alias-state-success-primary, #3aa675); box-shadow: 0 0 0 3px color-mix(in srgb, var(--dsw-alias-state-success-primary, #3aa675) 20%, transparent); }
.dshn-addr-url { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; }
.dshn-addr-scheme { color: var(--dsw-alias-label-tertiary, #8b9099); }
.dshn-addr-host { color: var(--dsw-alias-label-primary, #1c1e21); font-weight: 500; }
.dshn-addr-btn { display: inline-flex; align-items: center; justify-content: center; flex: none;
  width: 26px; height: 26px; border: 0; border-radius: 7px; background: transparent; cursor: pointer;
  color: var(--dsw-alias-label-tertiary, #8b9099); text-decoration: none; }
.dshn-addr-btn:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(128,134,142,.16)); color: var(--dsw-alias-label-primary, #1c1e21); }

.dshn-field { display: block; margin-bottom: 7px; }
.dshn-field > span { display: block; color: var(--dsw-alias-label-tertiary, #8b9099); font-size: 11px; margin-bottom: 3px; }
.dshn-prefixwrap { display: flex; align-items: stretch; }
.dshn-input { width: 100%; box-sizing: border-box; padding: 6px 10px; font-size: 13.5px;
  border: 1px solid var(--dsw-alias-border-l1, rgba(128,134,142,.35)); border-radius: 8px; background: transparent; color: inherit; }
.dshn-input:focus { outline: 2px solid var(--dsw-alias-label-primary-bluish, #4176e6); outline-offset: -1px; }
.dshn-input[data-bad="1"] { border-color: var(--dsw-alias-state-error-primary, #e5484d); }
.dshn-prefixwrap .dshn-input { border-radius: 8px 0 0 8px; }
.dshn-apex { display: flex; align-items: center; padding: 0 10px; font-size: 12.5px; color: var(--dsw-alias-label-tertiary, #8b9099);
  white-space: nowrap; border: 1px solid var(--dsw-alias-border-l1, rgba(128,134,142,.35)); border-left: 0; border-radius: 0 8px 8px 0;
  background: var(--dsw-alias-bg-layer-2, #f4f5f7); font-family: ui-monospace, Menlo, monospace; }
.dshn-pwwrap { position: relative; display: flex; align-items: stretch; }
.dshn-pwwrap .dshn-input { padding-right: 84px; }
.dshn-pwbtns { position: absolute; right: 6px; top: 50%; transform: translateY(-50%); display: flex; gap: 2px; }
.dshn-mini { border: 0; background: transparent; cursor: pointer; font-size: 11px; padding: 3px 5px; border-radius: 5px;
  color: var(--dsw-alias-label-tertiary, #8b9099); }
.dshn-mini:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(128,134,142,.14)); color: var(--dsw-alias-label-primary, #1c1e21); }
.dshn-meter { height: 5px; border-radius: 3px; margin-top: 6px; background: var(--dsw-alias-border-l3, rgba(128,134,142,.25)); overflow: hidden; }
.dshn-meter > i { display: block; height: 100%; width: 0; transition: width .18s ease, background .18s ease; }
.dshn-strength { font-size: 10.5px; margin-top: 3px; }

.dshn-actions { display: flex; gap: 8px; align-items: center; margin-top: 3px; }
.dshn-primary { flex: 1; padding: 7px; border: 0; border-radius: 8px; cursor: pointer; background: #4176e6; color: #fff; font-size: 13.5px; }
.dshn-primary:disabled { opacity: .5; cursor: default; }
.dshn-ghost { border: 0; background: transparent; cursor: pointer; color: var(--dsw-alias-label-tertiary, #8b9099); font-size: 12.5px; padding: 7px 8px; }
.dshn-err { color: var(--dsw-alias-state-error-primary, #e5484d); font-size: 11.5px; margin-bottom: 9px; }
.dshn-hint { color: var(--dsw-alias-label-tertiary, #8b9099); font-size: 10.5px; margin-top: 3px; }
.dshn-note { color: var(--dsw-alias-state-warn-primary, #d98324); font-size: 10.5px; margin: 2px 0 8px; }
.dshn-modeseg { display: flex; gap: 4px; padding: 2px; border-radius: 9px; background: var(--dsw-alias-bg-layer-2, #f4f5f7);
  border: 1px solid var(--dsw-alias-border-l2, rgba(128,134,142,.22)); }
.dshn-modebtn { flex: 1; padding: 5px 10px; border: 0; border-radius: 6px; cursor: pointer; font-size: 12.5px; font-family: inherit;
  background: transparent; color: var(--dsw-alias-label-secondary, #4a4f57); }
.dshn-modebtn.dshn-on { background: var(--dsw-alias-bg-layer-1, #fff); color: var(--dsw-alias-label-primary, #1c1e21);
  box-shadow: 0 1px 2px rgba(0,0,0,.08); }
.dshn-ca { min-height: 46px; resize: vertical; font-family: ui-monospace, Menlo, monospace; font-size: 11px; line-height: 1.4; }
.dshn-catoggle { border: 0; background: transparent; cursor: pointer; padding: 2px 0; font-size: 11px; font-family: inherit;
  color: var(--dsw-alias-label-tertiary, #8b9099); }
.dshn-catoggle:hover { color: var(--dsw-alias-label-primary, #1c1e21); }
.dshn-e2e-box { margin: 2px 0 8px; padding: 9px 11px; border-radius: 10px;
  border: 1px solid var(--dsw-alias-border-l2, rgba(128,134,142,.25)); background: var(--dsw-alias-bg-layer-2, #f4f5f7); }
.dshn-e2e-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px;
  color: var(--dsw-alias-label-tertiary, #8b9099); font-size: 11px; }
.dshn-e2e-actions { display: flex; gap: 8px; align-items: center; margin-top: 7px; }
.dshn-btn-sm { padding: 6px 12px; border: 0; border-radius: 7px; cursor: pointer; font-size: 12px;
  background: #4176e6; color: #fff; }
.dshn-btn-sm:disabled { opacity: .5; cursor: default; }
.dshn-btn-warn { background: transparent; color: var(--dsw-alias-state-error-primary, #e5484d);
  border: 1px solid var(--dsw-alias-border-l1, rgba(128,134,142,.3)); }
.dshn-btn-warn:hover:not(:disabled) { background: color-mix(in srgb, var(--dsw-alias-state-error-primary, #e5484d) 10%, transparent); }
.dshn-info { border: 1px solid var(--dsw-alias-border-l2, rgba(128,134,142,.22)); border-radius: 9px;
  padding: 6px 10px; margin-bottom: 8px; }
.dshn-info-row { display: flex; justify-content: space-between; align-items: center; gap: 10px; font-size: 11.5px; padding: 1.5px 0; }
.dshn-info-k { display: inline-flex; align-items: center; gap: 7px; color: var(--dsw-alias-label-tertiary, #8b9099); }
.dshn-info-k svg { flex: none; opacity: .85; }
.dshn-info-v { font-family: ui-monospace, Menlo, monospace; text-align: right; font-variant-numeric: tabular-nums; }
.dshn-dcwarn { border: 1px solid var(--dsw-alias-state-error-primary, #e5484d); background: rgba(229,72,77,.08);
  border-radius: 9px; padding: 8px 10px; margin-bottom: 8px; }
.dshn-dcwarn-title { font-weight: 640; font-size: 12.5px; margin-bottom: 3px; }
.dshn-dcwarn-body { font-size: 11.5px; color: var(--dsw-alias-label-secondary, #4a4f57); }
.dshn-danger { flex: 1; padding: 7px; border: 0; border-radius: 8px; cursor: pointer;
  background: var(--dsw-alias-state-error-primary, #e5484d); color: #fff; font-size: 13px; }

/* Multi-device switcher (remote pages only): a footer row like the local one,
   opening a small fixed popover above it listing this subdomain's devices. */
.dshn-devpop { position: fixed; left: 12px; bottom: 56px; z-index: 70; width: 244px;
  box-sizing: border-box; padding: 10px 10px 8px; border-radius: 12px;
  background: var(--dsw-alias-bg-layer-3, #fff);
  border: 1px solid var(--dsw-alias-border-l1, rgba(128,134,142,.25));
  box-shadow: var(--dsw-shadow-lv3, 0 12px 32px rgba(0,0,0,.24)); }
.dshn-devpop-title { font-size: 11px; color: var(--dsw-alias-label-tertiary, #8b9099); margin: 0 4px 6px; }
.dshn-devrow { display: flex; align-items: center; gap: 8px; width: 100%; box-sizing: border-box;
  padding: 8px 9px; border: 0; border-radius: 8px; background: transparent; cursor: pointer; text-align: left;
  color: var(--dsw-alias-label-primary, #1c1e21); font-size: 13px; font-family: inherit; }
.dshn-devrow:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover, rgba(128,134,142,.12)); }
.dshn-devrow:disabled { cursor: default; opacity: .6; }
.dshn-devrow-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dshn-devrow-tag { font-size: 10.5px; color: var(--dsw-alias-label-tertiary, #8b9099); }
`
    const cssId = ID + '/widget.css'
    if (typeof document !== 'undefined'
      && document.querySelector('style[data-plugin-css=' + JSON.stringify(cssId) + ']') === null) {
      const tag = document.createElement('style')
      tag.dataset.plugin = ID; tag.dataset.pluginCss = cssId; tag.textContent = CSS
      document.head.appendChild(tag)
    }

    const zh = String(document.documentElement.lang || navigator.language || 'en').toLowerCase().indexOf('zh') === 0
    const T = zh
      ? { brand: '公网转发 · ds.hn', connecting: '连接中…', live: '已上线', off: '未连接', notset: '未配置',
          setupTitle: '开启公网转发', setupSub: '设置域名前缀和访问密码——这两项就是你的凭据。',
          connTitle: '公网转发', prefix: '域名前缀', password: '访问密码', confirm: '再次输入密码',
          connect: '连接', reconnect: '重新连接', connecting2: '连接中…', later: '稍后', disconnect: '断开并重设',
          show: '显示', hide: '隐藏', copy: '复制', copied: '已复制', mismatch: '两次输入的密码不一致。',
          prefixHint: '只能小写字母、数字、连字符，4–32 位。',
          pwHint: '至少 8 位。云端只存哈希、无法找回，请记牢或用密码管理器保存。',
          recoverNote: '⚠ 云端不保存明文密码、也无法找回，请务必自行保存。',
          savedHint: '手机访问用这个密码登录。忘记时点“复制/显示”取回。',
          weak: '弱', fair: '一般', good: '较强', strong: '强',
          infoRelay: '线路', infoMode: { direct: '直连源站', cloudflare: '经 Cloudflare' },
          routePremium: '高级线路（加速）', routeStandard: '标准线路',
          infoUptime: '在线时长', infoServed: '已转发请求', infoPort: '本地端口', infoLatency: '延迟', infoDevice: '设备名',
          e2eLabel: '端到端密码（可选）', e2eHint: '设置后，会话内容用它加密，云端也看不到；密码不出本机。访问时需在网页再输一次。',
          e2eApply: '设置端到端密码', e2eUpdate: '更新端到端密码', e2eDisable: '关闭加密', e2eApplied: '✓ 端到端加密已开启', e2eOff2: '✓ 端到端加密已关闭', e2eIndep: '独立设置，不影响上面的连接。',
          infoE2E: '端到端加密', e2eOn: '已开启', e2eOff: '未开启',
          navLabel: '公网转发', sectionIntro: '把本机的 dsh 转发到公网。前缀 + 访问密码即凭据；可选设置端到端密码进一步加密内容。',
          localOnly: '公网转发的配置只能在本机（打开 dsh 的这台机器）进行。', loading: '加载中…',
          openSettings: '打开设置', open: '打开', addrLabel: '公网地址',
          dcTitle: '确认断开公网转发？', dcWarn: '断开会立即切断公网访问。云端不保存你的密码、无法找回；若你没有另存密码，之后可能无法用同一前缀重新连接。',
          dcConfirm: '确认断开', dcCancel: '取消', dcCopyFirst: '先复制密码',
          mode: '模式', modeOfficial: '官方 ds.hn', modeSelf: '自托管', yourDomain: '你的域名', relayHost: '中继地址',
          relayHostHint: '填你自己的 @dshn/relay,如 wss://tunnel.example.com。子域会挂在它的域名下。',
          relayCa: '中继证书(自签名,可选)',
          relayCaHint: '仅当你的中继用自签名证书时:粘贴其 PEM 证书以固定信任(公有证书/套 Cloudflare 时留空)。',
          devLabel: '设备', devSwitch: '切换设备', devOffline: '离线', devCurrent: '当前' }
      : { brand: 'Public forwarding · ds.hn', connecting: 'connecting…', live: 'live', off: 'off', notset: 'not set up',
          setupTitle: 'Set up public forwarding', setupSub: 'Pick a subdomain prefix and an access password — the two are your credential.',
          connTitle: 'Public forwarding', prefix: 'Subdomain prefix', password: 'Access password', confirm: 'Confirm password',
          connect: 'Connect', reconnect: 'Reconnect', connecting2: 'Connecting…', later: 'Later', disconnect: 'Disconnect & reset',
          show: 'show', hide: 'hide', copy: 'copy', copied: 'copied', mismatch: 'Passwords do not match.',
          prefixHint: 'Lowercase letters, digits, hyphens — 4–32 chars.',
          pwHint: 'At least 8 characters. The cloud stores only a hash — no recovery, so save it.',
          recoverNote: '⚠ The cloud never stores your password and cannot recover it — save it yourself.',
          savedHint: 'Log in from a phone with this password. Copy/show it here if you forget.',
          weak: 'weak', fair: 'fair', good: 'good', strong: 'strong',
          infoRelay: 'Link', infoMode: { direct: 'direct to origin', cloudflare: 'via Cloudflare' },
          routePremium: 'premium route (accelerated)', routeStandard: 'standard route',
          infoUptime: 'Uptime', infoServed: 'Requests served', infoPort: 'Local port', infoLatency: 'Latency', infoDevice: 'Device name',
          e2eLabel: 'End-to-end password (optional)', e2eHint: 'If set, session content is encrypted with it — even the cloud cannot read it, and it never leaves this machine. Visitors enter it again in the browser.',
          e2eApply: 'Set e2e password', e2eUpdate: 'Update e2e password', e2eDisable: 'Turn off', e2eApplied: '✓ End-to-end encryption on', e2eOff2: '✓ End-to-end encryption off', e2eIndep: 'Applied on its own — does not affect the connection above.',
          infoE2E: 'End-to-end encryption', e2eOn: 'on', e2eOff: 'off',
          navLabel: 'Public forwarding', sectionIntro: 'Forward this machine’s dsh to the public internet. The subdomain + access password are your credential; an optional end-to-end password further encrypts the content.',
          localOnly: 'Public-forwarding settings can only be changed on this machine (where dsh is running).', loading: 'Loading…',
          openSettings: 'open settings', open: 'open', addrLabel: 'Public address',
          dcTitle: 'Disconnect public forwarding?', dcWarn: 'This immediately cuts off public access. The cloud does not store your password and cannot recover it — if you have not saved it elsewhere, you may not be able to reconnect with the same prefix.',
          dcConfirm: 'Disconnect', dcCancel: 'Cancel', dcCopyFirst: 'Copy password first',
          mode: 'Mode', modeOfficial: 'Official ds.hn', modeSelf: 'Self-hosted', yourDomain: 'your-domain', relayHost: 'Relay host',
          relayHostHint: 'Your own @dshn/relay, e.g. wss://tunnel.example.com. Your subdomain lives under its domain.',
          relayCa: 'Relay CA (self-signed, optional)',
          relayCaHint: 'Only when your relay uses a self-signed cert: paste its PEM to pin trust (leave blank for a public cert / behind Cloudflare).',
          devLabel: 'Device', devSwitch: 'Switch device', devOffline: 'offline', devCurrent: 'current' }

    function strength(pw) {
      if (pw.length < MIN_PW) return { score: 0, ok: false }
      let s = 1
      if (pw.length >= 12) s++
      const classes = (/[a-z]/.test(pw) ? 1 : 0) + (/[A-Z]/.test(pw) ? 1 : 0) + (/\d/.test(pw) ? 1 : 0) + (/[^a-zA-Z0-9]/.test(pw) ? 1 : 0)
      if (classes >= 2) s++
      if (classes >= 3 && pw.length >= 10) s++
      return { score: Math.min(s, 4), ok: s >= 2 }
    }
    const SC = ['#e5484d', '#e5484d', '#d98324', '#3aa675', '#3aa675']
    const slabel = (n) => [T.weak, T.weak, T.fair, T.good, T.strong][n]

    // ── inline line-icons (no external assets; inherit currentColor) ──────────
    const SVG = { width: 13, height: 13, viewBox: '0 0 14 14', fill: 'none', stroke: 'currentColor',
      strokeWidth: 1.4, strokeLinecap: 'round', strokeLinejoin: 'round' }
    const P = (d) => h('path', { key: d, d })
    const ICONS = {
      globe: () => [h('circle', { key: 'c', cx: 7, cy: 7, r: 5.3 }), P('M1.7 7h10.6'),
        P('M7 1.7c2.3 2.3 2.3 8.3 0 10.6'), P('M7 1.7c-2.3 2.3-2.3 8.3 0 10.6')],
      cloud: () => [P('M4.4 10.6a2.6 2.6 0 01.2-5.2 3.4 3.4 0 016.5.9 2.2 2.2 0 01-.4 4.3z')],
      plug: () => [P('M5 2.3v2.2M9 2.3v2.2'), P('M4 4.6h6v1.9a3 3 0 01-6 0z'), P('M7 9.4v2.3')],
      bolt: () => [P('M7.6 1.8L3.3 7.8h3.1l-.8 4.4 4.3-6h-3.1z')],
      gauge: () => [P('M2.2 10.4a5 5 0 019.6 0'), P('M7 10.4l2.4-2.7'), h('circle', { key: 'd', cx: 7, cy: 10.4, r: .5, fill: 'currentColor' })],
      clock: () => [h('circle', { key: 'c', cx: 7, cy: 7, r: 5.3 }), P('M7 4.1v3.1l2 1.2')],
      swap: () => [P('M3.4 5h7.2l-2-2'), P('M10.6 9H3.4l2 2')],
      server: () => [h('rect', { key: 'a', x: 2.3, y: 2.4, width: 9.4, height: 3.7, rx: 1 }),
        h('rect', { key: 'b', x: 2.3, y: 7.4, width: 9.4, height: 3.7, rx: 1 }),
        P('M4.4 4.25h.01'), P('M4.4 9.25h.01')],
      lock: () => [h('rect', { key: 'a', x: 2.8, y: 6.3, width: 8.4, height: 5.4, rx: 1.2 }), P('M4.7 6.3V4.6a2.3 2.3 0 014.6 0v1.7')],
      unlock: () => [h('rect', { key: 'a', x: 2.8, y: 6.3, width: 8.4, height: 5.4, rx: 1.2 }), P('M4.7 6.3V4.6a2.3 2.3 0 014.5-.5')],
      external: () => [P('M8 2.6h3.4V6'), P('M11.4 2.6L6.4 7.6'), P('M9.6 8.4v2.2a1 1 0 01-1 1H3.4a1 1 0 01-1-1V5.4a1 1 0 011-1h2.2')],
      copy: () => [h('rect', { key: 'a', x: 4.6, y: 4.6, width: 6.8, height: 6.8, rx: 1.3 }), P('M9.4 4.6V3.4a1 1 0 00-1-1H3.4a1 1 0 00-1 1v5a1 1 0 001 1h1.2')],
    }
    const Icon = (name, extra) => h('svg', Object.assign({}, SVG, extra), ICONS[name]())

    function latColor(ms) { return ms == null ? 'var(--dsw-alias-label-tertiary, #8b9099)' : ms <= 90 ? '#3aa675' : ms <= 200 ? '#d98324' : '#e5484d' }

    // Signal-strength bars, lit count + colour from latency; shown on the pill.
    function SignalBars(props) {
      const lit = props.ms == null ? 0 : props.ms <= 45 ? 4 : props.ms <= 90 ? 3 : props.ms <= 200 ? 2 : 1
      const hs = [4, 6.5, 9, 11.5]
      return h('svg', { width: 15, height: 13, viewBox: '0 0 15 13' },
        hs.map((hh, i) => h('rect', { key: i, x: 0.5 + i * 3.6, y: 12.5 - hh, width: 2.4, height: hh, rx: .7,
          fill: i < lit ? props.color : 'var(--dsw-alias-label-tertiary, #8b9099)', opacity: i < lit ? 1 : .28 })))
    }

    function uptime(since) {
      if (!since) return '—'
      let s = Math.max(0, Math.floor((Date.now() - since) / 1000))
      const d = Math.floor(s / 86400); s -= d * 86400
      const hh = Math.floor(s / 3600); s -= hh * 3600
      const mm = Math.floor(s / 60); s -= mm * 60
      if (d > 0) return `${d}d ${hh}h`
      if (hh > 0) return `${hh}h ${mm}m`
      if (mm > 0) return `${mm}m ${s}s`
      return `${s}s`
    }

    // The one panel. `mode` is 'modal' or 'card' (styling + which dismiss it shows).
    function Panel(props) {
      const s = props.status
      const configured = s.configured
      const [prefix, setPrefix] = react.useState(configured ? (s.subdomain || '') : '')
      const [pw, setPw] = react.useState(configured ? (s.password || '') : '')
      const [confirm, setConfirm] = react.useState('')
      const [showPw, setShowPw] = react.useState(false)
      const [busy, setBusy] = react.useState(false)
      const [err, setErr] = react.useState('')
      const [copied, setCopied] = react.useState('')
      const [confirmDc, setConfirmDc] = react.useState(false)
      const [e2e, setE2e] = react.useState(configured ? (s.e2ePassword || '') : '')
      const [e2eBusy, setE2eBusy] = react.useState(false)
      const [e2eErr, setE2eErr] = react.useState('')
      const [e2eMsg, setE2eMsg] = react.useState('')
      // Mode: 'official' (ds.hn) vs 'selfhost' (your own @dshn/relay). Both share
      // the subdomain + password + e2e; self-hosted just adds the relay location.
      const rs0 = s.relaySettings || {}
      const [mode, setMode] = react.useState(rs0.relayHost ? 'selfhost' : 'official')
      const [relayHost, setRelayHost] = react.useState(rs0.relayHost || '')
      const [originCa, setOriginCa] = react.useState(rs0.originCa || '')
      // The self-signed CA is rarely needed (valid cert / Cloudflare cover most);
      // hidden behind a toggle, auto-shown only if one is already saved.
      const [showCa, setShowCa] = react.useState(!!rs0.originCa)

      // When the saved passwords arrive from a later status poll, fill them once.
      react.useEffect(() => {
        if (configured && s.password && pw === '') setPw(s.password)
      }, [s.password])
      react.useEffect(() => {
        if (configured && s.e2ePassword && e2e === '') setE2e(s.e2ePassword)
      }, [s.e2ePassword])
      // Fill the self-hosted relay fields once the saved settings arrive; auto-open
      // the advanced section when a custom relay is already configured.
      react.useEffect(() => {
        const rs = s.relaySettings
        if (!rs) return
        if (rs.relayHost && relayHost === '') { setRelayHost(rs.relayHost); setMode('selfhost') }
        if (rs.originCa && originCa === '') { setOriginCa(rs.originCa); setShowCa(true) }
      }, [s.relaySettings && s.relaySettings.relayHost])

      // The domain suffix reflects the self-hosted relay AS YOU TYPE it (a
      // client-side mirror of the server's apex derivation), so the preview shows
      // YOUR domain before connecting. Official mode → the server's apex (ds.hn).
      const apex = (() => {
        if (mode !== 'selfhost') return s.apex || 'ds.hn'
        const rh = relayHost.trim()
        if (rh === '') return T.yourDomain
        const bare = rh.replace(/^wss?:\/\//, '').replace(/:\d+$/, '').replace(/\/.*$/, '')
        const parts = bare.split('.')
        if (parts.length > 2 && (parts[0] === 'relay' || parts[0] === 'origin')) return parts.slice(1).join('.')
        return bare || T.yourDomain
      })()

      const copyText = (text, tag) => {
        if (!text || !navigator.clipboard) return
        navigator.clipboard.writeText(text).then(() => { setCopied(tag); setTimeout(() => setCopied(''), 1200) }).catch(() => {})
      }
      const copyPw = () => copyText(pw, 'pw')
      const disconnect = () => { fetch('/dshn/disconnect', { method: 'POST' }).catch(() => {}) }
      // Apply the e2e password on its own — a dedicated endpoint that never
      // touches the connection or the main credentials.
      const applyE2E = (value) => {
        setE2eBusy(true); setE2eErr(''); setE2eMsg('')
        fetch('/dshn/e2e', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ e2ePassword: value }) })
          .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
          .then(({ ok, j }) => { setE2eBusy(false); if (ok) setE2eMsg(j.enabled ? T.e2eApplied : T.e2eOff2); else setE2eErr((j && j.error) || 'failed') })
          .catch((e) => { setE2eBusy(false); setE2eErr(String(e)) })
      }

      const st = strength(pw)
      const matches = confirm === pw
      // First-time setup can also set the e2e password inline (optional), so the
      // whole thing is one flow. Once configured, e2e moves to its own dedicated
      // control below (its own apply button, independent of the connection).
      const e2eRegOk = configured || e2e.trim() === '' || e2e.trim().length >= MIN_PW
      const selfhostOk = mode !== 'selfhost' || relayHost.trim() !== ''
      const canSubmit = prefix.trim().length > 0 && !busy && e2eRegOk && selfhostOk
        && (configured ? pw.length >= MIN_PW : (st.ok && confirm.length > 0 && matches))

      const submit = () => {
        if (!canSubmit) return
        setBusy(true); setErr('')
        const e2eVal = e2e.trim()
        fetch('/dshn/configure', { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ subdomain: prefix.trim().toLowerCase(), password: pw,
            relayHost: mode === 'selfhost' ? relayHost.trim() : '', originCa: mode === 'selfhost' ? originCa.trim() : '' }) })
          .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
          .then(async ({ ok, j }) => {
            if (!ok) { setBusy(false); setErr((j && j.error) || 'failed'); return }
            // Same flow: if setting up for the first time and an e2e password was
            // entered, enable it now too — no separate trip to a second control.
            if (!configured && e2eVal !== '') {
              try { await fetch('/dshn/e2e', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ e2ePassword: e2eVal }) }) } catch { /* non-fatal: the tunnel is up; e2e can be set later */ }
            }
            setBusy(false)
            if (props.onClose) props.onClose()
          })
          .catch((e) => { setBusy(false); setErr(String(e)) })
      }

      const liveErr = err || (s.lastError && !s.connected ? s.lastError : '')

      return h('div', { className: 'dshn-panel', 'data-mode': props.mode },
        // In a settings section the nav label + intro already title the page, so
        // the panel's own header is dropped there.
        props.mode === 'section' ? null : h('div', { className: 'dshn-head' },
          h('div', null,
            h('div', { className: 'dshn-htitle' }, configured ? T.connTitle : T.setupTitle),
            h('div', { className: 'dshn-hsub' }, configured
              ? (s.connected ? T.live : T.connecting)
              : T.setupSub)),
          props.onClose ? h('button', { className: 'dshn-x', title: 'close', onClick: props.onClose }, '×') : null),

        configured && s.publicUrl ? (() => {
          const host = s.publicUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
          return h('div', { className: 'dshn-addr' },
            h('span', { className: 'dshn-addr-dot', 'data-on': s.connected ? '1' : '0' }),
            h('div', { className: 'dshn-addr-url' },
              h('span', { className: 'dshn-addr-scheme' }, 'https://'),
              h('span', { className: 'dshn-addr-host' }, host)),
            h('a', { className: 'dshn-addr-btn', href: s.publicUrl, target: '_blank', rel: 'noreferrer', title: T.open }, Icon('external', { width: 14, height: 14 })),
            h('button', { className: 'dshn-addr-btn', title: T.copy, onClick: () => copyText(s.publicUrl, 'url') }, copied === 'url' ? h('span', { style: { fontSize: '10px' } }, T.copied) : Icon('copy', { width: 14, height: 14 })))
        })() : null,

        configured && s.connected ? h('div', { className: 'dshn-info' },
          // The route is the operator's assignment (premium = accelerated path via
          // the tunnel's own hostname); the mode is how the default relay is reached.
          h('div', { className: 'dshn-info-row' },
            h('span', { className: 'dshn-info-k' }, Icon(s.route === 'premium' ? 'bolt' : s.mode === 'direct' ? 'plug' : 'cloud'), T.infoRelay),
            h('span', { className: 'dshn-info-v', style: s.route === 'premium' ? { color: '#c9930f' } : undefined },
              (s.route === 'premium' ? T.routePremium : s.route === 'standard' ? T.routeStandard + ' · ' + (T.infoMode[s.mode] || s.mode || '') : (T.infoMode[s.mode] || s.mode || ''))
              + (s.relayHost ? ' · ' + s.relayHost : ''))),
          h('div', { className: 'dshn-info-row' },
            h('span', { className: 'dshn-info-k' }, Icon('gauge'), T.infoLatency),
            h('span', { className: 'dshn-info-v', style: { color: latColor(s.latencyMs) } }, s.latencyMs == null ? '—' : s.latencyMs + ' ms')),
          h('div', { className: 'dshn-info-row' },
            h('span', { className: 'dshn-info-k' }, Icon('clock'), T.infoUptime),
            h('span', { className: 'dshn-info-v' }, uptime(s.connectedSince))),
          h('div', { className: 'dshn-info-row' },
            h('span', { className: 'dshn-info-k' }, Icon('swap'), T.infoServed),
            h('span', { className: 'dshn-info-v' }, String(s.served == null ? '—' : s.served))),
          s.localPort ? h('div', { className: 'dshn-info-row' },
            h('span', { className: 'dshn-info-k' }, Icon('server'), T.infoPort),
            h('span', { className: 'dshn-info-v' }, String(s.localPort))) : null,
          // How this machine shows up in the multi-device switcher when several
          // devices bind one subdomain.
          s.deviceName ? h('div', { className: 'dshn-info-row' },
            h('span', { className: 'dshn-info-k' }, Icon('server'), T.infoDevice),
            h('span', { className: 'dshn-info-v' }, s.deviceName)) : null,
          h('div', { className: 'dshn-info-row' },
            h('span', { className: 'dshn-info-k' }, Icon(s.e2eEnabled ? 'lock' : 'unlock'), T.infoE2E),
            h('span', { className: 'dshn-info-v', style: { color: s.e2eEnabled ? '#3aa675' : undefined } }, s.e2eEnabled ? T.e2eOn : T.e2eOff))) : null,

        liveErr ? h('div', { className: 'dshn-err' }, liveErr) : null,

        // While confirming a disconnect, hide the whole editable form (you're
        // leaving it) so the confirmation stays short and fully visible instead of
        // growing the panel past its container.
        confirmDc ? null : h(react.Fragment, null,

        // Mode: official ds.hn vs self-hosted. The subdomain + password + e2e
        // below are shared; self-hosted just adds where your own relay lives.
        h('div', { className: 'dshn-field' },
          h('span', null, T.mode),
          h('div', { className: 'dshn-modeseg' },
            h('button', { type: 'button', className: 'dshn-modebtn' + (mode === 'official' ? ' dshn-on' : ''), onClick: () => setMode('official') }, T.modeOfficial),
            h('button', { type: 'button', className: 'dshn-modebtn' + (mode === 'selfhost' ? ' dshn-on' : ''), onClick: () => setMode('selfhost') }, T.modeSelf))),

        mode === 'selfhost' ? h('label', { className: 'dshn-field' },
          h('span', null, T.relayHost),
          h('input', { className: 'dshn-input', value: relayHost, placeholder: 'wss://tunnel.example.com',
            autoComplete: 'off', spellCheck: false, autoFocus: !configured, onChange: (ev) => setRelayHost(ev.target.value) }),
          h('div', { className: 'dshn-hint' }, T.relayHostHint)) : null,
        // Self-signed CA — hidden behind a toggle; only the rare self-signed relay
        // needs it (valid cert / behind Cloudflare needs nothing).
        mode === 'selfhost' ? h('div', { className: 'dshn-field' },
          h('button', { type: 'button', className: 'dshn-catoggle', onClick: () => setShowCa(!showCa) }, (showCa ? '▾ ' : '▸ ') + T.relayCa),
          showCa ? h('textarea', { className: 'dshn-input dshn-ca', value: originCa, rows: 3, spellCheck: false, style: { marginTop: '6px' },
            placeholder: '-----BEGIN CERTIFICATE-----', onChange: (ev) => setOriginCa(ev.target.value) }) : null,
          showCa ? h('div', { className: 'dshn-hint' }, T.relayCaHint) : null) : null,

        h('label', { className: 'dshn-field' },
          h('span', null, T.prefix),
          h('div', { className: 'dshn-prefixwrap' },
            h('input', { className: 'dshn-input', value: prefix, placeholder: 'alice', autoFocus: !configured && mode !== 'selfhost',
              onChange: (e) => setPrefix(e.target.value.toLowerCase()) }),
            h('span', { className: 'dshn-apex' }, '.' + apex)),
          !configured ? h('div', { className: 'dshn-hint' }, T.prefixHint) : null),

        h('label', { className: 'dshn-field' },
          h('span', null, T.password),
          h('div', { className: 'dshn-pwwrap' },
            h('input', { className: 'dshn-input', type: showPw ? 'text' : 'password', value: pw,
              autoComplete: configured ? 'off' : 'new-password', placeholder: '••••••••',
              onChange: (e) => setPw(e.target.value),
              onKeyDown: (e) => { if (e.key === 'Enter' && configured) submit() } }),
            h('div', { className: 'dshn-pwbtns' },
              h('button', { className: 'dshn-mini', type: 'button', onClick: () => setShowPw(!showPw) }, showPw ? T.hide : T.show),
              h('button', { className: 'dshn-mini', type: 'button', onClick: copyPw }, copied === 'pw' ? T.copied : T.copy))),
          !configured && pw.length > 0 ? h('div', { className: 'dshn-meter' },
            h('i', { style: { width: ((st.score + 1) * 20) + '%', background: SC[st.score] } })) : null,
          !configured && pw.length > 0 ? h('div', { className: 'dshn-strength', style: { color: SC[st.score] } }, slabel(st.score)) : null,
          h('div', { className: 'dshn-hint' }, configured ? T.savedHint : T.pwHint)),

        !configured ? h('label', { className: 'dshn-field' },
          h('span', null, T.confirm),
          h('input', { className: 'dshn-input', type: showPw ? 'text' : 'password', value: confirm,
            'data-bad': confirm.length > 0 && !matches ? '1' : '0', autoComplete: 'new-password', placeholder: '••••••••',
            onChange: (e) => setConfirm(e.target.value), onKeyDown: (e) => { if (e.key === 'Enter') submit() } }),
          confirm.length > 0 && !matches ? h('div', { className: 'dshn-err', style: { marginTop: '5px', marginBottom: 0 } }, T.mismatch) : null) : null,

        !configured ? h('div', { className: 'dshn-note' }, T.recoverNote) : null,

        // First-time setup: an OPTIONAL e2e password inline, so setup is one flow
        // rather than "connect, then hunt for a second control". Left blank → e2e
        // stays off (the default). Once configured this collapses and the
        // dedicated control below takes over (with its own apply/disable).
        !configured ? h('label', { className: 'dshn-field' },
          h('span', null, '🔒 ' + T.e2eLabel),
          h('div', { className: 'dshn-pwwrap' },
            h('input', { className: 'dshn-input', type: showPw ? 'text' : 'password', value: e2e,
              autoComplete: 'new-password', placeholder: '••••••••',
              onChange: (ev) => setE2e(ev.target.value), onKeyDown: (ev) => { if (ev.key === 'Enter') submit() } }),
            h('div', { className: 'dshn-pwbtns' },
              h('button', { className: 'dshn-mini', type: 'button', onClick: () => setShowPw(!showPw) }, showPw ? T.hide : T.show))),
          e2e.trim() !== '' && e2e.trim().length < MIN_PW ? h('div', { className: 'dshn-err', style: { marginTop: '5px', marginBottom: 0 } }, T.pwHint) : null,
          h('div', { className: 'dshn-hint' }, T.e2eHint)) : null,

        // End-to-end password: a SELF-CONTAINED control with its own apply/disable
        // buttons, only once the tunnel is configured. Changing it never touches
        // the connection or the main credentials above.
        configured ? (() => {
          const saved = s.e2ePassword || ''
          const trimmed = e2e.trim()
          const changed = trimmed !== saved
          const valid = trimmed === '' || trimmed.length >= MIN_PW
          const canApply = changed && valid && !e2eBusy
          return h('div', { className: 'dshn-e2e-box' },
            h('div', { className: 'dshn-e2e-head' },
              h('span', null, '🔒 ' + T.e2eLabel),
              h('span', { className: 'dshn-info-v', style: { color: s.e2eEnabled ? '#3aa675' : 'var(--dsw-alias-label-tertiary, #8b9099)', fontSize: '11px' } }, s.e2eEnabled ? T.e2eOn : T.e2eOff)),
            h('div', { className: 'dshn-pwwrap' },
              h('input', { className: 'dshn-input', type: showPw ? 'text' : 'password', value: e2e,
                autoComplete: 'off', placeholder: '••••••••',
                onChange: (ev) => { setE2e(ev.target.value); setE2eMsg(''); setE2eErr('') } }),
              h('div', { className: 'dshn-pwbtns' },
                h('button', { className: 'dshn-mini', type: 'button', onClick: () => setShowPw(!showPw) }, showPw ? T.hide : T.show),
                e2e ? h('button', { className: 'dshn-mini', type: 'button', onClick: () => copyText(e2e, 'e2e') }, copied === 'e2e' ? T.copied : T.copy) : null)),
            trimmed !== '' && trimmed.length < MIN_PW ? h('div', { className: 'dshn-err', style: { marginTop: '5px', marginBottom: 0 } }, T.pwHint) : null,
            e2eErr ? h('div', { className: 'dshn-err', style: { marginTop: '6px', marginBottom: 0 } }, e2eErr) : null,
            e2eMsg ? h('div', { className: 'dshn-hint', style: { marginTop: '6px', color: '#3aa675' } }, e2eMsg) : null,
            h('div', { className: 'dshn-e2e-actions' },
              h('button', { className: 'dshn-btn-sm', disabled: !canApply, onClick: () => applyE2E(trimmed) },
                e2eBusy ? T.connecting2 : (s.e2eEnabled ? T.e2eUpdate : T.e2eApply)),
              s.e2eEnabled ? h('button', { className: 'dshn-btn-sm dshn-btn-warn', disabled: e2eBusy, onClick: () => { setE2e(''); applyE2E('') } }, T.e2eDisable) : null),
            h('div', { className: 'dshn-hint', style: { marginTop: '7px' } }, T.e2eHint + ' ' + T.e2eIndep))
        })() : null),

        // Disconnecting severs public access and the password is unrecoverable
        // from the cloud — so it takes an explicit, spelled-out confirmation.
        confirmDc ? h('div', { className: 'dshn-dcwarn' },
          h('div', { className: 'dshn-dcwarn-title' }, '⚠ ' + T.dcTitle),
          h('div', { className: 'dshn-dcwarn-body' }, T.dcWarn),
          h('div', { style: { marginTop: '8px' } },
            h('button', { className: 'dshn-mini', onClick: copyPw }, copied === 'pw' ? T.copied : T.dcCopyFirst))) : null,

        h('div', { className: 'dshn-actions' },
          confirmDc
            ? h(react.Fragment, null,
                h('button', { className: 'dshn-danger', onClick: () => { setConfirmDc(false); disconnect() } }, T.dcConfirm),
                h('button', { className: 'dshn-ghost', onClick: () => setConfirmDc(false) }, T.dcCancel))
            : h(react.Fragment, null,
                h('button', { className: 'dshn-primary', disabled: !canSubmit, onClick: submit },
                  busy ? T.connecting2 : (configured ? T.reconnect : T.connect)),
                configured
                  ? h('button', { className: 'dshn-ghost', onClick: () => setConfirmDc(true) }, T.disconnect)
                  : (props.mode === 'modal' ? h('button', { className: 'dshn-ghost', onClick: props.onClose }, T.later) : null))))
    }

    // Is THIS page loaded over loopback (i.e. locally)? The management widget is
    // a local tool: over the public tunnel /dshn/* is blocked and there is
    // nothing to configure, so the widget hides entirely — that also removes the
    // cloud/local inconsistency of a dead pill appearing remotely.
    const pageLoopback = (() => { const hn = location.hostname; return hn === 'localhost' || hn === '::1' || /^127\./.test(hn) })()

    // One poller feeds both slot entries (the footer button and the overlay),
    // kept in a tiny shared store so they never fight over state.
    const store = {
      status: null, open: false, dismissed: false, started: false, subs: new Set(),
      set(patch) { Object.assign(this, patch); this.subs.forEach((f) => f()) },
      sub(f) { this.subs.add(f); return () => this.subs.delete(f) },
      start() {
        if (this.started) return
        this.started = true
        const tick = () => fetch('/dshn/status', { cache: 'no-store' })
          .then((r) => (r.ok ? r.json() : null)).then((s) => this.set({ status: s })).catch(() => {})
        tick(); setInterval(tick, POLL_MS)
      },
    }
    function useStore() {
      const [, force] = react.useReducer((x) => x + 1, 0)
      react.useEffect(() => store.sub(force), [])
      return store
    }

    // ── multi-device switcher (remote pages only) ─────────────────────────────
    // On a public host, `/__dshn/devices` is answered by the RELAY (same host,
    // behind the same login cookie): the list of devices bound to this subdomain.
    // `multi` goes true when ≥2 are live — only then does the switcher appear.
    // `/dshn-e2e` (answered by the SERVING device through the tunnel) tells us
    // which device this page is actually on, for when no selection cookie is set.
    // An old relay answers neither with JSON — the switcher just stays hidden.
    const DEV_POLL_MS = 10000
    const devStore = {
      info: null, self: null, started: false, subs: new Set(),
      set(patch) { Object.assign(this, patch); this.subs.forEach((f) => f()) },
      sub(f) { this.subs.add(f); return () => this.subs.delete(f) },
      start() {
        if (this.started || pageLoopback) return
        this.started = true
        const tick = () => fetch('/__dshn/devices', { cache: 'no-store', credentials: 'include', headers: { accept: 'application/json' } })
          .then((r) => (r.ok && String(r.headers.get('content-type') || '').includes('json') ? r.json() : null))
          .then((j) => { if (j && Array.isArray(j.devices)) this.set({ info: j }) })
          .catch(() => {})
        tick(); setInterval(tick, DEV_POLL_MS)
        fetch(E2E_PUB_PATH, { cache: 'no-store', credentials: 'include' })
          .then((r) => (r.ok ? r.json() : null))
          .then((j) => { if (j && j.device) this.set({ self: j.device }) })
          .catch(() => {})
      },
    }
    function DeviceSwitcher() {
      const [, force] = react.useReducer((x) => x + 1, 0)
      react.useEffect(() => devStore.sub(force), [])
      const [open, setOpen] = react.useState(false)
      const [busy, setBusy] = react.useState(false)
      const info = devStore.info
      if (!info || !info.multi) return null
      const devices = info.devices || []
      const currentId = info.current || devStore.self
      const current = devices.find((d) => d.id === currentId) || null
      const pick = (d) => {
        if (busy || !d.online || d.id === currentId) return
        setBusy(true)
        // Set the selection cookie, then a full reload boots the app cleanly
        // against the chosen device (no cross-device state survives).
        fetch('/__dshn/select', { method: 'POST', credentials: 'include',
          headers: { 'content-type': 'application/json', accept: 'application/json' },
          body: JSON.stringify({ device: d.id }) })
          .then((r) => { if (r.ok) location.reload(); else setBusy(false) })
          .catch(() => setBusy(false))
      }
      return h(react.Fragment, null,
        h('button', { className: 'dshn-frow', title: T.devSwitch, 'aria-label': T.devSwitch, onClick: () => setOpen(!open) },
          h('span', { className: 'dshn-frow-ic' }, Icon('server', { width: 16, height: 16 })),
          h('span', { className: 'dshn-frow-label' }, current ? current.name : T.devLabel),
          h('span', { className: 'dshn-frow-trail' }, (info.live || 0) + '/' + devices.length)),
        open ? h('div', { className: 'dshn-devpop' },
          h('div', { className: 'dshn-devpop-title' }, T.devSwitch),
          devices.map((d) => h('button', {
            key: d.id, className: 'dshn-devrow', disabled: busy || !d.online || d.id === currentId,
            onClick: () => pick(d) },
            h('span', { className: 'dshn-dot', 'data-on': d.online ? '1' : '0' }),
            h('span', { className: 'dshn-devrow-name' }, d.name),
            d.id === currentId ? h('span', { className: 'dshn-devrow-tag' }, T.devCurrent)
              : (!d.online ? h('span', { className: 'dshn-devrow-tag' }, T.devOffline) : null)))) : null)
    }

    // Open dsh's Settings and land on our section. The settings trigger is a
    // stable `button[aria-haspopup="dialog"]` (class names are hashed); once it
    // is open, click our section's nav entry by its label.
    function openDshSettings() {
      const trigger = document.querySelector('button[aria-haspopup="dialog"]')
      if (!trigger) return
      trigger.click()
      const goToSection = (tries) => {
        scheduleIconPatch()
        const item = Array.from(document.querySelectorAll('button,a,li,[role="tab"],[role="option"]'))
          .find((e) => (e.textContent || '').trim() === T.navLabel)
        if (item) { (item.closest('button,a,li,[role="tab"]') || item).click(); return }
        if (tries > 0) setTimeout(() => goToSection(tries - 1), 120)
      }
      setTimeout(() => goToSection(10), 160)
    }

    // dsh chooses each settings-nav icon from a hardcoded switch on the section
    // id and falls back to its gear glyph for any id it doesn't know — including
    // ours, so "公网转发" would otherwise share the 通用设置 gear. There is no
    // registration field for a custom icon, so we swap the rendered glyph for our
    // globe (matching the footer). Idempotent, and re-applied by an observer since
    // dsh may re-render the cell. Built as raw SVG to mirror dsh's 16px navIcon.
    function globeSvgEl(cls) {
      const NS = 'http://www.w3.org/2000/svg'
      const svg = document.createElementNS(NS, 'svg')
      const set = (el, a) => { for (const k in a) el.setAttribute(k, a[k]) }
      set(svg, { width: '16', height: '16', viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor',
        'stroke-width': '1.4', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })
      if (cls) svg.setAttribute('class', cls)
      const add = (tag, a) => { const e = document.createElementNS(NS, tag); set(e, a); svg.appendChild(e) }
      add('circle', { cx: '8', cy: '8', r: '6' })
      add('path', { d: 'M2 8h12' })
      add('path', { d: 'M8 2c2.6 2.6 2.6 9.4 0 12' })
      add('path', { d: 'M8 2c-2.6 2.6-2.6 9.4 0 12' })
      return svg
    }
    function patchNavIcon() {
      const dlg = document.querySelector('[role="dialog"], [aria-modal="true"]')
      if (!dlg) return
      dlg.querySelectorAll('button').forEach((b) => {
        if (b.getAttribute('data-dshn-globe') === '1') return
        if ((b.textContent || '').trim() !== T.navLabel) return
        const svg = b.querySelector('svg')
        if (!svg) return
        svg.replaceWith(globeSvgEl(svg.getAttribute('class') || ''))
        b.setAttribute('data-dshn-globe', '1')
      })
    }
    let iconPatchScheduled = false
    function scheduleIconPatch() {
      if (iconPatchScheduled) return
      iconPatchScheduled = true
      const run = () => { iconPatchScheduled = false; try { patchNavIcon() } catch { /* ignore */ } }
      if (typeof requestAnimationFrame === 'function') requestAnimationFrame(run); else setTimeout(run, 16)
    }

    // At-a-glance status in dsh's own sidebar footer (beside settings, laid out
    // by dsh — no overlap). Globe + the live latency value; colour tracks quality.
    // Configuration itself lives in the Settings page, not here.
    function FooterButton() {
      useStore()
      // Remote pages get the device switcher in this slot instead of the local
      // status row (configuration is local-only; switching devices is the one
      // thing a remote visitor can do here).
      if (!pageLoopback) return h(DeviceSwitcher)
      const s = store.status
      const connected = s && s.connected
      const configured = s && s.configured
      const err = s && s.lastError && !connected
      const color = !configured ? 'var(--dsw-alias-label-tertiary, #8b9099)'
        : connected ? latColor(s.latencyMs) : err ? '#e5484d' : '#d98324'
      const lat = connected && s.latencyMs != null ? s.latencyMs + ' ms' : null
      // Trailing value: the live latency when connected, otherwise the state word.
      const trail = !s ? '' : !configured ? T.notset : connected ? (lat || T.live) : (err ? T.off : T.connecting)
      return h('button', { className: 'dshn-frow', title: 'ds.hn · ' + trail + ' — ' + T.openSettings, 'aria-label': T.navLabel, onClick: openDshSettings },
        h('span', { className: 'dshn-frow-ic', style: { color } }, Icon('globe', { width: 16, height: 16 })),
        h('span', { className: 'dshn-frow-label' }, T.navLabel),
        h('span', { className: 'dshn-frow-trail', style: { color } }, trail))
    }

    // The whole configuration, as a page in dsh's Settings (settings.section).
    // No separate floating form — this IS the form, laid out by dsh's settings
    // shell. Local machine only; a remote visitor just sees a note.
    function DshnSection() {
      useStore()
      const s = store.status
      if (!pageLoopback) return h('div', { className: 'dshn-section' }, h('p', { className: 'dshn-section-intro' }, T.localOnly))
      return h('div', { className: 'dshn-section' },
        h('p', { className: 'dshn-section-intro' }, T.sectionIntro),
        s ? h(Panel, { status: s, mode: 'section' }) : h('p', { className: 'dshn-hint' }, T.loading))
    }

    const inject = ['slots']
    function apply(ctx) {
      if (pageLoopback) store.start()
      else devStore.start()
      ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({ name: 'sidebar.footer.action', id: 'dshn-footer', order: 50 }, FooterButton))
      ctx.slots.inject('settings.section', () => ctx.slots.register({ name: 'settings.section', id: 'dshn', order: 40, label: () => T.navLabel }, DshnSection))
      // Keep our settings-nav globe applied however the panel is opened (dsh's own
      // gear, not just our footer) and re-applied if dsh re-renders the cell.
      if (pageLoopback && typeof MutationObserver !== 'undefined' && document.body) {
        new MutationObserver(scheduleIconPatch).observe(document.body, { childList: true, subtree: true })
      }
    }
    exports.apply = apply; exports.inject = inject
    return module.exports
  },
})
