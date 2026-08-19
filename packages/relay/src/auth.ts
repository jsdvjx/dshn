/**
 * The relay's login gate. dsh exposes bash and filesystem tools, so an
 * unauthenticated public URL is a remote shell — the gate is not optional. It
 * is deliberately simple: a per-tunnel password (the tunnel token) exchanged
 * for an HMAC-signed, host-scoped session cookie. No account server is in the
 * request path; verification is a constant-time MAC check.
 */
import { createHmac, timingSafeEqual } from 'node:crypto'

/** Session cookie name. Scoped by default to the exact subdomain that set it. */
export const COOKIE_NAME = 'dshn_sess'

/** Session lifetime. A month balances "don't log in constantly" against staleness. */
const MAX_AGE_S = 30 * 24 * 3600

/**
 * Mint a signed session value binding a subdomain to an expiry.
 * @param secret - the relay's cookie-signing secret.
 * @param subdomain - the subdomain the session is valid for.
 * @returns the cookie value `exp.mac`.
 */
export function sign(secret: string, subdomain: string): string {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE_S
  const mac = createHmac('sha256', secret).update(`${subdomain}.${exp}`).digest('base64url')
  return `${exp}.${mac}`
}

/**
 * Verify a session value against a subdomain: unexpired and correctly signed.
 * @param secret - the relay's cookie-signing secret.
 * @param subdomain - the subdomain the request is for.
 * @param value - the presented cookie value.
 * @returns whether the session is valid.
 */
export function verify(secret: string, subdomain: string, value: string): boolean {
  if (value === '') return false
  const dot = value.indexOf('.')
  if (dot < 0) return false
  const exp = Number(value.slice(0, dot))
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return false
  const expected = createHmac('sha256', secret).update(`${subdomain}.${exp}`).digest('base64url')
  return constantTimeEqual(value.slice(dot + 1), expected)
}

/**
 * The `Set-Cookie` header value for a fresh session.
 * @param value - a value from {@link sign}.
 * @returns the cookie header string.
 */
export function cookieHeader(value: string): string {
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${MAX_AGE_S}`
}

/**
 * Device-selection cookie (multi-device). Holds the device id the browser chose
 * on the picker page; the relay routes every request on this host to that
 * device. Not a credential — just a routing preference — so it needs no MAC.
 */
export const DEVICE_COOKIE = 'dshn_dev'

/** Device-selection cookie lifetime: long, so a chosen device sticks. */
const DEVICE_MAX_AGE_S = 180 * 24 * 3600

/**
 * The `Set-Cookie` header value selecting a device (or clearing the selection).
 * @param deviceId - the chosen device id, or null to clear.
 * @returns the cookie header string.
 */
export function deviceCookieHeader(deviceId: string | null): string {
  if (deviceId === null) return `${DEVICE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  return `${DEVICE_COOKIE}=${deviceId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${DEVICE_MAX_AGE_S}`
}

/**
 * Parse a `Cookie` request header into a name→value map.
 * @param header - the raw `Cookie` header, if any.
 * @returns the parsed cookies.
 */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (header === undefined) return out
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim()
  }
  return out
}

/**
 * Constant-time password check for the login POST.
 * @param a - one secret.
 * @param b - the other.
 * @returns whether they are equal, without leaking length-independent timing.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

/**
 * The login page. Self-contained HTML — the relay serves no assets — and
 * theme-neutral. It states the host so a user pasting a phone URL sees which
 * machine they are unlocking.
 * @param host - the public host being unlocked (e.g. `alice.ds.hn`).
 * @param error - whether to show a "wrong password" notice.
 * @returns the HTML document.
 */
export function loginPage(host: string, error: boolean): string {
  const notice = error
    ? '<p class="err">Incorrect password.</p>'
    : '<p class="hint">This machine is exposed through ds.hn. Enter its access password to continue.</p>'
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(host)} · ds.hn</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font: 15px/1.5 system-ui, sans-serif; background:#0f1115; color:#e8eaed; }
  @media (prefers-color-scheme: light) { body { background:#f4f5f7; color:#1c1e21; } }
  .card { width:min(340px,90vw); padding:26px 24px; border-radius:14px;
    background:rgba(128,134,142,.12); }
  h1 { font-size:15px; margin:0 0 4px; font-weight:600; }
  .host { font-family:ui-monospace,Menlo,monospace; opacity:.7; font-size:13px; margin-bottom:16px; }
  .hint { font-size:13px; opacity:.7; margin:0 0 16px; }
  .err { font-size:13px; color:#e5484d; margin:0 0 16px; }
  input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:9px;
    border:1px solid rgba(128,134,142,.4); background:transparent; color:inherit; font-size:15px; }
  button { width:100%; margin-top:12px; padding:10px; border:0; border-radius:9px;
    background:#4176e6; color:#fff; font-size:15px; cursor:pointer; }
</style></head>
<body><form class="card" method="POST" action="/__dshn/login">
  <h1>ds.hn</h1>
  <div class="host">${escapeHtml(host)}</div>
  ${notice}
  <input type="password" name="password" placeholder="Access password" autofocus autocomplete="current-password" required>
  <button type="submit">Unlock</button>
</form></body></html>`
}

/** One row of the device picker page. */
export interface PickerDevice {
  id: string
  name: string
  online: boolean
  current: boolean
}

/**
 * The device picker page, shown when several devices are bound to this
 * subdomain and the browser has not chosen one (or its chosen one is gone).
 * Each online device is a submit button POSTing the selection to
 * `/__dshn/select`; the relay answers with the device cookie and a redirect.
 * Self-contained HTML, same look as {@link loginPage}.
 * @param host - the public host (e.g. `alice.ds.hn`).
 * @param devices - the devices to list, already sorted.
 * @returns the HTML document.
 */
export function devicesPage(host: string, devices: PickerDevice[]): string {
  const rows = devices.map((d) => {
    const dot = `<span class="dot${d.online ? ' on' : ''}"></span>`
    const state = d.online ? '' : '<span class="off">offline</span>'
    const mark = d.current ? '<span class="cur">current</span>' : ''
    if (!d.online) {
      return `<div class="dev dim">${dot}<span class="name">${escapeHtml(d.name)}</span>${mark}${state}</div>`
    }
    return `<form method="POST" action="/__dshn/select"><input type="hidden" name="device" value="${escapeHtml(d.id)}">`
      + `<button class="dev" type="submit">${dot}<span class="name">${escapeHtml(d.name)}</span>${mark}<span class="go">→</span></button></form>`
  }).join('\n')
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(host)} · devices · ds.hn</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font: 15px/1.5 system-ui, sans-serif; background:#0f1115; color:#e8eaed; }
  @media (prefers-color-scheme: light) { body { background:#f4f5f7; color:#1c1e21; } }
  .card { width:min(360px,90vw); padding:26px 24px; border-radius:14px;
    background:rgba(128,134,142,.12); }
  h1 { font-size:15px; margin:0 0 4px; font-weight:600; }
  .host { font-family:ui-monospace,Menlo,monospace; opacity:.7; font-size:13px; margin-bottom:6px; }
  .hint { font-size:13px; opacity:.7; margin:0 0 16px; }
  form { margin:0; }
  .dev { display:flex; align-items:center; gap:10px; width:100%; box-sizing:border-box;
    padding:11px 12px; margin-top:8px; border-radius:10px; text-align:left; font-size:14px;
    border:1px solid rgba(128,134,142,.35); background:transparent; color:inherit; cursor:pointer; }
  button.dev:hover { border-color:#4176e6; }
  .dev.dim { cursor:default; opacity:.55; }
  .dot { width:8px; height:8px; border-radius:50%; flex:none; background:rgba(128,134,142,.6); }
  .dot.on { background:#3aa675; box-shadow:0 0 0 3px rgba(58,166,117,.2); }
  .name { flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .cur { font-size:11px; color:#4176e6; border:1px solid currentColor; border-radius:99px; padding:1px 7px; }
  .off { font-size:11px; opacity:.7; }
  .go { opacity:.5; }
</style></head>
<body><div class="card">
  <h1>ds.hn</h1>
  <div class="host">${escapeHtml(host)}</div>
  <p class="hint">Several devices share this address. Pick the one to use — you can switch any time from the sidebar.</p>
  ${rows}
</div></body></html>`
}

/** Minimal HTML escaping for the one interpolated value (the host). */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;')
}
