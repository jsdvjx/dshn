/**
 * The operator admin panel, served on the bare apex under `/__admin`. It shows
 * platform-wide numbers (claims, live devices, traffic since the relay started,
 * trend charts from the relay's in-memory samples) and manages users: a claim
 * can be kicked offline, released, or banned.
 *
 * It exists only when the operator configures an admin password; without one
 * every `/__admin` path is a 404, indistinguishable from an absent feature.
 * Auth reuses the relay's HMAC session scheme under a scope (`__admin`) that
 * can never collide with a claimable subdomain label, and the cookie is
 * host-only on the apex, so tunnel subdomains never see it.
 */

/** Admin session cookie name, host-only on the apex. */
export const ADMIN_COOKIE = 'dshn_admin'

/**
 * HMAC scope for admin sessions. Underscores are impossible in a claimable
 * label, so no tunnel session can ever verify against this scope.
 */
export const ADMIN_SCOPE = '__admin'

/** Admin sessions are short — this is the platform's keys, not a tunnel's. */
export const ADMIN_MAX_AGE_S = 12 * 3600

/**
 * The `Set-Cookie` header value for an admin session (or for clearing one).
 * @param value - a value from `sign(secret, ADMIN_SCOPE, ADMIN_MAX_AGE_S)`, or null to clear.
 * @returns the cookie header string.
 */
export function adminCookieHeader(value: string | null): string {
  if (value === null) return `${ADMIN_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/__admin; Max-Age=0`
  return `${ADMIN_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/__admin; Max-Age=${ADMIN_MAX_AGE_S}`
}

/** Minimal HTML escaping for interpolated values. */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;')
}

/**
 * The admin login page. Same self-contained look as the tunnel login page, but
 * clearly labeled as the operator entrance.
 * @param apex - the platform apex (e.g. `ds.hn`), shown so the operator knows which relay this is.
 * @param error - whether to show a "wrong password" notice.
 * @returns the HTML document.
 */
export function adminLoginPage(apex: string, error: boolean): string {
  const notice = error
    ? '<p class="err">Incorrect password.</p>'
    : '<p class="hint">Operator area. Enter the admin password to continue.</p>'
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>admin · ${escapeHtml(apex)}</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font: 15px/1.5 system-ui, sans-serif; background:#0f1115; color:#e8eaed; }
  @media (prefers-color-scheme: light) { body { background:#f4f5f7; color:#1c1e21; } }
  .card { width:min(340px,90vw); padding:26px 24px; border-radius:14px;
    background:rgba(128,134,142,.12); }
  h1 { font-size:15px; margin:0 0 4px; font-weight:600; display:flex; align-items:center; gap:8px; overflow-wrap:anywhere; }
  h1 svg { width:16px; height:16px; flex:none; }
  .host { font-family:ui-monospace,Menlo,monospace; opacity:.7; font-size:13px; margin-bottom:16px; }
  .hint { font-size:13px; opacity:.7; margin:0 0 16px; }
  .err { font-size:13px; color:#e5484d; margin:0 0 16px; }
  input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:9px;
    border:1px solid rgba(128,134,142,.4); background:transparent; color:inherit; font-size:15px; }
  button { width:100%; margin-top:12px; padding:10px; border:0; border-radius:9px;
    background:#4176e6; color:#fff; font-size:15px; cursor:pointer; }
</style></head>
<body><form class="card" method="POST" action="/__admin/login">
  <h1><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>${escapeHtml(apex)} · admin</h1>
  <div class="host">relay operator panel</div>
  ${notice}
  <input type="password" name="password" placeholder="Admin password" autofocus autocomplete="current-password" required>
  <button type="submit">Enter</button>
</form></body></html>`
}

/**
 * The admin dashboard. A self-contained page (the relay serves no assets) that
 * renders from `GET /__admin/api/state` (live numbers, every few seconds) and
 * `GET /__admin/api/history` (trend samples, every 30s): stat tiles, three
 * trend charts drawn as inline SVG, then one table row per claim with kick /
 * release / ban actions. All user-controlled strings (subdomains, device
 * names) are escaped client-side before touching the DOM.
 * @param apex - the platform apex (e.g. `ds.hn`).
 * @returns the HTML document.
 */
export function adminPage(apex: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>admin · ${escapeHtml(apex)}</title>
<style>
  :root {
    color-scheme: light dark;
    --bg:#0f1115; --ink:#e8eaed; --ink2:rgba(232,234,237,.62); --ink3:rgba(232,234,237,.42);
    --card:rgba(128,134,142,.12); --line:rgba(128,134,142,.25); --grid:rgba(128,134,142,.18);
    --accent:#4176e6; --good:#3aa675; --bad:#e5484d;
    --s1:#3987e5; --s2:#d95926;
  }
  @media (prefers-color-scheme: light) { :root {
    --bg:#f4f5f7; --ink:#1c1e21; --ink2:rgba(28,30,33,.62); --ink3:rgba(28,30,33,.45);
    --card:rgba(128,134,142,.12); --line:rgba(128,134,142,.3); --grid:rgba(128,134,142,.22);
    --s1:#2a78d6; --s2:#eb6834;
  } }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; font:14px/1.5 system-ui,sans-serif; background:var(--bg); color:var(--ink); }
  .wrap { max-width:1040px; margin:0 auto; padding:24px 20px 60px; }
  svg.i { width:15px; height:15px; flex:none; vertical-align:-2px; }
  header { display:flex; align-items:center; flex-wrap:wrap; gap:8px 10px; margin-bottom:20px; }
  h1 { font-size:16px; font-weight:600; margin:0; display:flex; align-items:center; gap:7px; }
  .apex { font-family:ui-monospace,Menlo,monospace; font-size:13px; color:var(--ink2); overflow-wrap:anywhere; }
  .spacer { flex:1; }
  .meta { font-size:12px; color:var(--ink3); white-space:nowrap; }
  .btn { display:inline-flex; align-items:center; gap:5px; border:1px solid var(--line); background:transparent;
    color:var(--ink2); font:inherit; font-size:12px; padding:5px 10px; border-radius:8px; cursor:pointer; line-height:1.2; }
  .btn:hover { border-color:var(--accent); color:var(--ink); }
  .btn svg.i { width:13px; height:13px; }
  select.btn { padding:5px 8px; appearance:auto; }
  .tiles { display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:10px; }
  .tile { background:var(--card); border-radius:12px; padding:12px 14px 10px; min-width:0; }
  .tile .k { display:flex; align-items:center; gap:6px; font-size:11px; letter-spacing:.04em; text-transform:uppercase;
    color:var(--ink3); margin-bottom:3px; }
  .tile .k svg.i { width:13px; height:13px; }
  .tile .v { font-size:22px; font-weight:600; font-variant-numeric:tabular-nums; line-height:1.15; overflow-wrap:anywhere; }
  .tile .s { font-size:11px; color:var(--ink3); margin-top:2px; overflow-wrap:anywhere; }
  .note { font-size:11px; color:var(--ink3); margin:6px 2px 24px; }
  h2 { display:flex; align-items:center; gap:7px; font-size:13px; font-weight:600; margin:0 0 10px; color:var(--ink2); }
  h2 .range { margin-left:auto; display:inline-flex; gap:2px; border:1px solid var(--line); border-radius:8px; padding:2px; }
  h2 .range button { border:0; background:transparent; color:var(--ink3); font:inherit; font-size:11px;
    padding:2px 8px; border-radius:6px; cursor:pointer; }
  h2 .range button.on { background:var(--card); color:var(--ink); }
  .charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:10px; margin-bottom:26px; }
  .chart { background:var(--card); border-radius:12px; padding:12px 14px 8px; min-width:0; position:relative; }
  .chart .t { display:flex; align-items:baseline; flex-wrap:wrap; gap:4px 10px; font-size:12px; color:var(--ink2); margin-bottom:4px; }
  .chart .t b { font-weight:600; color:var(--ink); }
  .chart .legend { display:inline-flex; gap:10px; margin-left:auto; font-size:11px; color:var(--ink3); }
  .chart .legend i { display:inline-block; width:10px; height:3px; border-radius:2px; vertical-align:2px; margin-right:4px; }
  .chart svg { display:block; width:100%; height:150px; overflow:visible; }
  .chart .empty { height:150px; display:grid; place-items:center; font-size:12px; color:var(--ink3); text-align:center; padding:0 10px; }
  .chart text { font-size:10.5px; fill:var(--ink3); font-variant-numeric:tabular-nums; }
  .chart .grid { stroke:var(--grid); stroke-width:1; }
  .chart .axis { stroke:var(--line); stroke-width:1; }
  .chart .line { fill:none; stroke-width:2; stroke-linejoin:round; stroke-linecap:round; }
  .chart .area { opacity:.10; }
  .chart .xh { stroke:var(--ink3); stroke-width:1; stroke-dasharray:3 3; }
  .chart .pt { stroke:var(--bg); stroke-width:2; }
  .chart .hit { fill:transparent; cursor:crosshair; }
  .tip { position:absolute; z-index:2; pointer-events:none; background:var(--bg); border:1px solid var(--line);
    border-radius:8px; padding:6px 9px; font-size:11.5px; color:var(--ink); box-shadow:0 4px 16px rgba(0,0,0,.25);
    white-space:nowrap; display:none; font-variant-numeric:tabular-nums; }
  .tip .d { color:var(--ink3); margin-bottom:2px; }
  .tip i { display:inline-block; width:8px; height:8px; border-radius:2px; margin-right:6px; vertical-align:-1px; }
  .tablewrap { overflow-x:auto; border:1px solid var(--line); border-radius:12px; }
  table { border-collapse:collapse; width:100%; min-width:900px; }
  th { text-align:left; font-size:11px; letter-spacing:.04em; text-transform:uppercase; color:var(--ink3);
    font-weight:500; padding:9px 12px; border-bottom:1px solid var(--line); white-space:nowrap; }
  td { padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; font-variant-numeric:tabular-nums; }
  tr:last-child td { border-bottom:0; }
  td.num, th.num { text-align:right; white-space:nowrap; }
  .sub { min-width:160px; max-width:240px; }
  .sub a { color:var(--ink); text-decoration:none; font-family:ui-monospace,Menlo,monospace; font-size:13px;
    overflow-wrap:anywhere; display:inline-flex; align-items:baseline; gap:5px; }
  .sub a svg.i { width:11px; height:11px; opacity:.45; flex:none; }
  .sub a:hover { color:var(--accent); }
  .sub a:hover svg.i { opacity:1; }
  .dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--ink3);
    margin-right:6px; vertical-align:1px; flex:none; }
  .dot.on { background:var(--good); box-shadow:0 0 0 3px rgba(58,166,117,.18); }
  .state { font-size:12px; color:var(--ink2); white-space:nowrap; }
  .route { display:inline-flex; align-items:center; gap:4px; font-size:11px; border:1px solid var(--line); border-radius:99px;
    padding:2px 8px; color:var(--ink3); white-space:nowrap; }
  .route svg.i { width:11px; height:11px; }
  .route.on { color:#c9930f; border-color:rgba(201,147,15,.55); background:rgba(201,147,15,.08); }
  .act .btn.gold:hover { border-color:#c9930f; color:#c9930f; }
  .devs { min-width:200px; max-width:300px; }
  .dev { display:flex; align-items:baseline; font-size:12px; color:var(--ink2); line-height:1.45; }
  .dev .n { overflow-wrap:anywhere; }
  .dev .ago { color:var(--ink3); white-space:nowrap; margin-left:5px; }
  .dim { color:var(--ink3); font-size:12px; white-space:nowrap; }
  .act { white-space:nowrap; text-align:right; }
  .act .btn { padding:4px 8px; margin-left:4px; }
  .act .btn.danger:hover { border-color:var(--bad); color:var(--bad); }
  .empty { padding:22px; text-align:center; color:var(--ink3); font-size:13px; }
  .banned { display:flex; flex-wrap:wrap; gap:8px; }
  .banchip { display:inline-flex; align-items:center; gap:8px; border:1px solid var(--line); max-width:100%;
    border-radius:99px; padding:4px 6px 4px 12px; font-family:ui-monospace,Menlo,monospace; font-size:12px; }
  .banchip span { overflow-wrap:anywhere; word-break:break-all; }
  .banchip button { display:inline-flex; align-items:center; gap:4px; border:0; background:var(--card); color:var(--ink2);
    font:inherit; font-size:11px; padding:3px 9px; border-radius:99px; cursor:pointer; font-family:system-ui,sans-serif; flex:none; }
  .banchip button:hover { color:var(--ink); }
  .toast { position:fixed; left:50%; bottom:24px; transform:translateX(-50%); background:var(--ink); max-width:min(560px,88vw);
    color:var(--bg); font-size:13px; padding:8px 16px; border-radius:9px; opacity:0; transition:opacity .2s; pointer-events:none;
    overflow-wrap:anywhere; text-align:center; }
  .toast.show { opacity:1; }
</style></head>
<body><div class="wrap">
  <header>
    <h1><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>admin</h1>
    <span class="apex" id="apex"></span>
    <span class="spacer"></span>
    <span class="meta" id="updated">loading…</span>
    <select class="btn" id="every" title="Auto-refresh interval">
      <option value="5000">every 5s</option>
      <option value="15000">every 15s</option>
      <option value="60000">every 60s</option>
      <option value="0">paused</option>
    </select>
    <button class="btn" id="refresh" title="Refresh now"></button>
    <form method="POST" action="/__admin/logout" style="margin:0"><button class="btn" type="submit" id="logout"></button></form>
  </header>

  <div class="tiles" id="tiles"></div>
  <div class="note">Traffic and stream counters are since the relay started (bodies and messages only, ciphertext for E2E tunnels); claims and devices are persistent.</div>

  <h2 id="h-trends">Trends
    <span class="range" id="range"><button data-r="3600000">1h</button><button data-r="21600000">6h</button><button data-r="86400000">24h</button></span>
  </h2>
  <div class="charts">
    <div class="chart" id="c-req"></div>
    <div class="chart" id="c-bytes"></div>
    <div class="chart" id="c-dev"></div>
  </div>

  <h2 id="h-claims">Claims</h2>
  <div class="tablewrap"><table>
    <thead><tr>
      <th>Subdomain</th><th>Status</th><th>Route</th><th>Devices</th><th>Created</th>
      <th class="num">Requests</th><th class="num">WS</th><th class="num">In</th><th class="num">Out</th><th></th>
    </tr></thead>
    <tbody id="rows"></tbody>
  </table></div>

  <div id="bannedwrap" style="display:none">
    <h2 style="margin-top:26px" id="h-banned">Banned subdomains</h2>
    <div class="banned" id="banned"></div>
  </div>
  <div class="toast" id="toast"></div>
</div>
<script>
'use strict'
const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))

// ── icons (inline, stroke = currentColor) ─────────────────────────────────
const I = {
  users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  down: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  up: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
  clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  power: '<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
  unlock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
  slash: '<circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>',
  undo: '<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>',
  ext: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
  chart: '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
  list: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
  globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  route: '<polygon points="3 11 22 2 13 21 11 13 3 11"/>',
  star: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
}
const icon = (n) => '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + I[n] + '</svg>'
$('refresh').innerHTML = icon('refresh') + 'Refresh'
$('logout').innerHTML = icon('logout') + 'Log out'
$('h-trends').insertAdjacentHTML('afterbegin', icon('chart'))
$('h-claims').insertAdjacentHTML('afterbegin', icon('list'))
$('h-banned').insertAdjacentHTML('afterbegin', icon('slash'))

// ── formatting ────────────────────────────────────────────────────────────
const trim = (s) => s.includes('.') ? s.replace(/\.?0+$/, '') : s
const fmtBytes = (n) => {
  if (n < 1024) return Math.round(n) + ' B'
  const u = ['KB','MB','GB','TB']; let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return trim(n >= 100 ? String(Math.round(n)) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + ' ' + u[i]
}
const fmtInt = (n) => Math.round(n).toLocaleString('en-US')
const fmtNum = (n) => n >= 100 ? fmtInt(n) : trim(n >= 10 ? n.toFixed(1) : n.toFixed(2))
const ago = (ms, now) => {
  const s = Math.max(0, Math.round((now - ms) / 1000))
  if (s < 60) return s + 's ago'
  if (s < 3600) return Math.round(s / 60) + 'm ago'
  if (s < 86400) return Math.round(s / 3600) + 'h ago'
  return Math.round(s / 86400) + 'd ago'
}
const fmtUptime = (ms) => {
  const s = Math.floor(ms / 1000)
  if (s < 3600) return Math.floor(s / 60) + 'm'
  if (s < 86400) return (s / 3600).toFixed(1) + 'h'
  return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h'
}
const fmtDate = (ms) => new Date(ms).toISOString().slice(0, 10)
const pad2 = (n) => (n < 10 ? '0' : '') + n
const fmtClock = (ms) => { const d = new Date(ms); return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) }
const fmtClockS = (ms) => { const d = new Date(ms); return fmtClock(ms) + ':' + pad2(d.getSeconds()) }

// ── persisted view preferences (per browser; absent = defaults) ───────────
const pref = (k, v) => {
  try { if (v === undefined) return localStorage.getItem('dshn_admin_' + k); localStorage.setItem('dshn_admin_' + k, v) } catch { return null }
}
let everyMs = Number(pref('every') ?? 5000)
let rangeMs = Number(pref('range') ?? 21600000)

let toastTimer
function toast(msg) {
  const el = $('toast'); el.textContent = msg; el.classList.add('show')
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('show'), 2600)
}

// ── stat tiles + claims table ─────────────────────────────────────────────
function tile(ic, k, v, s) {
  return '<div class="tile"><div class="k">' + icon(ic) + esc(k) + '</div><div class="v">' + esc(v) + '</div>'
    + (s ? '<div class="s">' + esc(s) + '</div>' : '') + '</div>'
}

let lastState = null
function renderState(st) {
  lastState = st
  $('apex').textContent = st.apex
  const t = st.totals, tr = st.traffic
  $('tiles').innerHTML = [
    tile('users', 'Claims', fmtInt(t.claims), t.onlineSubdomains + ' online now'),
    tile('monitor', 'Devices online', fmtInt(t.onlineDevices), t.knownDevices + ' known'),
    tile('activity', 'Live streams', fmtInt(t.inflightRequests + t.inflightSockets), t.inflightRequests + ' req · ' + t.inflightSockets + ' ws'),
    tile('zap', 'Requests', fmtInt(tr.requests), 'since start'),
    tile('link', 'WS sessions', fmtInt(tr.wsSessions), 'since start'),
    tile('down', 'Traffic in', fmtBytes(tr.bytesIn), 'since start'),
    tile('up', 'Traffic out', fmtBytes(tr.bytesOut), 'since start'),
    tile('clock', 'Uptime', fmtUptime(st.now - st.startedAt), 'started ' + fmtDate(st.startedAt)),
    st.premium
      ? tile('route', 'Premium route', st.premium.tunnels + ' tunnel' + (st.premium.tunnels === 1 ? '' : 's'), st.premium.host + ' · DNS ' + st.premium.dns)
      : tile('route', 'Premium route', 'off', 'not configured on this relay'),
  ].join('')

  const rows = st.claims.map((c) => {
    const devs = c.devices.length === 0 ? '<span class="dim">—</span>' : c.devices.map((d) =>
      '<div class="dev" title="' + esc(d.name) + ' (' + esc(d.id) + ')"><span class="dot' + (d.online ? ' on' : '') + '"></span><span class="n">' + esc(d.name) + '</span>'
      + '<span class="ago">· ' + (d.online ? 'online' : esc(ago(d.lastSeen, st.now))) + '</span></div>'
    ).join('')
    const state = c.online
      ? '<span class="state"><span class="dot on"></span>online · ' + c.liveDevices + '</span>'
      : '<span class="state"><span class="dot"></span>offline</span>'
    const route = c.premium
      ? '<span class="route on" title="premium since ' + esc(fmtDate(c.premium.since)) + (c.premium.dns ? ' · DNS record ' + esc(c.premium.dns.id) : ' · DNS manual') + '">' + icon('star') + 'premium</span>'
      : '<span class="route">standard</span>'
    const routeBtn = !st.premium ? '' : c.premium
      ? '<button class="btn" data-premium="' + esc(c.subdomain) + '" data-on="0" title="Back to the standard route (via the CDN)">' + icon('route') + 'Standard</button>'
      : '<button class="btn gold" data-premium="' + esc(c.subdomain) + '" data-on="1" title="Move onto the premium route (' + esc(st.premium.host) + ')">' + icon('star') + 'Premium</button>'
    return '<tr>'
      + '<td class="sub"><a href="https://' + esc(c.subdomain) + '.' + esc(st.apex) + '" target="_blank" rel="noopener">' + esc(c.subdomain) + icon('ext') + '</a></td>'
      + '<td>' + state + '</td>'
      + '<td>' + route + '</td>'
      + '<td class="devs">' + devs + '</td>'
      + '<td class="dim">' + esc(fmtDate(c.createdAt)) + '</td>'
      + '<td class="num">' + fmtInt(c.traffic.requests) + '</td>'
      + '<td class="num">' + fmtInt(c.traffic.wsSessions) + '</td>'
      + '<td class="num">' + fmtBytes(c.traffic.bytesIn) + '</td>'
      + '<td class="num">' + fmtBytes(c.traffic.bytesOut) + '</td>'
      + '<td class="act">'
      + routeBtn
      + (c.online ? '<button class="btn" data-kick="' + esc(c.subdomain) + '" title="Drop live connections">' + icon('power') + 'Kick</button>' : '')
      + '<button class="btn danger" data-release="' + esc(c.subdomain) + '" title="Delete the claim; name becomes free">' + icon('unlock') + 'Release</button>'
      + '<button class="btn danger" data-ban="' + esc(c.subdomain) + '" title="Delete and block the name">' + icon('slash') + 'Ban</button></td>'
      + '</tr>'
  }).join('')
  $('rows').innerHTML = rows || '<tr><td colspan="10"><div class="empty">No claims yet.</div></td></tr>'

  $('bannedwrap').style.display = st.banned.length > 0 ? '' : 'none'
  $('banned').innerHTML = st.banned.map((s) =>
    '<span class="banchip"><span>' + esc(s) + '</span><button data-unban="' + esc(s) + '">' + icon('undo') + 'Unban</button></span>'
  ).join('')
  $('updated').textContent = 'updated ' + fmtClockS(st.now)
}

// ── trend charts (inline SVG, no libraries) ───────────────────────────────
let history = null // { interval, samples }

/** Per-minute rate of a cumulative column, from neighbouring samples. */
function rateSeries(samples, col) {
  const out = []
  for (let i = 1; i < samples.length; i++) {
    const dt = samples[i][0] - samples[i - 1][0]
    if (dt <= 0) continue
    out.push({ t: samples[i][0], v: Math.max(0, samples[i][col] - samples[i - 1][col]) / dt * 60000 })
  }
  return out
}
/** A level column as-is. */
const levelSeries = (samples, col) => samples.map((s) => ({ t: s[0], v: s[col] }))

/** Bucket points down to at most maxN, aggregating with agg ('mean' | 'max'). */
function downsample(points, maxN, agg) {
  if (points.length <= maxN) return points
  const size = Math.ceil(points.length / maxN)
  const out = []
  for (let i = 0; i < points.length; i += size) {
    const b = points.slice(i, i + size)
    const v = agg === 'max' ? Math.max(...b.map((p) => p.v)) : b.reduce((a, p) => a + p.v, 0) / b.length
    out.push({ t: b[b.length - 1].t, v })
  }
  return out
}

/** Nice y-axis ticks: 0 … a rounded ceiling, ≤4 lines. */
function yTicks(max, integer, binary) {
  if (max <= 0) return [0, 1]
  const rough = max / 3
  // Byte axes step in 1024-based units so ticks read 512 KB / 1 MB, not 488 KB / 977 KB.
  const unit = binary && rough >= 1024 ? Math.pow(1024, Math.floor(Math.log(rough) / Math.log(1024))) : 1
  const p = Math.pow(10, Math.floor(Math.log10(rough / unit)))
  let step = [1, 2, 2.5, 5, 10].map((m) => m * p * unit).find((s) => s >= rough)
  if (integer) step = Math.max(1, Math.round(step))
  const out = []
  for (let v = 0; v <= max + step * 0.999; v += step) out.push(v)
  return out
}

function drawChart(el, spec) {
  const W = el.clientWidth - 28 // card padding
  const H = 150, L = 46, R = 10, T = 8, B = 20
  const series = spec.series.map((s) => ({ ...s, points: downsample(s.points, Math.max(20, Math.floor((W - L - R) / 3)), s.agg) }))
  const legend = series.length > 1
    ? '<span class="legend">' + series.map((s) => '<span><i style="background:' + s.color + '"></i>' + esc(s.name) + '</span>').join('') + '</span>'
    : ''
  const head = '<div class="t"><b>' + esc(spec.title) + '</b><span>' + esc(spec.unit) + '</span>' + legend + '</div>'
  const n = Math.min(...series.map((s) => s.points.length))
  if (!(n >= 2) || W < 80) {
    el.innerHTML = head + '<div class="empty">Collecting… the first trend point lands within a minute of relay start.</div>'
    return
  }
  const t0 = Math.min(...series.map((s) => s.points[0].t))
  const t1 = Math.max(...series.map((s) => s.points[s.points.length - 1].t))
  const ticks = yTicks(Math.max(...series.flatMap((s) => s.points.map((p) => p.v))), spec.integer, spec.binary)
  const yMax = ticks[ticks.length - 1]
  const X = (t) => L + (t1 === t0 ? 0 : (t - t0) / (t1 - t0)) * (W - L - R)
  const Y = (v) => T + (1 - v / yMax) * (H - T - B)
  let g = ''
  for (const v of ticks) {
    g += '<line class="grid" x1="' + L + '" x2="' + (W - R) + '" y1="' + Y(v).toFixed(1) + '" y2="' + Y(v).toFixed(1) + '"/>'
    g += '<text x="' + (L - 6) + '" y="' + (Y(v) + 3.5).toFixed(1) + '" text-anchor="end">' + esc(spec.fmt(v)) + '</text>'
  }
  const nx = Math.max(2, Math.min(5, Math.floor((W - L - R) / 90)))
  for (let i = 0; i < nx; i++) {
    const t = t0 + (t1 - t0) * i / (nx - 1)
    g += '<text x="' + X(t).toFixed(1) + '" y="' + (H - 5) + '" text-anchor="' + (i === 0 ? 'start' : i === nx - 1 ? 'end' : 'middle') + '">' + fmtClock(t) + '</text>'
  }
  g += '<line class="axis" x1="' + L + '" x2="' + (W - R) + '" y1="' + Y(0).toFixed(1) + '" y2="' + Y(0).toFixed(1) + '"/>'
  for (const s of series) {
    let d = ''
    s.points.forEach((p, i) => {
      const x = X(p.t).toFixed(1), y = Y(p.v).toFixed(1)
      if (i === 0) d += 'M' + x + ' ' + y
      else if (spec.step) d += 'H' + x + 'V' + y
      else d += 'L' + x + ' ' + y
    })
    if (series.length === 1) {
      g += '<path class="area" fill="' + s.color + '" d="' + d + 'V' + Y(0).toFixed(1) + 'H' + X(s.points[0].t).toFixed(1) + 'Z"/>'
    }
    g += '<path class="line" stroke="' + s.color + '" d="' + d + '"/>'
  }
  g += '<g class="hov" style="display:none"><line class="xh" y1="' + T + '" y2="' + Y(0).toFixed(1) + '"/>'
    + series.map((s) => '<circle class="pt" r="4" fill="' + s.color + '"/>').join('') + '</g>'
  g += '<rect class="hit" x="' + L + '" y="0" width="' + (W - L - R) + '" height="' + H + '"/>'
  el.innerHTML = head + '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '">' + g + '</svg><div class="tip"></div>'

  // Hover layer: nearest sample by x, crosshair + ringed markers + tooltip.
  const svg = el.querySelector('svg'), hover = svg.querySelector('.hov'), tip = el.querySelector('.tip')
  const xh = hover.querySelector('line'), pts = hover.querySelectorAll('circle')
  const base = series[0].points
  svg.querySelector('.hit').addEventListener('mousemove', (e) => {
    const rect = svg.getBoundingClientRect()
    const mx = (e.clientX - rect.left) * (W / rect.width)
    let best = 0, bd = Infinity
    base.forEach((p, i) => { const d = Math.abs(X(p.t) - mx); if (d < bd) { bd = d; best = i } })
    const t = base[best].t, x = X(t)
    xh.setAttribute('x1', x); xh.setAttribute('x2', x)
    let rows = ''
    series.forEach((s, k) => {
      const p = s.points[Math.min(best, s.points.length - 1)]
      pts[k].setAttribute('cx', X(p.t)); pts[k].setAttribute('cy', Y(p.v))
      rows += '<div><i style="background:' + s.color + '"></i>' + esc(s.name) + ' ' + esc(spec.fmt(p.v)) + '</div>'
    })
    hover.style.display = ''
    tip.innerHTML = '<div class="d">' + fmtClock(t) + '</div>' + rows
    tip.style.display = 'block'
    const left = x / W * rect.width + 14
    tip.style.left = Math.min(left, el.clientWidth - tip.offsetWidth - 8) + 'px'
    tip.style.top = (e.clientY - el.getBoundingClientRect().top - 40) + 'px'
  })
  svg.querySelector('.hit').addEventListener('mouseleave', () => { hover.style.display = 'none'; tip.style.display = 'none' })
}

const s1 = () => getComputedStyle(document.documentElement).getPropertyValue('--s1').trim()
const s2 = () => getComputedStyle(document.documentElement).getPropertyValue('--s2').trim()

function renderCharts() {
  if (history === null) return
  const cutoff = Date.now() - rangeMs
  const samples = history.samples.filter((s) => s[0] >= cutoff)
  const c1 = s1(), c2 = s2()
  drawChart($('c-req'), { title: 'Requests', unit: 'per minute', fmt: fmtNum,
    series: [{ name: 'requests', color: c1, points: rateSeries(samples, 1), agg: 'mean' }] })
  drawChart($('c-bytes'), { title: 'Traffic', unit: 'per minute', fmt: fmtBytes, binary: true,
    series: [{ name: 'in', color: c1, points: rateSeries(samples, 3), agg: 'mean' },
             { name: 'out', color: c2, points: rateSeries(samples, 4), agg: 'mean' }] })
  drawChart($('c-dev'), { title: 'Devices online', unit: 'count', fmt: fmtInt, integer: true, step: true,
    series: [{ name: 'devices', color: c1, points: levelSeries(samples, 5), agg: 'max' }] })
  for (const b of $('range').querySelectorAll('button')) b.classList.toggle('on', Number(b.dataset.r) === rangeMs)
}

// ── data loading + refresh cadence ────────────────────────────────────────
async function loadState() {
  try {
    const res = await fetch('/__admin/api/state', { headers: { accept: 'application/json' } })
    if (res.status === 401) { location.reload(); return }
    renderState(await res.json())
  } catch { $('updated').textContent = 'refresh failed' }
}
async function loadHistory() {
  try {
    const res = await fetch('/__admin/api/history', { headers: { accept: 'application/json' } })
    if (res.status === 401) { location.reload(); return }
    history = await res.json()
    renderCharts()
  } catch { /* charts keep their last render */ }
}
const loadAll = () => { loadState(); loadHistory() }

let stateTimer = null
function schedule() {
  clearInterval(stateTimer); stateTimer = null
  if (everyMs > 0) stateTimer = setInterval(() => { if (!document.hidden) loadState() }, everyMs)
}
setInterval(() => { if (!document.hidden) loadHistory() }, 30000) // matches the relay's sample interval
$('every').value = String(everyMs)
$('every').addEventListener('change', () => { everyMs = Number($('every').value); pref('every', everyMs); schedule() })
$('range').addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return
  rangeMs = Number(b.dataset.r); pref('range', rangeMs); renderCharts()
})
let resizeTimer
window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(renderCharts, 150) })
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', renderCharts)

async function act(path, subdomain, extra) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(Object.assign({ subdomain }, extra || {})),
  })
  if (res.status === 401) { location.reload(); return null }
  return res.json().catch(() => null)
}

document.addEventListener('click', async (e) => {
  const b = e.target.closest('button'); if (!b) return
  const kick = b.dataset.kick, release = b.dataset.release, ban = b.dataset.ban, unban = b.dataset.unban, premium = b.dataset.premium
  if (premium) {
    const on = b.dataset.on === '1'
    const host = lastState && lastState.premium ? lastState.premium.host : '?'
    const msg = on
      ? 'Move "' + premium + '" onto the premium route?\n\nA dedicated DNS record points ' + premium + '.' + lastState.apex + ' at ' + host + ' (DNS only, bypassing the CDN); its agent is told to reconnect through that path. Visitors follow within the DNS TTL.'
      : 'Move "' + premium + '" back to the standard route?\n\nIts dedicated DNS record is removed (the CDN wildcard takes over again) and its agent reconnects through the default relay host.'
    if (!confirm(msg)) return
    const r = await act('/__admin/api/premium', premium, { enabled: on })
    if (r) {
      if (!r.ok) toast('Route change failed: ' + (r.error || '?'))
      else if (r.dns === 'manual') toast((on ? 'Premium route set — now ADD DNS: ' : 'Standard route set — now REMOVE DNS: ') + r.record.type + ' ' + r.record.name + ' → ' + r.record.content + ' (DNS only)')
      else toast((on ? 'Premium route enabled for ' : 'Back to standard route: ') + premium)
    }
    loadState()
  } else if (kick) {
    if (!confirm('Kick every live device of "' + kick + '" offline? Their agents will auto-reconnect unless stopped.')) return
    const r = await act('/__admin/api/kick', kick)
    if (r) toast(r.ok ? 'Kicked ' + r.kicked + ' device(s) of ' + kick : 'Kick failed: ' + (r.error || '?'))
    loadState()
  } else if (release) {
    const typed = prompt('Release "' + release + '"?\\n\\nThis deletes the claim: the user is kicked offline, their password stops working, and the subdomain becomes claimable by anyone (including their own auto-reconnecting agent). Type the subdomain to confirm:')
    if (typed !== release) { if (typed !== null) toast('Not released — name did not match.'); return }
    const r = await act('/__admin/api/release', release)
    if (r) toast(r.ok ? 'Released ' + release : 'Release failed: ' + (r.error || '?'))
    loadState()
  } else if (ban) {
    const typed = prompt('Ban "' + ban + '"?\\n\\nThis kicks the user, deletes the claim, and blocks the subdomain from being claimed again until unbanned. Type the subdomain to confirm:')
    if (typed !== ban) { if (typed !== null) toast('Not banned — name did not match.'); return }
    const r = await act('/__admin/api/ban', ban)
    if (r) toast(r.ok ? 'Banned ' + ban : 'Ban failed: ' + (r.error || '?'))
    loadState()
  } else if (unban) {
    const r = await act('/__admin/api/unban', unban)
    if (r) toast(r.ok ? 'Unbanned ' + unban : 'Unban failed: ' + (r.error || '?'))
    loadState()
  }
})
$('refresh').addEventListener('click', loadAll)
document.addEventListener('visibilitychange', () => { if (!document.hidden) loadAll() })
schedule()
loadAll()
</script></body></html>`
}
