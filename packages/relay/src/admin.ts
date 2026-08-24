/**
 * The operator admin panel, served on the bare apex under `/__admin`. It shows
 * platform-wide numbers (claims, live devices, traffic since the relay started)
 * and manages users: a claim can be kicked offline or released entirely.
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
  h1 { font-size:15px; margin:0 0 4px; font-weight:600; }
  .host { font-family:ui-monospace,Menlo,monospace; opacity:.7; font-size:13px; margin-bottom:16px; }
  .hint { font-size:13px; opacity:.7; margin:0 0 16px; }
  .err { font-size:13px; color:#e5484d; margin:0 0 16px; }
  input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:9px;
    border:1px solid rgba(128,134,142,.4); background:transparent; color:inherit; font-size:15px; }
  button { width:100%; margin-top:12px; padding:10px; border:0; border-radius:9px;
    background:#4176e6; color:#fff; font-size:15px; cursor:pointer; }
</style></head>
<body><form class="card" method="POST" action="/__admin/login">
  <h1>${escapeHtml(apex)} · admin</h1>
  <div class="host">relay operator panel</div>
  ${notice}
  <input type="password" name="password" placeholder="Admin password" autofocus autocomplete="current-password" required>
  <button type="submit">Enter</button>
</form></body></html>`
}

/**
 * The admin dashboard. A self-contained page (the relay serves no assets) that
 * renders from `GET /__admin/api/state` and refreshes itself: stat tiles for
 * the platform totals, then one table row per claim with kick / release
 * actions. All user-controlled strings (subdomains, device names) are escaped
 * client-side before touching the DOM.
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
    --bg:#0f1115; --ink:#e8eaed; --ink2:rgba(232,234,237,.62); --ink3:rgba(232,234,237,.4);
    --card:rgba(128,134,142,.12); --line:rgba(128,134,142,.25);
    --accent:#4176e6; --good:#3aa675; --bad:#e5484d;
  }
  @media (prefers-color-scheme: light) { :root {
    --bg:#f4f5f7; --ink:#1c1e21; --ink2:rgba(28,30,33,.62); --ink3:rgba(28,30,33,.4);
    --card:rgba(128,134,142,.12); --line:rgba(128,134,142,.3);
  } }
  body { margin:0; min-height:100vh; font:14px/1.5 system-ui,sans-serif; background:var(--bg); color:var(--ink); }
  .wrap { max-width:980px; margin:0 auto; padding:28px 20px 60px; }
  header { display:flex; align-items:baseline; gap:10px; margin-bottom:22px; }
  h1 { font-size:16px; font-weight:600; margin:0; }
  .apex { font-family:ui-monospace,Menlo,monospace; font-size:13px; color:var(--ink2); }
  .spacer { flex:1; }
  .meta { font-size:12px; color:var(--ink3); }
  .btn { border:1px solid var(--line); background:transparent; color:var(--ink2); font-size:12px;
    padding:5px 11px; border-radius:8px; cursor:pointer; }
  .btn:hover { border-color:var(--accent); color:var(--ink); }
  .tiles { display:grid; grid-template-columns:repeat(auto-fill,minmax(148px,1fr)); gap:10px; margin-bottom:10px; }
  .tile { background:var(--card); border-radius:12px; padding:13px 15px 11px; }
  .tile .k { font-size:11px; letter-spacing:.04em; text-transform:uppercase; color:var(--ink3); margin-bottom:2px; }
  .tile .v { font-size:22px; font-weight:600; font-variant-numeric:tabular-nums; }
  .tile .s { font-size:11px; color:var(--ink3); }
  .note { font-size:11px; color:var(--ink3); margin:2px 2px 26px; }
  h2 { font-size:13px; font-weight:600; margin:0 0 10px; color:var(--ink2); }
  .tablewrap { overflow-x:auto; border:1px solid var(--line); border-radius:12px; }
  table { border-collapse:collapse; width:100%; min-width:760px; }
  th { text-align:left; font-size:11px; letter-spacing:.04em; text-transform:uppercase; color:var(--ink3);
    font-weight:500; padding:9px 12px; border-bottom:1px solid var(--line); white-space:nowrap; }
  td { padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; font-variant-numeric:tabular-nums; }
  tr:last-child td { border-bottom:0; }
  td.num, th.num { text-align:right; }
  .sub a { color:var(--ink); text-decoration:none; font-family:ui-monospace,Menlo,monospace; font-size:13px; }
  .sub a:hover { color:var(--accent); }
  .dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--ink3);
    margin-right:6px; vertical-align:1px; }
  .dot.on { background:var(--good); box-shadow:0 0 0 3px rgba(58,166,117,.18); }
  .state { font-size:12px; color:var(--ink2); white-space:nowrap; }
  .dev { font-size:12px; color:var(--ink2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:220px; }
  .dev .ago { color:var(--ink3); }
  .dim { color:var(--ink3); font-size:12px; }
  .act { white-space:nowrap; text-align:right; }
  .act .btn.danger:hover { border-color:var(--bad); color:var(--bad); }
  .empty { padding:22px; text-align:center; color:var(--ink3); font-size:13px; }
  .banned { display:flex; flex-wrap:wrap; gap:8px; }
  .banchip { display:inline-flex; align-items:center; gap:8px; border:1px solid var(--line);
    border-radius:99px; padding:4px 6px 4px 12px; font-family:ui-monospace,Menlo,monospace; font-size:12px; }
  .banchip button { border:0; background:var(--card); color:var(--ink2); font-size:11px;
    padding:3px 9px; border-radius:99px; cursor:pointer; font-family:system-ui,sans-serif; }
  .banchip button:hover { color:var(--ink); }
  .toast { position:fixed; left:50%; bottom:24px; transform:translateX(-50%); background:var(--ink);
    color:var(--bg); font-size:13px; padding:8px 16px; border-radius:9px; opacity:0; transition:opacity .2s; pointer-events:none; }
  .toast.show { opacity:1; }
</style></head>
<body><div class="wrap">
  <header>
    <h1>admin</h1><span class="apex" id="apex"></span>
    <span class="spacer"></span>
    <span class="meta" id="updated"></span>
    <button class="btn" id="refresh">Refresh</button>
    <form method="POST" action="/__admin/logout" style="margin:0"><button class="btn" type="submit">Log out</button></form>
  </header>

  <div class="tiles" id="tiles"></div>
  <div class="note">Traffic and stream counters are since the relay started; claims and devices are persistent.</div>

  <h2>Claims</h2>
  <div class="tablewrap"><table>
    <thead><tr>
      <th>Subdomain</th><th>Status</th><th>Devices</th><th>Created</th>
      <th class="num">Requests</th><th class="num">WS</th><th class="num">In</th><th class="num">Out</th><th></th>
    </tr></thead>
    <tbody id="rows"></tbody>
  </table></div>

  <div id="bannedwrap" style="display:none">
    <h2 style="margin-top:26px">Banned subdomains</h2>
    <div class="banned" id="banned"></div>
  </div>
  <div class="toast" id="toast"></div>
</div>
<script>
'use strict'
const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
const fmtBytes = (n) => {
  if (n < 1024) return n + ' B'
  const u = ['KB','MB','GB','TB']; let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return (n >= 100 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i]
}
const fmtInt = (n) => n.toLocaleString('en-US')
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

let toastTimer
function toast(msg) {
  const el = $('toast'); el.textContent = msg; el.classList.add('show')
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('show'), 2600)
}

function tile(k, v, s) {
  return '<div class="tile"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + '</div>'
    + (s ? '<div class="s">' + esc(s) + '</div>' : '') + '</div>'
}

function render(st) {
  $('apex').textContent = st.apex
  const t = st.totals, tr = st.traffic
  $('tiles').innerHTML = [
    tile('Claims', fmtInt(t.claims), t.onlineSubdomains + ' online now'),
    tile('Devices online', fmtInt(t.onlineDevices), t.knownDevices + ' known'),
    tile('Live streams', fmtInt(t.inflightRequests + t.inflightSockets), t.inflightRequests + ' req · ' + t.inflightSockets + ' ws'),
    tile('Requests', fmtInt(tr.requests), 'since start'),
    tile('WS sessions', fmtInt(tr.wsSessions), 'since start'),
    tile('Traffic in', fmtBytes(tr.bytesIn), 'bodies, since start'),
    tile('Traffic out', fmtBytes(tr.bytesOut), 'bodies, since start'),
    tile('Uptime', fmtUptime(st.now - st.startedAt), 'started ' + fmtDate(st.startedAt)),
  ].join('')

  const rows = st.claims.map((c) => {
    const devs = c.devices.length === 0 ? '<span class="dim">—</span>' : c.devices.map((d) =>
      '<div class="dev"><span class="dot' + (d.online ? ' on' : '') + '"></span>' + esc(d.name)
      + ' <span class="ago">· ' + (d.online ? 'online' : esc(ago(d.lastSeen, st.now))) + '</span></div>'
    ).join('')
    const state = c.online
      ? '<span class="state"><span class="dot on"></span>online · ' + c.liveDevices + '</span>'
      : '<span class="state"><span class="dot"></span>offline</span>'
    return '<tr>'
      + '<td class="sub"><a href="https://' + esc(c.subdomain) + '.' + esc(st.apex) + '" target="_blank" rel="noopener">' + esc(c.subdomain) + '</a></td>'
      + '<td>' + state + '</td>'
      + '<td>' + devs + '</td>'
      + '<td class="dim">' + esc(fmtDate(c.createdAt)) + '</td>'
      + '<td class="num">' + fmtInt(c.traffic.requests) + '</td>'
      + '<td class="num">' + fmtInt(c.traffic.wsSessions) + '</td>'
      + '<td class="num">' + fmtBytes(c.traffic.bytesIn) + '</td>'
      + '<td class="num">' + fmtBytes(c.traffic.bytesOut) + '</td>'
      + '<td class="act">'
      + (c.online ? '<button class="btn" data-kick="' + esc(c.subdomain) + '">Kick</button> ' : '')
      + '<button class="btn danger" data-release="' + esc(c.subdomain) + '">Release</button> '
      + '<button class="btn danger" data-ban="' + esc(c.subdomain) + '">Ban</button></td>'
      + '</tr>'
  }).join('')
  $('rows').innerHTML = rows || '<tr><td colspan="9"><div class="empty">No claims yet.</div></td></tr>'

  $('bannedwrap').style.display = st.banned.length > 0 ? '' : 'none'
  $('banned').innerHTML = st.banned.map((s) =>
    '<span class="banchip">' + esc(s) + '<button data-unban="' + esc(s) + '">Unban</button></span>'
  ).join('')
  $('updated').textContent = 'updated ' + new Date(st.now).toLocaleTimeString()
}

async function load() {
  try {
    const res = await fetch('/__admin/api/state', { headers: { accept: 'application/json' } })
    if (res.status === 401) { location.reload(); return }
    render(await res.json())
  } catch { $('updated').textContent = 'refresh failed' }
}

async function act(path, subdomain) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ subdomain }),
  })
  if (res.status === 401) { location.reload(); return null }
  return res.json().catch(() => null)
}

document.addEventListener('click', async (e) => {
  const b = e.target.closest('button'); if (!b) return
  const kick = b.dataset.kick, release = b.dataset.release, ban = b.dataset.ban, unban = b.dataset.unban
  if (kick) {
    if (!confirm('Kick every live device of "' + kick + '" offline? Their agents will auto-reconnect unless stopped.')) return
    const r = await act('/__admin/api/kick', kick)
    if (r) toast(r.ok ? 'Kicked ' + r.kicked + ' device(s) of ' + kick : 'Kick failed: ' + (r.error || '?'))
    load()
  } else if (release) {
    const typed = prompt('Release "' + release + '"?\\n\\nThis deletes the claim: the user is kicked offline, their password stops working, and the subdomain becomes claimable by anyone (including their own auto-reconnecting agent). Type the subdomain to confirm:')
    if (typed !== release) { if (typed !== null) toast('Not released — name did not match.'); return }
    const r = await act('/__admin/api/release', release)
    if (r) toast(r.ok ? 'Released ' + release : 'Release failed: ' + (r.error || '?'))
    load()
  } else if (ban) {
    const typed = prompt('Ban "' + ban + '"?\\n\\nThis kicks the user, deletes the claim, and blocks the subdomain from being claimed again until unbanned. Type the subdomain to confirm:')
    if (typed !== ban) { if (typed !== null) toast('Not banned — name did not match.'); return }
    const r = await act('/__admin/api/ban', ban)
    if (r) toast(r.ok ? 'Banned ' + ban : 'Ban failed: ' + (r.error || '?'))
    load()
  } else if (unban) {
    const r = await act('/__admin/api/unban', unban)
    if (r) toast(r.ok ? 'Unbanned ' + unban : 'Unban failed: ' + (r.error || '?'))
    load()
  }
})
$('refresh').addEventListener('click', load)
setInterval(() => { if (!document.hidden) load() }, 10000)
document.addEventListener('visibilitychange', () => { if (!document.hidden) load() })
load()
</script></body></html>`
}
