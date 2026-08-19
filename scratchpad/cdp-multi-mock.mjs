// Real-browser check of the multi-device SWITCHER UI on the live show.ds.hn
// page, with the device list MOCKED in the page (per the standing rule: never
// bind a second agent to the user's production subdomain — mock the browser's
// view instead). Verifies: the footer row appears when /__dshn/devices reports
// multi, the popover lists devices with online/offline states, an offline row
// is disabled, and clicking a live row POSTs the selection and reloads.
//
//   DSHN_JAR=<jar> node scratchpad/cdp-multi-mock.mjs
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
const require = createRequire(new URL('../packages/agent/package.json', import.meta.url))
const { WebSocket } = require('ws')

const HOST = 'show.ds.hn'
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

let failures = 0
const check = (name, cond, detail = '') => {
  if (cond) console.log(`  ok  ${name}`)
  else { failures++; console.error(`FAIL  ${name} ${detail}`) }
}

const status = await fetch('http://127.0.0.1:3080/dshn/status').then((r) => r.json())
const e2ePassword = status.e2ePassword
const sess = readFileSync(process.env.DSHN_JAR, 'utf8').split('\n').find((l) => l.includes('dshn_sess'))?.trim().split(/\s+/).pop()
if (!e2ePassword || !sess) { console.error('missing credentials'); process.exit(1) }

const profile = mkdtempSync(join(tmpdir(), 'dshn-cdp-multi-'))
const chrome = spawn(CHROME, [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--disable-extensions', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] })
const port = await new Promise((resolve, reject) => {
  let buf = ''
  const timer = setTimeout(() => reject(new Error('no DevTools port')), 15000)
  chrome.stderr.on('data', (c) => {
    buf += c.toString()
    const m = /DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//.exec(buf)
    if (m) { clearTimeout(timer); resolve(Number(m[1])) }
  })
})
const targets = await fetch(`http://127.0.0.1:${port}/json`).then((r) => r.json())
const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl, { maxPayload: 64 * 1024 * 1024 })
await new Promise((r) => ws.on('open', r))

let msgId = 0
const pending = new Map()
ws.on('message', (data) => {
  const msg = JSON.parse(data.toString())
  if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id) }
})
const cdp = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++msgId
  pending.set(id, (msg) => (msg.error ? reject(new Error(`${method}: ${msg.error.message}`)) : resolve(msg.result)))
  ws.send(JSON.stringify({ id, method, params }))
})
const evalJs = async (expression) => {
  const r = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (r.exceptionDetails) throw new Error(`eval: ${r.exceptionDetails.text}`)
  return r.result.value
}
const until = async (expr, what, ms = 30000) => {
  const start = Date.now()
  while (Date.now() - start < ms) {
    if (await evalJs(expr)) return
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error(`timeout: ${what}`)
}

try {
  await cdp('Page.enable')
  await cdp('Network.enable')
  await cdp('Network.setCookie', { name: 'dshn_sess', value: sess, domain: HOST, path: '/', secure: true, httpOnly: true })
  await cdp('Page.navigate', { url: `https://${HOST}/` })

  // Unlock the E2E gate first (the app only mounts its slots afterwards).
  await until('!!document.querySelector("#dshn-e2e-pw")', 'gate')
  await cdp('Runtime.evaluate', {
    expression: `(() => {
      const pw = document.querySelector('#dshn-e2e-pw'); pw.value = ${JSON.stringify(e2ePassword)}
      document.querySelector('#dshn-e2e-remember').checked = false
      pw.closest('form').requestSubmit()
    })()`,
  })
  await until('window.__dshnE2E && window.__dshnE2E.stage === "unlocked"', 'unlock')

  // Mock the device list (and the select POST) in the page: two devices, one
  // offline. The switcher's 10s poll picks this up on its next tick.
  await evalJs(`(() => {
    const real = window.fetch
    window.__mockLog = []
    window.fetch = function (input, init) {
      const url = typeof input === 'string' ? input : (input && input.url) || String(input)
      if (url.indexOf('/__dshn/devices') === 0) {
        return Promise.resolve(new Response(JSON.stringify({
          multi: true, live: 2, current: null,
          devices: [
            { id: 'devlocal', name: 'Laptop A', online: true, current: false },
            { id: 'devother', name: 'Desktop B', online: false, current: false },
          ],
        }), { status: 200, headers: { 'content-type': 'application/json' } }))
      }
      if (url.indexOf('/__dshn/select') === 0) {
        try { localStorage.setItem('__dshn_seltest', String(init && init.body)) } catch {}
        return Promise.resolve(new Response(JSON.stringify({ ok: true, device: 'devlocal' }), { status: 200, headers: { 'content-type': 'application/json' } }))
      }
      return real.apply(this, arguments)
    }
    return true
  })()`)

  await until('!!document.querySelector(".dshn-frow")', 'switcher row appears after the poll tick')
  check('switcher footer row appears in multi mode', true)
  check('row shows the live/total device count', (await evalJs('document.querySelector(".dshn-frow-trail").textContent')) === '2/2')

  await evalJs('document.querySelector(".dshn-frow").click(); true')
  await until('!!document.querySelector(".dshn-devpop")', 'popover opens')
  const rows = await evalJs(`Array.from(document.querySelectorAll('.dshn-devrow')).map((b) => ({
    name: b.querySelector('.dshn-devrow-name').textContent, disabled: b.disabled,
    tag: (b.querySelector('.dshn-devrow-tag') || {}).textContent || '',
  }))`)
  check('popover lists both devices', rows.length === 2, JSON.stringify(rows))
  check('live device row is clickable', rows[0].name === 'Laptop A' && rows[0].disabled === false, JSON.stringify(rows[0]))
  check('offline device row is disabled and tagged', rows[1].name === 'Desktop B' && rows[1].disabled === true && rows[1].tag.length > 0, JSON.stringify(rows[1]))

  // Click the live device: the select POST fires and the page reloads.
  await evalJs('document.querySelectorAll(".dshn-devrow")[0].click(); true')
  await until('!document.querySelector(".dshn-devpop")', 'page reloads after select (popover gone)')
  await until('window.__dshnE2E !== undefined', 'page came back')
  const sel = await evalJs('localStorage.getItem("__dshn_seltest")')
  check('clicking a device POSTs the selection', sel === JSON.stringify({ device: 'devlocal' }), String(sel))
  check('mock gone after reload (real page again)', (await evalJs('window.__mockLog === undefined')) === true)
} finally {
  ws.close()
  chrome.kill()
  await new Promise((r) => setTimeout(r, 300))
  rmSync(profile, { recursive: true, force: true })
}

console.log(failures === 0 ? '\nALL OK' : `\n${failures} FAILURES`)
process.exit(failures === 0 ? 0 : 1)
