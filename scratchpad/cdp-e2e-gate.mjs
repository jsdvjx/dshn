// Real-browser acceptance of the LIVE show.ds.hn page with the NEW client.js:
// the E2E unlock gate must still work (type password → unlock → /api decrypts),
// "remember on this device" must save under the storage key scheme and
// auto-unlock on reload, and the multi-device switcher must stay hidden while
// only one device is live. Credentials come from the local agent's loopback
// status; nothing secret is printed.
//
//   node scratchpad/cdp-e2e-gate.mjs
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
const require = createRequire(new URL('../packages/agent/package.json', import.meta.url))
const { WebSocket } = require('ws')

const HOST = 'show.ds.hn'
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const JAR = process.env.DSHN_JAR // netscape cookie jar from the curl login

let failures = 0
const check = (name, cond, detail = '') => {
  if (cond) console.log(`  ok  ${name}`)
  else { failures++; console.error(`FAIL  ${name} ${detail}`) }
}

// ── credentials (kept off stdout) ───────────────────────────────────────────
const status = await fetch('http://127.0.0.1:3080/dshn/status').then((r) => r.json())
const e2ePassword = status.e2ePassword
if (!e2ePassword) { console.error('no e2e password on loopback status — is dsh running?'); process.exit(1) }
const sess = readFileSync(JAR, 'utf8').split('\n').find((l) => l.includes('dshn_sess'))?.trim().split(/\s+/).pop()
if (!sess) { console.error('no dshn_sess in jar'); process.exit(1) }

// ── launch headless chrome ──────────────────────────────────────────────────
const profile = mkdtempSync(join(tmpdir(), 'dshn-cdp-'))
const chrome = spawn(CHROME, [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--disable-extensions', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] })
const port = await new Promise((resolve, reject) => {
  let buf = ''
  const timer = setTimeout(() => reject(new Error('chrome did not report DevTools port')), 15000)
  chrome.stderr.on('data', (c) => {
    buf += c.toString()
    const m = /DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//.exec(buf)
    if (m) { clearTimeout(timer); resolve(Number(m[1])) }
  })
})

const targets = await fetch(`http://127.0.0.1:${port}/json`).then((r) => r.json())
const page = targets.find((t) => t.type === 'page')
const ws = new WebSocket(page.webSocketDebuggerUrl, { maxPayload: 64 * 1024 * 1024 })
await new Promise((r) => ws.on('open', r))

let msgId = 0
const pending = new Map()
const errors = []
ws.on('message', (data) => {
  const msg = JSON.parse(data.toString())
  if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id) }
  if (msg.method === 'Runtime.exceptionThrown') {
    errors.push(msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text || 'exception')
  }
})
const cdp = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++msgId
  pending.set(id, (msg) => (msg.error ? reject(new Error(`${method}: ${msg.error.message}`)) : resolve(msg.result)))
  ws.send(JSON.stringify({ id, method, params }))
})
const evalJs = async (expression) => {
  const r = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.text} :: ${expression.slice(0, 80)}`)
  return r.result.value
}
const until = async (expr, what, ms = 25000) => {
  const start = Date.now()
  while (Date.now() - start < ms) {
    if (await evalJs(expr)) return
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error(`timeout: ${what}`)
}

try {
  await cdp('Runtime.enable')
  await cdp('Page.enable')
  await cdp('Network.enable')
  await cdp('Network.setCookie', { name: 'dshn_sess', value: sess, domain: HOST, path: '/', secure: true, httpOnly: true })

  // 1. Fresh visit: the gate must appear (E2E is ON for this subdomain).
  await cdp('Page.navigate', { url: `https://${HOST}/` })
  await until('!!document.querySelector("#dshn-e2e-pw")', 'unlock gate appears')
  check('gate appears on a fresh visit', true)
  check('shim stage is gating', await evalJs('window.__dshnE2E && window.__dshnE2E.stage') === 'gating')

  // 2. Wrong password is rejected and the gate stays.
  await evalJs(`(async () => {
    const pw = document.querySelector('#dshn-e2e-pw'); pw.value = 'definitely-wrong-pw'
    document.querySelector('#dshn-e2e-pw').closest('form').requestSubmit()
  })()`)
  await until('document.querySelector("#dshn-e2e-err") && document.querySelector("#dshn-e2e-err").style.display !== "none"', 'wrong-pw notice')
  check('wrong password rejected with a notice', !!(await evalJs('document.querySelector("#dshn-e2e-pw")')))

  // 3. Correct password + remember → unlock; key saved under the expected name.
  await cdp('Runtime.evaluate', {
    expression: `(() => {
      const pw = document.querySelector('#dshn-e2e-pw'); pw.value = ${JSON.stringify(e2ePassword)}
      document.querySelector('#dshn-e2e-remember').checked = true
      pw.closest('form').requestSubmit()
    })()`,
    returnByValue: true,
  })
  await until('window.__dshnE2E && window.__dshnE2E.stage === "unlocked"', 'unlock')
  check('correct password unlocks', true)
  check('gate removed after unlock', await evalJs('!document.querySelector("#dshn-e2e-pw")'))
  const keys = await evalJs('Object.keys(localStorage).filter((k) => k.startsWith("dshn:e2e:"))')
  // Old agent host half sends no device id yet, so the legacy host-only key is
  // the correct outcome here; after the dsh restart it becomes host:device.
  check('remember saved under one dshn:e2e key', Array.isArray(keys) && keys.length === 1, JSON.stringify(keys))
  check('key is host(-device) scoped', keys[0].startsWith(`dshn:e2e:${HOST}`), keys[0])

  // 4. Sealed /api round-trip through the patched fetch decrypts.
  const apiStatus = await evalJs(`fetch('/api/host.describe', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }).then((r) => r.status)`)
  check('/api decrypts through the shim', apiStatus === 200, `status=${apiStatus}`)

  // 5. Reload → silent auto-unlock from the remembered password, no gate.
  await cdp('Page.navigate', { url: `https://${HOST}/` })
  await until('window.__dshnE2E && window.__dshnE2E.stage === "unlocked"', 'auto-unlock after reload')
  check('auto-unlock on reload', await evalJs('window.__dshnE2E.autounlock === true'))
  check('no gate on reload', await evalJs('!document.querySelector("#dshn-e2e-pw")'))

  // 6. Single device → no multi switcher anywhere on the remote page.
  await new Promise((r) => setTimeout(r, 2500)) // let slots mount + devStore poll
  check('device switcher hidden with one device', await evalJs('!document.querySelector(".dshn-devrow") && !document.querySelector(".dshn-frow")'))

  const fatal = errors.filter((e) => !/favicon/i.test(e))
  check('no page exceptions', fatal.length === 0, fatal.slice(0, 3).join(' | '))
} finally {
  ws.close()
  chrome.kill()
  await new Promise((r) => setTimeout(r, 300))
  rmSync(profile, { recursive: true, force: true })
}

console.log(failures === 0 ? '\nALL OK' : `\n${failures} FAILURES`)
process.exit(failures === 0 ? 0 : 1)
