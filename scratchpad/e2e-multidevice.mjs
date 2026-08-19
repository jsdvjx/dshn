// Loopback E2E for multi-device: TWO real AgentTunnels (compiled lib) claim ONE
// subdomain against a real RelayServer, each fronting its own fake dsh origin.
// Verifies: both HELLOs coexist, unselected API traffic stays on the first
// device, the picker appears on navigation, cookie selection routes HTTP AND
// WebSocket upgrades to the chosen device, and switching back works.
//
// Run from the repo root after `pnpm -r run build`:
//   node scratchpad/e2e-multidevice.mjs
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { ClaimStore } from '../packages/relay/lib/claims.js'
import { RelayServer } from '../packages/relay/lib/server.js'
import { AgentTunnel, fileStore } from '../packages/agent/lib/index.js'

// `ws` lives in the packages' own node_modules (pnpm strict layout), not here.
const require = createRequire(new URL('../packages/agent/package.json', import.meta.url))
const { WebSocketServer, WebSocket } = require('ws')

const APEX = 'test.local'
const SUB = 'multitest'
const HOST = `${SUB}.${APEX}`
const PASSWORD = 'password123'

let failures = 0
function check(name, cond, detail = '') {
  if (cond) console.log(`  ok  ${name}`)
  else { failures++; console.error(`FAIL  ${name} ${detail}`) }
}

/** A fake dsh origin: marks every HTTP response and WS message with its tag. */
function fakeOrigin(tag) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`${tag}:${req.url}`)
  })
  const wss = new WebSocketServer({ server })
  wss.on('connection', (ws) => ws.send(`ws-${tag}`))
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })))
}

function request(port, path, { cookie, accept, method = 'GET', contentType, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }))
    })
    req.setHeader('host', HOST)
    if (cookie) req.setHeader('cookie', cookie)
    if (accept) req.setHeader('accept', accept)
    if (contentType) req.setHeader('content-type', contentType)
    req.on('error', reject)
    req.end(body)
  })
}

function wsMessage(port, path, cookie) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`, { headers: { host: HOST, cookie } })
    const timer = setTimeout(() => { ws.terminate(); reject(new Error('ws timeout')) }, 3000)
    ws.on('message', (data) => { clearTimeout(timer); ws.close(); resolve(data.toString()) })
    ws.on('error', (err) => { clearTimeout(timer); reject(err) })
  })
}

async function until(cond, what, ms = 4000) {
  const start = Date.now()
  while (Date.now() - start < ms) {
    if (await cond()) return
    await new Promise((r) => setTimeout(r, 40))
  }
  throw new Error(`timeout waiting for ${what}`)
}

const dir = mkdtempSync(join(tmpdir(), 'dshn-e2e-mdev-'))
const relay = new RelayServer({ apex: APEX, port: 0, cookieSecret: 's3cret', claims: ClaimStore.fromFile(join(dir, 'claims.json')) })
await new Promise((r) => relay.listen(r))
const relayPort = relay.port()

const originA = await fakeOrigin('A')
const originB = await fakeOrigin('B')

function makeTunnel(originPort, stateName) {
  const config = {
    enabled: true,
    relayHost: `ws://127.0.0.1:${relayPort}`,
    localHost: '127.0.0.1',
    localPort: originPort,
    originCa: '',
    statePath: join(dir, stateName), // distinct state path → distinct derived deviceId
  }
  return new AgentTunnel(config, () => originPort, fileStore(config.statePath))
}
const tunnelA = makeTunnel(originA.port, 'state-a.json')
const tunnelB = makeTunnel(originB.port, 'state-b.json')

check('derived device ids differ', tunnelA.deviceId !== tunnelB.deviceId, `${tunnelA.deviceId} vs ${tunnelB.deviceId}`)

tunnelA.configure(SUB, PASSWORD)
await until(() => tunnelA.status.connected, 'tunnel A connected')
tunnelB.configure(SUB, PASSWORD)
await until(() => tunnelB.status.connected, 'tunnel B connected')
check('both tunnels connected at once', tunnelA.status.connected && tunnelB.status.connected)

const login = await request(relayPort, '/__dshn/login', {
  method: 'POST', contentType: 'application/x-www-form-urlencoded', body: `password=${PASSWORD}`,
})
const session = String(login.headers['set-cookie'][0]).split(';', 1)[0]
check('login succeeds', login.status === 302, `status=${login.status}`)

const api = await request(relayPort, '/api/probe', { cookie: session, accept: 'application/json' })
check('unselected API stays on first device', api.body === 'A:/api/probe', api.body)

const nav = await request(relayPort, '/', { cookie: session, accept: 'text/html' })
check('unselected navigation gets the picker', nav.body.includes('/__dshn/select'), nav.body.slice(0, 80))

const list = JSON.parse((await request(relayPort, '/__dshn/devices', { cookie: session, accept: 'application/json' })).body)
check('device list reports multi with 2 live', list.multi === true && list.live === 2, JSON.stringify(list))

const idB = tunnelB.deviceId
const sel = await request(relayPort, '/__dshn/select', {
  method: 'POST', cookie: session, contentType: 'application/json', accept: 'application/json',
  body: JSON.stringify({ device: idB }),
})
const devCookie = String(sel.headers['set-cookie'][0]).split(';', 1)[0]
const both = `${session}; ${devCookie}`
check('select answers with the device cookie', devCookie === `dshn_dev=${idB}`, devCookie)

const navB = await request(relayPort, '/', { cookie: both, accept: 'text/html' })
check('selected navigation routes to device B', navB.body === 'B:/', navB.body)
const wsB = await wsMessage(relayPort, '/api/events.test', both)
check('selected WebSocket routes to device B', wsB === 'ws-B', wsB)

const selA = await request(relayPort, '/__dshn/select', {
  method: 'POST', cookie: session, contentType: 'application/json', accept: 'application/json',
  body: JSON.stringify({ device: tunnelA.deviceId }),
})
const bothA = `${session}; ${String(selA.headers['set-cookie'][0]).split(';', 1)[0]}`
const navA = await request(relayPort, '/', { cookie: bothA, accept: 'text/html' })
const wsA = await wsMessage(relayPort, '/api/events.test', bothA)
check('switching back routes to device A', navA.body === 'A:/' && wsA === 'ws-A', `${navA.body} ${wsA}`)

tunnelB.stop()
await until(async () => JSON.parse((await request(relayPort, '/__dshn/devices', { cookie: session, accept: 'application/json' })).body).live === 1, 'B gone')
const deadApi = await request(relayPort, '/api/probe', { cookie: both, accept: 'application/json' })
check('stale selection fails closed (502)', deadApi.status === 502, `status=${deadApi.status}`)
const fallback = await request(relayPort, '/api/probe', { cookie: session, accept: 'application/json' })
check('unselected traffic keeps flowing to the survivor', fallback.body === 'A:/api/probe', fallback.body)

tunnelA.stop()
relay.close()
originA.server.close()
originB.server.close()
rmSync(dir, { recursive: true, force: true })

console.log(failures === 0 ? '\nALL OK' : `\n${failures} FAILURES`)
process.exit(failures === 0 ? 0 : 1)
