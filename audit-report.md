# dshn 全面审计报告

审计对象：`dshn`，提交 `428d212`（`feat/premium-route`）  
审计范围：正确性、网络安全、资源生命周期、性能、E2E、DNS、可扩展性、测试与发布。  
审计方式：源码审阅、负向复现、单元/集成测试、TypeScript 检查、bundle 检查、生产依赖审计。

## 总结

当前版本功能可用，但不建议直接公网生产。存在 2 个 P0 问题和多个 P1 问题：

1. 未校验的 agent HELLO 可触发 relay 进程崩溃。
2. 本地管理接口只信任 Host 头，可被伪造为 localhost。
3. Release/Ban 不会撤销已有浏览器会话。
4. claims 文件损坏时 fail-open，可能导致旧 subdomain 被重新认领。
5. HTTP/WS/E2E 没有统一的流控、大小上限和超时。
6. configure/disconnect 未清理旧 stream，存在 stream ID 复用串流风险。
7. 同步 scrypt/PBKDF2 和全量 JSON 持久化可阻塞事件循环。
8. E2E 对未标记 API、XHR、sendBeacon 等流量不 fail-closed。
9. Premium DNS ownership、删除和并发操作存在误删/竞态。

## P0：立即修复

### 1. 恶意 HELLO 可能导致 relay 崩溃

`packages/relay/src/server.ts:983` 只解析 JSON 并检查 `frame.t`，没有验证字段类型、长度或协议版本，随后直接调用 `packages/relay/src/claims.ts:130`。

发送以下消息即可使 `password.length` 抛出未捕获 `TypeError`：

```json
{"t":"hello","subdomain":"audit"}
```

握手成功后才安装 WebSocket error handler；握手前也没有超时、连接数或速率限制。应使用运行时 schema 校验，并在整个握手阶段安装 error handler 和 idle timeout。

### 2. loopback 管理边界可被 Host 头绕过

`packages/agent/src/index.ts:1198` 只检查 `Host: localhost`、`127.*` 或 `::1`，没有校验 `req.socket.remoteAddress`。

在非 loopback 的远端地址上设置 `Host: localhost`，`isLoopbackRequest()` 仍返回 `true`。这样可能访问 `/dshn/status`（返回保存的密码）以及 configure、E2E、disconnect 管理路由。应基于 socket 地址判断，并明确配置可信反向代理列表。

## P1：公网部署前修复

### 会话与持久化

- `packages/relay/src/auth.ts:37` 的 session 只验证 HMAC 和 30 天过期时间。
- `packages/relay/src/server.ts:879` 的 release/ban 删除 claim、踢 agent，但不使已有 cookie 失效。
- `packages/relay/src/claims.ts:94` 把所有读盘、解析错误当成空 store。损坏的 claims 文件会让旧名称重新变成可认领状态。
- claims seed 没有运行时校验；salt/hash 损坏时可能抛异常。
- JSON 文件没有 fsync 或跨进程锁，不支持安全的多实例写入。

建议加入 claim generation/session version，坏文件 fail-closed，并把 claim/session 状态移入带锁的持久化存储。

### 流控与资源上限

- relay `packages/relay/src/server.ts:361` 和 agent `sendData()` 直接写 WebSocket，无 `bufferedAmount` 阈值、背压、队列上限或 stream timeout。
- E2E `/api` 请求/响应整体缓存（`packages/agent/src/index.ts:1014`），HTML 重写也整体缓存。
- agent WebSocket `maxPayload` 为 512 MB（`packages/agent/src/index.ts:762`），relay 使用 ws 默认大 payload。
- 缺少 request `aborted/close` 清理、慢上传 timeout、全局并发/每租户额度。
- pre-HELLO socket 不进入 heartbeat sweep，攻击者可长期占用未认证连接。

### agent stream 生命周期

`packages/agent/src/index.ts:440` 的 configure 和 `:553` 的 disconnect 关闭 control socket，但不调用已有的 `dropStreams()`（`:591`）。旧请求、E2E map 和 WebSocket 仍可能保留；新 control connection 的 stream ID 从 1 重新开始，存在串流/数据错配风险。`setE2E()` 修改密钥时也没有清理活动 E2E stream。

### 同步密码派生与持久化

`packages/relay/src/claims.ts:69` 使用 `scryptSync`，设备连接/断开在 `:173` 同步重写整个 claims 文件；agent 的 PBKDF2 也在同步路径中执行。

本地基准：

- 20 次 claim：439.2 ms，平均 22.0 ms/次；
- 20 次 PBKDF2：294.2 ms，平均 14.7 ms/次。

HELLO 没有 IP 限速、连接上限或唯一 label 配额，存在 CPU DoS 风险。

### E2E 与缓存正确性

- `packages/agent/src/index.ts:1014` 只对带 `x-dshn-e2e` 标记的 body 解密；未标记请求仍以明文转给 dsh。
- `packages/agent/src/e2e-shim.ts:67` 只包装 `fetch`，不覆盖 XHR、sendBeacon、表单等客户端。
- `packages/agent/src/index.ts:1037` 对 HTML 进行重写时仍可能保留 ETag/Last-Modified；304 响应不会重新注入 shim，可能加载无 E2E bootstrap 的旧缓存页面。
- `setE2E` 改密钥时已有 WebSocket/请求可能使用旧密钥。

应对不支持的请求明确拒绝或显式标记明文，并在改写/加密响应时删除缓存校验头。

### Premium DNS

- `packages/relay/src/dns.ts:88` 仅凭目标 IP 判断记录属于 relay，可能误认领运营方已有记录。
- `packages/relay/src/dns.ts:109` 按 ID 删除时不重新核对 name/content/comment；无 ID 时会删除同名同 IP 的所有记录。
- `packages/relay/src/dns.ts:65` 没有 Cloudflare API timeout/AbortSignal。
- `packages/relay/src/server.ts:692` 的 enable/disable 未按 subdomain 串行化；release/ban 的异步 DNS 删除可能与重新认领或再次 enable 竞态。

应只操作带明确 ownership ID/comment 的记录，删除前二次核验，并为每个 subdomain 串行化 DNS 状态机。

## P2：加固与架构问题

- CA 文件读取失败会在 `packages/agent/src/index.ts:520` 静默回退系统 CA；应 fail-closed。
- `packages/agent/src/index.ts:759` 接受 `ws://`，生产应强制 `wss://`。
- `packages/relay/src/server.ts:404` 在非可信代理场景仍信任 `cf-connecting-ip`，登录限速可被伪造头削弱。
- relay 没有真正检查 protocol version；坏帧在 `server.ts:1038` 被吞掉，可能留下永久 pending stream。
- deny 分支 `packages/agent/src/index.ts:911` 清除内存凭据但没有持久化清除，重启后可能重复使用旧凭据。
- `RelayServer` 和 `AgentTunnel` 都过于单体，分别混合 HTTP、mux、认证、admin、DNS、E2E、配置和生命周期。
- agents、traffic、loginGate、session 和 claim 主要是进程本地状态，无法安全水平扩展。
- 测试缺少 malformed frame、坏 claims、session revocation、远程 Host、背压/取消、DNS ownership、Premium 并发和 CSP/XHR 场景；relay 测试还直接 import 已构建的 `agent/lib`。
- 根 `package.json` 未锁定 package manager；CI 使用 pnpm 9，本地 pnpm 11 行为不同。根、agent、relay 版本号及 bundle 脚本中的版本存在漂移。
- Dockerfile 默认安装 `@dshn/relay@latest` 并以 root 运行，发布供应链和运行隔离仍需加固。

## 架构优点

- protocol、agent、relay 已分包；
- 二进制帧避免 base64；
- stream ID 由 relay 单向分配；
- heartbeat、route fallback、设备上限和 history 上限已存在；
- E2E 使用 PBKDF2 + AES-GCM，密码不发送给 relay。

## 验证结果

- Vitest：7 个 test files，68 个测试全部通过；
- 三个 package 的 TypeScript `--noEmit` 全部通过；
- `scripts/build-dist.mjs`、agent client 和 relay bundle 语法检查通过；
- `pnpm audit --prod`：4 个生产依赖未发现已知漏洞；
- `git diff --check` 通过，审计未修改源码。

关键复现摘要：

```json
{
  "malformed": "TypeError: Cannot read properties of undefined (reading 'length')",
  "corruptClaim": {"ok": true, "claimed": true},
  "sessionAfterRemove": true,
  "spoofedLoopback": true
}
```

## 修复顺序

1. 修复 HELLO schema/version/timeout/error handler 和 loopback 地址校验。
2. 增加 session revocation，claims 损坏时 fail-closed。
3. 引入统一 stream quota、背压、timeout、abort 清理和 max payload。
4. 修复 configure/disconnect/setE2E 的生命周期清理。
5. 重做 DNS ownership、删除校验、并发串行化和 API timeout。
6. 将 E2E 对未支持流量改为明确拒绝或显式明文模式，清理变换响应的缓存头。
7. 拆分 relay/agent 模块，并补齐负向、并发和资源测试。
8. 若目标是多实例部署，将 claims/session/agent registry/stream routing 移入带锁的控制面。

---

## 修复状态（0.4.1 / agent 0.3.4，2026-08-26）

按本报告做了一轮修复，`pnpm test` 8 文件 83 测试全绿；三个包 `tsc --noEmit` 通过；真实浏览器端到端 E2E 复验通过（`scratchpad/e2e-cdp/local-ws.mjs`）。

| 条目 | 状态 | 处理 |
|---|---|---|
| P0-1 恶意 HELLO 崩溃 | 已修 | `checkHello()` 运行时 schema（类型/长度/协议版本）；握手前即装 error handler + 10s HELLO 超时；claim 检查失败/异常一律 `deny` 不抛。 |
| P0-2 Host 头伪造 loopback | 已修 | `isLoopbackRequest` 增加 `req.socket.remoteAddress` 必须是回环（`isLoopbackAddress`，含 `::ffff:` 映射）；`Host: localhost` 从 LAN 地址不再放行。 |
| P1 会话不失效 | 已修 | claim 加 `sessionVersionOf`（createdAt+salt 前缀）并进 cookie MAC；release/ban 后重新认领即换版本，旧 cookie 全部失效。`sign/verify` 带 version。 |
| P1 claims fail-open | 已修 | 缺文件=全新；文件存在但损坏/字段非法=启动即抛（`checkRecord` 校验 hash/salt/createdAt/devices/premium），不再当空 store。fsync + 关停 flush。 |
| P1 无流控/上限/超时 | 已修 | relay+agent 双向背压（`bufferedAmount` 高水位暂停源、`flushed` 恢复）；`MAX_FRAME_BYTES=128MB`（relay ws + agent maxPayload）；不可暂停的浏览器/事件 socket 超 `MAX_BUFFERED=64MB` 断开；响应 120s 空闲超时；HELLO 速率闸（IP 60/min、peer 600/min、每 peer 32 未认证 socket）。 |
| P1 configure/disconnect/setE2E 不清流 | 已修 | 三者都走 `dropStreams()`；`setE2E` 换密钥时清活动流（半旧密钥密文作废）。 |
| P1 同步 scrypt/持久化阻塞 | 已修 | `scryptSync`→异步 `scrypt`（libuv 线程池）；`claimOrVerify`/`verifyLogin` 异步并处理认领竞态；device-touch 惰性合并落盘（`persist(lazy)`）。 |
| P1 E2E 不 fail-closed | 已修 | E2E 开启时未标记的 `/api` 请求返回 428（不再明文转发）；shim 拦截 XHR/sendBeacon 到 `/api` 并报错；改写/加密响应清 ETag/Last-Modified/Cache-Control 并置 `no-store`；条件请求剥 `If-None-Match/If-Modified-Since` 防 304 旧壳。 |
| P1 Premium DNS 归属/删除/并发 | 已修 | 归属只认 relay 盖的 comment（不再凭目标 IP）；按 id 删除前二次核验属主，否则拒删；每 subdomain 用 `premiumSerial` 串行化 enable/disable/release 的 DNS+claim；Cloudflare API 加 15s AbortSignal 超时。 |
| P2 CA 读取失败静默回退 | 已修 | 读不到配置的 CA 文件→拒绝拨号（不降级系统信任库）。 |
| P2 接受 ws:// | 已修 | 仅回环允许 ws://，其余强制 wss://。 |
| P2 版本漂移 | 已修 | build-dist 从各 package.json 读版本；根 `packageManager: pnpm@11`；CI pnpm 9→11。 |
| P2 Docker root | 已修 | Dockerfile `USER node`，/data 归 node。 |
| P2 坏帧留 pending | 已修 | agent 违反协议的帧→关闭该连接（cleanup 失败其流，agent 重连），不再静默吞。 |
| 测试缺负向/并发 | 已做 | 新增 `hardening.test.ts`（12）+ `dns.test.ts` 归属用例；malformed HELLO/坏 claims/会话吊销/伪造 IP 限速/远程 Host/E2E fail-closed/缓存头。 |

未做（架构级，超出本轮）：relay/agent 拆分为更小模块；claims/session/registry 移入带锁控制面以支持多实例水平扩展；cf-connecting-ip 仅在可信代理场景才信任（当前用 socket-peer 第二道闸缓解伪造，已覆盖测试）。
