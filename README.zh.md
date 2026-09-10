# dshn — DeepSeek Harness Network

[English](./README.md) · **中文**

[![awesome · DSH plugin](https://awesome-dsh-plugin.com/badge.svg)](https://awesome-dsh-plugin.com/)
[![npm](https://img.shields.io/npm/v/@dshn/agent?label=%40dshn%2Fagent&color=cb3837)](https://www.npmjs.com/package/@dshn/agent)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

把本机运行的 **DeepSeek Harness**（`dsh`）网页界面,通过 `*.ds.hn` 子域名安全地开放到公网,并由登录门禁把守。安装插件、在本地打开 dsh,设置里的表单会让你填一个**子域前缀**和一个**密码**——这两项就是凭据。无需 token、无需环境变量、无需任何预置。还可选设置一个**端到端密码**加密流量,连中继运营者也只能看到密文。

> ⚠️ **dsh 内置 bash 与文件系统工具,公网可达的 dsh 界面就是一个远程 Shell。** 中继的登录门禁不是可选项,不要关掉它。请使用高强度密码,敏感场景优先启用端到端加密。

## 特性

- **零配置凭据。** 在 dsh 设置里填一次 `(子域, 密码)` → 插件即认领子域并连接。凭据持久化到 dsh 自己的 `~/.dsh/settings.yaml`,重启自动重连。
- **信任首次使用(TOFU)。** 首个认领空闲子域的 agent 设定其密码(在中继上以 scrypt 哈希存储);此后的连接与每一次浏览器登录都必须匹配它——防抢占。
- **多设备。** 多台机器可用同一凭据绑定**同一个**子域,各自显示为一台具名设备。有 ≥2 台在线时,打开链接会出现设备选择页,页面侧栏底部也有切换器;选择按浏览器记住(路由 cookie),切换即对另一台机器做一次干净的重载。仅一台在线时行为与从前完全一致。
- **可选端到端加密**(默认关闭)。一个**独立**的 e2e 密码(绝不发往中继)加密 `/api` 请求体与事件流:PBKDF2-SHA256(21 万次)→ AES-256-GCM。访客在浏览器里输入一次即可,可按设备记在 `localStorage`(永不传输)。
- **原生 UI。** 配置就在 dsh 自己的设置里(「公网转发」),页脚一行实时显示延迟并可点入。
- **上行压缩。** 响应体在进入隧道前先 gzip——agent→中继这一跳才是窄口,而 dsh 自己的 web 服务默认不做任何压缩。一次冷加载的线上字节数从约 12.5 MB 降到约 5.0 MB(2.5 倍);dsh 已经编码过的响应原样透传。
- **自持数据面。** 流量经 Cloudflare 边缘回到**你自己的**服务器——无需每用户的 Cloudflare 账号,无需 NS 委派。

## dsh 版本兼容

已对 **dsh 0.1.5-rc.1** 实测通过(同时保持对更早版本可用)。

从 **dsh 0.1.2-rc.1** 起,dsh 给应用外壳和每一次 `/api` 调用都加了一道签名的、
与 Host 绑定的浏览器会话 cookie:浏览器要靠打开 dsh 打印的那个带 token 的启动
URL 才能换到它,其余一律 `401 dsh web authentication required`。公网访客不可能
持有这个 cookie——他们浏览器里的 cookie 属于公网域名,而 agent 回放的每个请求
Host 都被改写成了 loopback,dsh 又是按请求到达时的 Host 校验 cookie 的。所以
agent 改为向 dsh 自己的 `connection` 服务取本进程的启动 token,在 loopback 上兑
换一次,再把拿到的 cookie 盖在每一个回放请求和隧道内的 WebSocket 升级上。这个
cookie 始终不出本机:中继和访客浏览器都看不到它,访问控制仍然由中继的登录把关。
面对没有这道围栏的旧版 dsh,agent 会自动识别并保持原有行为。

**dsh ≥ 0.1.2 必须搭配 agent 0.4.0。** 更早的 agent 只会把一个 401 页面转发出去。
中继无需改动——修复完全在 agent 侧,已部署的中继同时服务两者。

## 架构

```
浏览器  alice.ds.hn
  │  HTTPS
  ▼
Cloudflare 边缘  (*.ds.hn 代理 / 橙色云)              免费 DDoS、WAF、TLS、
  │  回源                                              Anycast、隐藏源站
  ▼
中继 relay  (你的服务器, @dshn/relay)                 登录门禁 + 子域认领表;
  │  每设备一条多路复用 WSS                            只搬运字节
  ▼
dshn  (dsh 插件, 在用户机器上)                        把 HTTP + WS 重放给 dsh,
  │  http://127.0.0.1:<dsh 端口>                       Host/Origin 改写为环回
  ▼
dsh  (本地网页服务)                                   信任门禁看到的是一个环回请求
```

- **不改 trustedHosts。** agent 把每个转发请求的 Host/Origin 改写为环回,于是 dsh 的 `/api` 浏览器信任门禁把它当作**任意**运行时选定子域的本地同源请求接受——这正是「子域来自表单而非组合」得以成立的原因。访问由中继登录把守,而非该门禁。
- **端到端模式** 在 agent 处密封请求/响应体、在浏览器里解开;中继始终是一个盲搬运者。应用外壳与插件包保持明文,以便浏览器自举并弹出解锁弹窗。它能防住被动/好奇的中继与静态数据泄露,但防不住一个主动作恶、篡改所投送 JS 的中继。

## 包结构

| 包 | 是什么 | 运行在哪 |
|---|---|---|
| `@dshn/protocol` | 两端共同编译的 WSS 帧协议 | 共享 |
| `@dshn/agent` | dsh 插件:设置表单 + 出站隧道 + 状态挂件 + e2e | 用户机器,dsh 之内 |
| `@dshn/relay` | 登录门禁 + 认领表 + 子域路由 + HTTP/WS 桥接 | 你的服务器,Cloudflare 之后 |

认领表（`packages/relay/src/claims.ts`）目前是信任首次使用;账号化的控制面日后替换它。

## 安装 agent(用户机器)

从 npm 安装(推荐——一条命令,完全自包含):

```sh
dsh plugin --profile web add @dshn/agent
dsh --profile web
```

或从最新 GitHub Release 下载预构建 tarball:

```sh
curl -L -o dshn.tgz \
  https://github.com/jsdvjx/dshn/releases/latest/download/dshn.tgz
dsh plugin --profile web add ./dshn.tgz
```

或从源码构建:

```sh
pnpm install && node scripts/build-dist.mjs
dsh plugin --profile web add ./dist/dshn
dsh --profile web
```

随后在本地打开 dsh,进入 **设置 → 公网转发**,填写子域前缀与密码(可选端到端密码),点**连接**。用同一个访问密码即可从手机登录。每个子域最多跑**一个** agent——相同凭据的两个 agent 会互相争抢。

agent 环境变量(全部可选,均有合理默认值):

| 变量 | 默认值 | 用途 |
|---|---|---|
| `DSHN_ENABLED` | `1` | 设为 `0` 则加载插件但不启用 |
| `DSHN_RELAY_HOST` | `relay.ds.hn` | 中继地址;直连(绕开 Cloudflare)用 `wss://origin.ds.hn:8787` |
| `DSHN_ORIGIN_CA` | — | 钉扎自签名直连源站证书的 PEM |
| `DSHN_STATE` | `~/.dsh/dshn-agent.json` | 旧版状态文件(凭据现在存于 `settings.yaml`) |
| `DSH_HOME` | `~/.dsh` | dsh 主目录 |

## 自托管你自己的网络

你不必用 `ds.hn`——整套都能跑在你自己的域名上。中继以 **`@dshn/relay`**(npm)及 Docker 镜像发布;在设置表单里选 **自托管**、填入中继地址即可指过去(也可用 `DSHN_RELAY_HOST`)。完整指南(含 DNS 与 TLS 各选项):**[SELF-HOSTING.md](./SELF-HOSTING.md)**。

```sh
# 你的服务器 —— 唯一必填的只有 apex;登录密钥自动生成并持久化,
# claims 与密钥都放在 --data-dir 里
npx @dshn/relay --apex tunnel.example.com --data-dir /var/lib/dshn
# 你的 dsh —— 或直接在 设置 → 公网转发 → 自托管 里填
DSHN_RELAY_HOST=wss://tunnel.example.com dsh --profile web
```

Cloudflare:把 `*.ds.hn`(橙色云代理)指向中继源站。请把源站加固为仅接受 Cloudflare——按 [Cloudflare IP 段](https://www.cloudflare.com/ips/)做防火墙,并启用 Authenticated Origin Pulls(mTLS)。因为 Cloudflare 约 100 秒关闭空闲 WebSocket,两端每 25 秒心跳——已内置。若要承载持续大流量的直连隧道,加一条灰云(仅 DNS)`origin.ds.hn` A 记录,并让 agent 用 `DSHN_RELAY_HOST` + `DSHN_ORIGIN_CA` 指过去。

## 现状

对 dsh 0.1.5-rc.1 端到端可用。已知不足:偶发的隧道套接字断开会让该连接上的在途请求失败(尚无请求重放);持续大流量下 Cloudflare 可能重置隧道(改用直连源站方案);CF 免费版 100 MB 请求上限会截断较大的 dsh 图片上传;单个隧道帧上限 128 MB,低于 dsh 自己的 300 MB 请求体上限,因此超过该大小的端到端加密响应会失败;端到端加密的 `/api` 响应体不压缩(密文压不动);认领表仍是信任首次使用、无账号层;生产环境应把中继源站锁定到 Cloudflare IP 段并启用 Authenticated Origin Pulls。

## 许可

[MIT](./LICENSE)
