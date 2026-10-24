# dsh-traffic-guard

给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）用的**计量代理流量闸门**：
让 agent 的下载默认走直连，只有在直连**真的停滞**时才借用代理，而且每一次代理流量都受**硬预算**约束、并记进本地账本。

一个 CLI（`netguard`，可独立使用）+ 一个 Host 插件（3 个工具：`net_usage` / `net_probe` / `net_download`）。

![ci](https://github.com/JerryLingWuQ/dsh-traffic-guard/actions/workflows/ci.yml/badge.svg)

> English: [README.en.md](README.en.md)

---

## 为什么需要它

用「机场」类按量计费代理、手机热点、或企业出网网关时，**流量是钱**。而 agent 的工作方式恰好容易失控：

- 一次 `curl -O`、一次 `git clone`、一个 `pip install` 就可能几百 MB；
- 桌面应用的 **nightly 自动更新**会在后台悄悄下载整包（本项目实测过一次 **347.7 MB** 的全量更新包，且更新器走 Chromium 网络栈、**遵守系统代理**，于是真的花了计划流量）；
- 代理客户端通常只给你一个「账号已用总量」，**没有按应用/按域名的归因**，出了问题根本查不到是谁花的；
- 而 CLI 子进程（curl/git/npm）往往又不读取系统代理，导致「有的流量进代理、有的不进」，统计口径完全对不上。

`dsh-traffic-guard` 把这些收拢成一条可审计的策略：**直连优先 → 停滞才升级 → 预算硬限 → 全部记账**。

## 它做什么

| 层 | 行为 |
| --- | --- |
| **路由** | 默认直连。只有目标命中 `proxy_hosts`、且直连在 `connect_timeout` 内失败 / 0 字节 / 读超时时，才改走本机代理。代理地址从 `scutil --proxy`（macOS）或 `NETGUARD_HTTP_PROXY` 动态发现，不写死端口。 |
| **预算** | 代理调用受 `per_call`（默认 128 MiB）与 `per_day`（默认 300 MiB）双重硬限；超限直接失败（退出码 3），`--force` 才放行。预算只约束「代理」，直连不花计划流量、不计数。 |
| **重定向** | 关闭自动跟随，**每一跳都重新按策略判定**（借鉴 SSRF 护栏类插件的做法）：代理域跳到直连域会重新决策，不会一路错下去。 |
| **预检** | 响应头 `Content-Length` 超过本次预算时**不下载**，一个字节都不花；流式读取时边读边数，超限立刻断开。 |
| **超时** | 整条链共用一个 `max_time` 预算，避免「每跳各卡 19 秒 × N 跳」。 |
| **账本** | 每次调用写一行 JSONL：时间、URL、host、路由、字节、耗时、成败、命中哪条规则。`report` 可按天/按主机汇总。 |
| **失败缓存** | 某主机近期直连多次失败后，下次直接走代理，省掉每次 8 秒的等待。 |

## 安装

```bash
# 从 GitHub 安装（推荐）
dsh plugin --profile <profile> add github:<you>/dsh-traffic-guard

# 或者在 Desktop 版里用 plugin_manager 安装本地目录
#   action: install_bundle, target: <该仓库的绝对路径>
```

插件不依赖任何 dsh 包（只用 Node 内置模块），因此可以按 linked package 方式安装。
装好后模型会多出三个工具：

- `net_usage`：读账本（按天/按主机/直连 vs 代理）；
- `net_probe`：先探测直连是否可用，避免无谓地走代理；
- `net_download`：带策略与预算的下载。

## CLI 单独使用

```bash
export NETGUARD_HOME=~/.dsh/netguard      # 可选，默认就是它
cp cli/config.example.json "$NETGUARD_HOME/config.json"

python3 cli/netguard.py status            # 当前代理 + 今日已用/剩余预算
python3 cli/netguard.py probe https://github.com/
python3 cli/netguard.py dl https://example.com/file.zip -o /tmp/file.zip
python3 cli/netguard.py report --days 7
```

退出码：`0` 成功、`3` 预算/大小被拒、`4` 网络失败、`5` 需要代理但代理不可用。

## 配置

`$NETGUARD_HOME/config.json`（默认 `~/.dsh/netguard/config.json`），字段见 [cli/config.example.json](cli/config.example.json)。

最关键的是两个名单：

```json
{
  "route": {
    "proxy_hosts": ["github.com", "*.githubusercontent.com", "huggingface.co"],
    "direct_hosts": ["*.deepseek.com", "*.npmmirror.com", "*.aliyun.com"]
  },
  "budget": { "per_call": 134217728, "per_day": 314572800 }
}
```

- `proxy_hosts`：**允许**在直连停滞时使用代理的主机（不是「必须走代理」）。
- `direct_hosts`：**永远**不走代理的主机，优先级高于 `proxy_hosts`。把你的模型 API、国内镜像、更新 CDN 放这里，能省掉大量计划流量。

## 与同类插件的对比

DSH 生态里已有几个方向相近的插件，本项目的取舍是**预算与账本**，不是出网安全：

| 项目 | 关注点 | 本项目借鉴了什么 |
| --- | --- | --- |
| [JackZo400/dsh-netguard](https://github.com/JackZo400/dsh-netguard) | SSRF 出网护栏：解析后的每个 IP 都判、每跳重定向复查、流式限字节、预检 Content-Length | 逐跳重定向复查、`Content-Length` 预检、整链共享超时 |
| [CharlotteN7/dsh-netguard](https://github.com/CharlotteN7/dsh-netguard) | `web_fetch`/`web_search` 主机允许名单、bash 命令目标预检、默认 audit 模式 | 「先记账、后约束」的 audit-first 思路 |
| [wtdwang/dsh-tool-netguard](https://github.com/wtdwang/dsh-tool-netguard) | 区分「外传 / 获取」，`tools/pre-execute` + `ctx.approval` | 未来可加「超预算前弹审批」 |
| [MukundaKatta/resilient-agent](https://github.com/MukundaKatta/resilient-agent) | 重试、熔断、USD 预算、出网名单、审计轨迹 | 预算 + 审计正交的验证 |

如果你要的是「防 SSRF / 防数据外泄」，请优先看上面三个；本插件解决的是「别把计量流量烧光」。

## Roadmap
- [ ] 超预算前走 `ctx.approval` 弹审批，而不是直接失败
- [ ] `netguard` 支持 SOCKS5（现在只支持 HTTP/HTTPS 代理）
- [ ] 可选 `web_fetch` provider 替换模式（需处理 `WEB_PROVIDER_AMBIGUOUS`）
- [x] CI（GitHub Actions：10 个单测 + `node --check` + manifest JSON 校验）
- [ ] 发布 npm 包，支持 `dsh plugin add dsh-traffic-guard`
- [ ] 收录进 awesome-dsh-plugin / dsh-market 等社区列表

## 局限（请先读）

- **不是操作系统级防火墙**。它约束的是「经过 `netguard` 的下载」。任何绕过它的 `curl`、`git clone`、应用自动更新，都不会被拦（但会出现在系统/客户端的总量里）。
- **代理客户端没有按应用归因**，所以本插件用**自己的账本**补这一块；账本只覆盖经过 `netguard` 的调用。
- **预算是对 agent 的硬约束，不是对系统的硬约束**：`--force` 可以覆盖，且它无法阻止其他进程使用同一个代理。
- 目前只支持 HTTP/HTTPS 代理（urllib 不支持 SOCKS）；SOCKS-only 客户端请改用它提供的 HTTP 代理口。
- macOS 用 `scutil --proxy` 发现系统代理；Linux/Windows 请设置 `NETGUARD_HTTP_PROXY`。
- 不包含任何特定代理客户端的私有配置格式或密钥。

## 开发

```bash
python3 -m unittest discover -s test -v   # 10 个用例，全部走本地 127.0.0.1，无外网
node --check index.mjs
```

## License

MIT
