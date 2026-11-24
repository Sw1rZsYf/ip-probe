# IP PROBE

一个**单文件、零第三方依赖**的本地 IP 体检工具，终端报告 + 本地 Web 面板，定位类似 ping0.cc。

> GitHub: <https://github.com/Sw1rZsYf/ip-probe>  
> Release: <https://github.com/Sw1rZsYf/ip-probe/releases/tag/v1.0.1>

支持检测当前公网 IPv4 / IPv6 出口，也可以查询任意 IP：

- IP 地址、IPv4 / IPv6、反向解析
- 国家 / 省 / 市 / 邮编、经纬度、时区
- ASN、ASN 所有者、企业 / ISP、网络段、注册局
- IP 类型：家庭宽带 / 移动网络 / 企业网络 / 数据中心 / 代理 / VPN / Tor
- 风控值（0–100）与风险等级
- 共享人数估算、原生 IP 推断
- 适用场景评分（TikTok / 跨境电商 / 社媒运营 / AI 应用）
- 双栈结果、多源并发、超时降级、数据源状态
- 终端彩色报告、JSON 输出、本地 Web 面板

> 共享人数、原生 IP、适用场景是**估算/推断**，不是 ping0.cc 的官方数据，也不构成精确风控结论。

---

## 快速开始

要求：Python 3.9+（Windows / macOS / Linux）。

```bash
# 检测当前公网 IPv4 + IPv6
python ip_probe.py

# 查询指定 IP
python ip_probe.py --ip 8.8.8.8

# 启动本地 Web 面板（默认 http://127.0.0.1:8848）
python ip_probe.py --serve --open
```

Windows 下也可以直接双击 `start.bat`。

---

## 终端用法

```text
python ip_probe.py [IP] [选项]

选项：
  --ip IP             查询指定 IP（与位置参数二选一）
  --family {auto,4,6} 当前出口检测的协议族，默认 auto（双栈）
  --json              输出 JSON
  --no-color          禁用终端颜色
  --no-risk           不查询 proxycheck.io 风控值
  --fast              快速模式：跳过 RDAP 注册地查询
  --deep              深度模式：额外查询 RIPEstat 与反向 DNS
  --timeout 秒        单次 HTTP 超时，默认 12
  --serve             启动本地 Web 面板
  --host HOST         Web 监听地址，默认 127.0.0.1
  --port PORT         Web 端口，默认 8848
  --open              启动 Web 后打开浏览器
  --quiet             不输出进度提示
  --version           显示版本
```

### 常用示例

```bash
# 只看 IPv4
python ip_probe.py --family 4

# 查询 Google DNS，并加上 RIR / PTR 信息
python ip_probe.py --ip 8.8.8.8 --deep

# 不查询风控，适合不想把 IP 发给 proxycheck 的场景
python ip_probe.py --ip 1.1.1.1 --no-risk

# 输出 JSON，方便接监控或脚本
python ip_probe.py --json > ip.json

# 指定端口启动，并自动打开浏览器
python ip_probe.py --serve --port 9000 --open
```

### 终端输出示例

```text
  IP PROBE  ·  本地 IP 体检
  2026-11-24 20:19:32+08:00  ·  耗时 3.6s

  ╭─ IPv4 出口 ───────────────────────────────────────────────────────────╮
  │ 8.8.8.8  数据中心/机房  ·  广播/机房 IP                                │
  │ 美国 · 加利福尼亚州 · 圣何塞 · 95025                                   │
  │ 37.339394, -121.894955 · America/Los_Angeles · UTC-08:00               │
  │                                                                       │
  │ ASN         AS15169  Google LLC                                       │
  │ ASN 所有者  Google LLC                                                │
  │ 企业 / ISP  Google LLC · google.com                                   │
  │ 网络类型    数据中心/机房（Business）                                 │
  │ 原生 IP     广播/机房 IP  ·  置信度 中                                │
  │ 风控值      0/100  极低  ░░░░░░░░░░                                    │
  │ 共享人数    50-500+ 人 · 很多（估算）                                  │
  │ 网络段      8.8.8.0/24                                                │
  │ 注册信息    ARIN                                                      │
  │ 适用场景    TikTok ★☆☆☆☆   跨境电商 ☆☆☆☆☆   社媒运营 ☆☆☆☆☆          │
  │ 数据源      ipwho.is ✓ 841ms · proxycheck.io ✓ 994ms · RDAP ✓ 2790ms  │
  ╰───────────────────────────────────────────────────────────────────────╯
```

---

## Web 面板

```bash
python ip_probe.py --serve --open
```

默认地址：<http://127.0.0.1:8848/>

功能：

- 留空查询 = 当前公网出口
- 输入任意公网 IPv4 / IPv6 = 目标查询
- IPv4 / IPv6 双栈切换
- 风控值环形图、网络指纹、适用场景
- OpenStreetMap 地图定位
- 数据源状态与耗时
- 30 秒自动刷新（仅当前 IP 模式）
- 复制 IP
- Web 端结果缓存 5 分钟，避免频繁触发免费 API 限流

API：

```text
GET /api/health
GET /api/ip?ip=8.8.8.8&risk=1&deep=0&fast=0
```

示例：

```bash
curl "http://127.0.0.1:8848/api/ip?ip=1.1.1.1"
```

---

## JSON 输出

`--json` 返回结构稳定的 JSON，主要字段：

```json
{
  "ok": true,
  "generated_at": "2026-11-24T20:19:32+08:00",
  "elapsed_ms": 3600,
  "mode": "current",
  "primary": { "...": "..." },
  "addresses": [
    {
      "ip": "8.8.8.8",
      "family": "IPv4",
      "location": {
        "country": "美国",
        "region": "加利福尼亚州",
        "city": "圣何塞",
        "latitude": 37.339394,
        "longitude": -121.894955,
        "timezone": "America/Los_Angeles"
      },
      "asn": { "id": "AS15169", "owner": "Google LLC", "registry": "ARIN" },
      "company": { "name": "Google LLC", "domain": "google.com" },
      "network": { "type": "数据中心/机房", "type_code": "hosting" },
      "native": { "label": "广播/机房 IP", "confidence": "中" },
      "risk": { "score": 0, "level": "极低" },
      "shared": { "range": "50-500+", "level": "很多", "estimated": true },
      "scenarios": [ "..." ],
      "sources": [ "..." ]
    }
  ],
  "missing": [],
  "warnings": []
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `mode` | `current` 当前出口 / `target` 指定 IP |
| `primary` | 优先 IPv4 的主结果 |
| `addresses` | 所有检测到的出口 / 查询结果 |
| `missing` | 未检测到的协议族 |
| `location.accuracy` | `城市级` / `省级` / `国家级` |
| `network.type_code` | `residential` / `mobile` / `business` / `hosting` / `proxy` / `vpn` / `tor` |
| `risk.score` | 0–100；`null` 表示未获取 |
| `shared.estimated` | 恒为 `true`，表示估算 |
| `native.is_native` | `true` / `false` / `null`（未知） |
| `sources` | 每个数据源的成功状态与耗时 |

---

## 数据源

| 数据源 | 用途 | 需要 Key | 备注 |
| --- | --- | --- | --- |
| [ipwho.is](https://ipwho.is) | 归属地、ASN、ISP、时区 | 否 | 主数据源，支持中文 |
| [proxycheck.io](https://proxycheck.io) | IP 类型、风险值、设备数 | 否 | 免费额度约 100 次/天；可配 Key |
| [RIPEstat](https://stat.ripe.net) | ASN 持有者、前缀、注册局 | 否 | `--deep` 时启用 |
| [RDAP](https://rdap.org) | 注册地、注册局 | 否 | 默认启用；`--fast` 跳过 |
| [ipinfo.io](https://ipinfo.io) | 备用归属地 / 隐私标记 | 可选 | 无 Token 也能用，但字段少 |
| [ip-api.com](http://ip-api.com) | 备用类型 / 代理 / 机房标记 | 否 | 免费版仅 HTTP |

### 可选环境变量

```bash
# proxycheck.io 更高额度（可选）
set PROXYCHECK_API_KEY=your_key

# ipinfo.io Token（可选，能补充 privacy/asn 字段）
set IPINFO_TOKEN=your_token
```

PowerShell：

```powershell
$env:PROXYCHECK_API_KEY = "your_key"
$env:IPINFO_TOKEN = "your_token"
```

---

## 准确性与限制

### 能做得比较准的

- 公网 IP 检测（双栈）
- 国家 / 省 / 市、经纬度、时区（城市级）
- ASN、ASN 所有者、企业 / ISP、网络段
- 代理 / VPN / Tor / 机房标记（依赖 proxycheck / ip-api）
- 风控值（proxycheck 返回时）

### 只能估算的

- **共享人数**：ping0.cc 使用自建探测网统计，公开 API 没有真值。本项目用 `proxycheck` 的设备数 + IP 类型 + NAT / 机房特征给出区间，全部标记为“估算”。
- **原生 IP**：用 RDAP 注册地 vs 实际归属地、机房 / 云厂商 ASN、代理特征推断，结果标记“推断”和置信度。
- **适用场景**：基于 IP 类型、风险、国家、共享程度的启发式评分，仅供参考。

### 隐私说明

查询时会把目标 IP 发送给上表中的第三方公共服务。默认使用 HTTPS；`ip-api.com` 免费版使用 HTTP。若不想把 IP 发给风控服务，使用：

```bash
python ip_probe.py --no-risk
```

私有 / 保留地址（如 `192.168.1.1`、`10.0.0.1`）不会发送到第三方，只显示本地判断。

---

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功 |
| `1` | 查询完成但所有数据源失败，或未检测到公网 IP |
| `2` | 参数错误 / IP 格式错误 |
| `130` | 用户按 Ctrl+C |

---

## 文件结构

```text
ip-probe/
├── ip_probe.py   # 单文件主程序（CLI + Web + HTML）
├── start.bat     # Windows 一键启动 Web 面板
├── README.md
├── LICENSE
└── .gitignore
```

---

## 常见问题

**Q：为什么 IPv4 和 IPv6 的归属地不一样？**  
A：双栈出口可能走不同线路，两个地址的 GeoIP 数据也可能不同。工具会分别查询并展示。

**Q：为什么 8.8.8.8 显示“广播/机房 IP”？**  
A：Google / Cloudflare 等 Anycast / 云网络会被识别为机房网络，不是原生住宅 IP。

**Q：为什么风控值显示“未知”？**  
A：proxycheck.io 免费额度用尽、网络不可达，或使用了 `--no-risk`。工具会降级到 ip-api 获取类型，但不会编造风险分。

**Q：Web 面板打不开？**  
A：确认端口没有被占用，或换一个端口：

```bash
python ip_probe.py --serve --port 9000
```

**Q：能查询域名吗？**  
A：当前版本只接受 IP 地址。可以先用 `nslookup` / `dig` 解析域名，再查询结果 IP。

---

## License

[MIT](LICENSE) © 2026 Sw1rZsYf

第三方数据源的使用请遵守各自服务条款。
