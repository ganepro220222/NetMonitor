# 🚀 NetMonitor — 网络连通性实时监控与网络空间高级诊断系统

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![UI](https://img.shields.io/badge/UI-CustomTkinter%20%2B%20Flask%20Web-black.svg)]()
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

**NetMonitor** 是一款面向网络运维与信息安全审计的高可靠多线程网络监控与诊断系统。它把**桌面客户端（CustomTkinter 现代暗黑界面）**、**内嵌 Flask 实时 Web 看板**与**单写线程 + WAL 的 SQLite 时序内核**整合在一起：以秒级高频对 ICMP / TCP / HTTP(S) / DNS 多类目标持续探测，通过**持久化可靠投递的 Webhook 告警总线**做全生命周期通知，并提供 PMTU、迭代权威解析、客户端 DNSSEC 验证等网络空间深度取证能力。当前完整适配 **Windows** 宿主，Linux 跨平台在演进路线中。

---

## ⚡ 核心特性

### 📡 1. 多协议实时探测引擎（`src/ping_engine.py`）
- 原生支持 **ICMP / TCP 端口 / HTTP(S) / DNS** 四类探针，秒级高频采集，每类协议独立的成功判定与超时/丢包/状态码语义。
- 三态状态机（正常 / 警告 / 严重）与**结构化失败原因**归类，为告警与诊断提供一致的事实来源。
- 与高级诊断、告警、Web 看板共享同一份探测结果，避免重复探测与口径漂移。

### 🚨 2. 可靠持久化告警总线与 Webhook Outbox（`src/alert_manager.py` + `src/webhook_outbox.py`）
- **崩溃/重启不丢的持久化 outbox**：所有告警事件先落入 SQLite `webhook_outbox` 表，再由独立调度器投递；支持**指数退避重试**、**按目标严格有序**、**去重**与**队头阻塞自动排空**（长退避的旧事件不会卡死后续恢复通知）。
- **进程重启自恢复**：重启后从数据库重建在途故障、补发“重启后续报”告警，并恢复投递序号基线。
- **多层 fail-closed 门控**：投递前/后对网关序号、目标身份（标签/IP/代次 generation）双重复检；目标被删除或身份变更时自动作废过期排队消息；恢复闭环（closed-summary）**仅在确认送达后**才作废对应红色告警，避免“漏报恢复 + 静默红灯”。
- **多平台智能分发**：按 **URL hostname 精确白名单**识别并适配 **企业微信 / 钉钉 / 飞书 / Lark（含国际版 `larksuite`）** 的文本消息格式，其余地址回退为通用 JSON；全程区分 incident 范围、状态去重。
- **运维可观测**：完整投递状态机、`last_error` 保留、`/api/webhook/stats|deliveries` 接口、以及 Web 端**投递失败详情面板**（含 `delivery_id` 溯源、单条/批量一键复制排障信息）；终态投递记录按保留期自动清理，长跑实例不被历史失败淹没。

### 🔊 3. 纯数学音频合成告警（`src/alert_manager.py`）
- **零外置音频依赖**：直接用标准库 `wave` + `struct` + `math.sin` 动态合成告警音——橙色警告（880Hz 短促双音）、红色告警（440/880Hz 紧迫循环）、绿色恢复（523→784Hz 升调）。
- **跨线程异步安全播音**：经 `winsound.PlaySound` 的 `SND_ASYNC` 标志位托管，规避多线程子线程调用导致的告警音静默丢弃。

### 💾 4. 高并发时序持久化与司法级审计（`src/data_store.py`）
- **WAL + 单写线程队列**：独立 `data_store-writer` 线程独占写连接，常规探测每 60s 批量落盘，告警/恢复等突发事件**即时冲刷**；只读走线程局部（TLS）连接缓存，实现 WAL 下读写并发。
- **三级自适应降采样**：≤2 小时取原始秒级；≤48 小时按 1 分钟桶聚合；>48 小时走小时级静态聚合，兼顾长周期趋势透视、探针权重均等与内存安全。
- **Schema 版本化与分类保留期**：`PRAGMA user_version` 迁移（当前 v15）；原始 8 天 / 小时聚合 90 天 / 告警事件 365 天 / 路由日志 30 天 / 诊断历史 180 天 / outbox 90 天，可热更新。
- **二级故障现场绑定**：节点严重阻断瞬间派发唯一 `incident_id`，并把路由断点拓扑快照、跳数变动与该单号在库内强绑定，支持跨重启续接与溯源。
- **Excel 取证报告**：一键导出含「全局 SLA 连通汇总」「多节点自适应时序 Sheet」「全故障事件流时间线」的报表，内嵌故障瞬时路由断点与 ICMP 错误原因（时间戳精确到毫秒，外部文本做公式注入防护）。

### 🔍 5. 网络空间高级诊断矩阵（`src/dns_diag.py` / `src/icmp_diag.py` / `src/diag_sem.py`）
- **跨诊断全局单槽互斥**：`diag_sem` 信号量对高级 ICMP / DNS / 手动 Traceroute 强互斥，防止多路探针争抢链路带宽导致 RTT 失真。
- **高级 ICMP 链路透视**：大载荷注入（0–9000 字节）、DF 分片保护、巨型包链路压测、基于二分查找的 **PMTU 路径最大传输单元**自适应追踪与稳定性测试。
- **顺序多路解析 Diff**：系统默认 + 最多 3 路自定义解析器（共 4 列对照）串行比对，输出逐条 TTL 变动与结构化应答，揭示 DNS 污染/劫持。
- **迭代权威路径追踪**：从内置 IANA IPv4 根提示（`_ROOT_IPV4_HINTS`）以 RD=0 逐层迭代，支持最高 10 层 CNAME 链与循环防御，referral 缺失 bailiwick 胶水记录时自动“借道解析（Glue Borrow）”兜底。
- **客户端 DNSSEC 密码学自验证**：内嵌 IANA 根信任锚（KSK-2017，key tag 20326），屏蔽解析器 AD 位操纵，逐层拉取并验证 DS / DNSKEY / RRSIG，输出四态结论 **SECURE / INSECURE / BOGUS / INDETERMINATE**。

### 🖥️ 6. 内嵌 Flask 实时 Web 看板（`src/web_server.py`）
- 默认监听 `0.0.0.0:8765`（端口可配），与桌面端共享同一数据内核，浏览器即可远程查看。
- 提供**实时连通看板**、**SLA 视图**、**Webhook 投递失败详情面板**，以及 `/api/webhook/*` 等只读 REST 接口；后端异常时返回稳定 JSON（而非 500 页面），前端输出经 HTML 转义防 XSS。

### 📦 7. 宿主自适应与打包自愈生态
- **静默托盘自启**：支持 `--minimized`，开机自启时直接隐藏主窗体退化为系统托盘常驻。
- **写保护路径透明迁移**：检测到 frozen 打包态时，自动把 config / WAL 时序库 / 日志 / `crash.log` 重定向到 `%LOCALAPPDATA%\NetMonitor`，规避 Program Files 等受保护目录权限问题。
- **全线程崩溃捕获**：重写 `sys.excepthook` 与 `threading.excepthook`，主循环与全部后台线程的未捕获异常均落盘 `crash.log` 追溯。
- **打包冲突自愈**：`build.bat` / `build_exe.spec` / `check_build_env.py` / `fix_pathlib.bat` 在构建前检测并移除与 PyInstaller 静态分析冲突的历史 `pathlib` backport，保障一次性产出绿色单目录运行版。

---

## 🛠️ 技术栈

| 层 | 技术 |
|---|---|
| 桌面 GUI | CustomTkinter（现代暗黑主题、高密度响应式栅格） |
| Web 看板 | Flask + Werkzeug（`make_server` 内嵌 WSGI） |
| 数据内核 | SQLite3（WAL、单写队列批量、三级降采样、自动保留期清理） |
| 探测/诊断 | subprocess 并发、`dnspython`（底层报文引擎）、`cryptography`（DNSSEC 验签） |
| 报表 | `openpyxl`（结构化导出、二级故障单 JOIN） |
| 可视化 | Matplotlib（5 分钟滑窗实时波形） |
| 托盘 | `pystray` + `Pillow` |

---

## 📂 项目结构

```text
NetMonitor/
├── assets/                       # 运行时生成的告警音频
│   ├── alert_warning.wav
│   ├── alert_alarm.wav
│   └── alert_recovery.wav
├── src/
│   ├── ui/                       # CustomTkinter 图形界面
│   │   ├── main_window.py        # 主窗体事件循环与高密度 Grid 布局
│   │   ├── chart_panel.py        # 实时连通/延时图表面板
│   │   ├── waveform_window.py    # Matplotlib 滑窗波形
│   │   ├── history_panel.py      # 历史趋势面板
│   │   ├── ip_card.py            # 单节点状态卡片
│   │   ├── dns_diag_window.py    # DNS 高级诊断交互窗
│   │   ├── icmp_diag_window.py   # ICMP/PMTU 诊断交互窗
│   │   ├── traceroute_result_window.py
│   │   ├── settings_dialog.py / dialogs.py / fonts.py / window_utils.py
│   ├── ping_engine.py            # 多协议探测引擎（ICMP/TCP/HTTP(S)/DNS）
│   ├── alert_manager.py          # 告警状态机 + 音频合成 + Webhook 总线
│   ├── webhook_outbox.py         # 可靠 outbox 投递调度器（重试/排序/恢复）
│   ├── data_store.py             # SQLite 时序内核、SLA 状态机、Excel 取证导出
│   ├── web_server.py             # Flask 实时 Web 看板 + REST API
│   ├── config_manager.py         # 目标优先 / 全局兜底双层配置
│   ├── diag_sem.py               # 跨诊断全局单槽互斥信号量
│   ├── dns_diag.py               # DNSSEC / 迭代权威解析引擎
│   ├── icmp_diag.py              # PMTU 二分追踪与巨型包压测探针
│   ├── trace_policy.py / traceroute_summary.py / traceroute_util.py
│   ├── history_store.py          # 内存波形滑动缓冲
│   ├── host_validation.py / capacity.py / logger.py
│   ├── icon_generator.py / utils_autostart.py
├── main.py                       # 入口：路径自适应 + 全线程崩溃捕获
├── build.bat / build_exe.spec    # PyInstaller 打包
├── check_build_env.py / fix_pathlib.bat   # 打包环境自检与冲突自愈
├── setup.bat                     # 初始化 venv + 安装依赖 + 生成 start.bat
├── requirements.txt
└── README.md
```

---

## 🚀 快速开始

### 💻 开发环境
```bat
git clone https://github.com/ganepro220222/NetMonitor.git
cd NetMonitor

:: 初始化向导：自动创建 .venv、安装依赖并生成 start.bat
setup.bat

:: 启动（setup 生成的脚本，等价于 .venv\Scripts\python.exe main.py）
start.bat
```
启动后桌面客户端即开始监控，浏览器访问 `http://127.0.0.1:8765`（默认端口，可在设置中修改）即可打开 Web 看板。

### 🚀 生产打包（绿色单目录分发）
```bat
build.bat
```
产物输出于 `dist/NetMonitor/`，双击 `NetMonitor.exe` 无黑框运行。开机自启可使用 `NetMonitor.exe --minimized` 直接进托盘静默值守。

---

## 📄 开源协议
本项目基于 **MIT License** 开源。
