# 🚀 NetMonitor: 网络连通性及网络空间高级诊断监测系统

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![Platform](https://img.shields.io/badge/platform-windows-blue.svg)](https://www.microsoft.com/windows)
[![Code Style](https://img.shields.io/badge/style-hacker--density-black.svg)]()
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

**NetMonitor** 是一款专为网络运维专家与信息安全审计人员打造的高可靠、多线程网络状态实时监测及网络空间数字化取证系统。系统原生支持现代暗黑极客（Modern Dark）视觉风格，底层通过全异步数据落盘架构与互斥诊断信号量机制，实现秒级高频探测下的极致运行稳定性与司法级故障现场留痕。目前系统完美适配 **Windows** 宿主环境，Linux 跨平台架构已纳入后期演进路线。。

---

## ⚡ 核心技术特性 (Core Architectural Features)

### 🚨 1. 异步立体化告警总线 (`src/alert_manager.py`)
* **零外部依赖音频自合成**：摒弃传统外挂 wav 音频文件的做法，底层直接调用标准库 `wave` 与 `struct` 模块，通过正弦波算法纯数学动态合成橙色警告（880Hz 短促双音）、红色告警（440Hz/880Hz/紧迫循环）以及绿色恢复（523Hz/784Hz 升调提示）音频。
* **跨线程异步安全播音**：针对 Win32 消息循环缺陷进行深层重构，播音请求全量托管至 `winsound.PlaySound` 的异步文件流标记位（`SND_ASYNC`），彻底根治多线程并发环境下子线程调用导致的告警音频静默丢弃故障。
* **多通道智能感知 Webhook**：内置多平台感知逻辑，自动识别并将标准文本或富文本卡片无缝分发至企业微信、钉钉及飞书 Webhook 终端，支持全生命周期事件过滤与状态去重。

---

### 💾 2. 高并发时序持久化与数字资产审计 (`src/data_store.py`)
* **SQLite WAL 独占单线程写队列**：利用独立写线程（`data_store-writer`）独占 SQLite 写入连接，常规探测结果每 60 秒批量落盘（极低磁盘 I/O 开销），告警/恢复等突发事件采用即时冲刷（Immediate Flush）策略，配合线程局部变量（TLS）只读连接缓存，实现 WAL 模式下读写完全并发。
* **多粒度波形自适应下采样**：提供对数级历史波形读取逻辑，自适应匹配时间窗口跨度（≤2小时提取原始秒级，≤48小时提取 1 分钟桶，>48小时提取小时级静态聚合），保证长周期趋势透视下的探针权重均等与内存安全。
* **二级故障现场数字化绑定 (Level-2 Incident Binding)**：节点发生严重阻断的瞬间，状态机自动派发唯一故障单号（`incident_id`），网络追踪模块即时执行路由取证并将断点拓扑快照、跳数变动状态与该 ID 进行数据库底层强绑定。
* **Excel 数字化司法级审计报告**：一键生成包含“全局 SLA 连通汇总表”、“多节点自适应时序 Sheet 归档”以及“全故障事件流时间线表”的专业 Excel 报告，深度嵌入故障瞬时路由拓扑断点及精确的 ICMP 错误原因，满足高规格网络安全合规性审计需求。

---

### 🔍 3. 高级网络空间多模式诊断矩阵 (`src/dns_diag.py`, `src/icmp_diag.py`)
* **跨诊断全局单槽互斥锁 (`src/diag_sem.py`)**：通过全局单槽信号量（`DIAG_TASK_SEM`）对高级 ICMP 诊断、DNS 诊断和手动 Traceroute 执行强互斥锁定，防止多路探针争抢物理链路带宽而引发探测 RTT 偏高或进程并发倾斜。
* **高级 ICMP 链路特征透视**：支持大载荷注入（最高 9000 字节）、DF（Don't Fragment）分片保护、网络层巨型包链路压测、以及基于二分查找算法的 PMTU（路径最大传输单元）智能自适应追踪。
* **顺序多路解析器 Diff 矩阵**：支持系统默认及最多 3 路自定义名称服务器（共 4 列对照）的串行解析差异对齐，深度输出单条记录的精确 TTL 变动和结构化应答，让地方运营商 DNS 污染与劫持无所遁形。
* **迭代权威路径追踪 (Authority Trace)**：完全绕过本地递归缓存，从 IANA IPv4 根服务器提示（`_ROOT_IPV4_HINTS`）开始发出 RD=0 迭代探测，支持最高 10 层 CNAME 链深度和循环防御，并在 referral 缺失内 bailiwick 胶水记录时自动激活单次借道解析（Glue Borrow）兜底逻辑。
* **本地根锚点 DNSSEC 密码学自验证**：源码内嵌 IANA 根区终极信任锚点（KSK-2017，key-tag 20326），完全屏蔽解析器的 AD 标志位操纵，直接在客户端逐层拉取验证 TLD 的 RRSIG、DS 与 DNSKEY 记录，严密解构并输出四状态（SECURE / INSECURE / BOGUS / INDETERMINATE）权威结论。

---

### 📦 4. 宿主环境自适应优化与打包自愈生态
* **静默 Tray 模式自启动 (`main.py`)**：原生支持 `--minimized` 命令行参数。开机自启时自动隐藏主窗体并 withdrew 图形上下文，退化为系统托盘常驻，保障后台静默值守。
* **写保护路径透明迁移**：当检测到程序处于打包后冻结（Frozen）状态且部署在 Program Files 等受保护路径下时，自动将配置、WAL 时序库、日志无损重定向至 `%LOCALAPPDATA%\NetMonitor`，彻底终结因权限不足引发的后台静默溃散。
* **全线程异常捕获覆盖**：全面重写 `sys.excepthook` 和 `threading.excepthook`，实现主事件循环线程与全量后台后台异步线程未捕获异常的 `crash.log` 堆栈追溯落盘。
* **环境自愈式打包生态 (`build_exe.spec`, `check_build_env.py`)**：配套自动化自提权修复脚本（`fix_pathlib.bat`），在打包前自动检测并强制卸载与 PyInstaller 静态分析机制严重冲突的历史 `pathlib` 历史后端口依赖包，确保一次性构建绿色单目录运行版本。

---

## 🛠️ 技术栈 (Tech Stack)

* **GUI Framework**: CustomTkinter (Modern Dark Design, High-density responsive grid)
* **Data Core**: SQLite3 (Write Queue Batching, WAL Mode, Automatic Data Retention Cleanup)
* **Networking Engine**: Subprocess Concurrency, Asyncio, `dnspython` (Low-level Message Engine), `cryptography`
* **Reporting Backend**: `openpyxl` (Structured Data Formatting, Level-2 Incident JOINs)
* **Telemetry**: Matplotlib (5-Minute Slid-Window Realtime Waveform Rendering)

---

## 📂 项目结构说明 (Directory Structure)

```text
NetMonitor/
├── assets/                  # 静态资源与多媒体文件
│   ├── icon.ico             # 程序高分辨率主图标
│   └── theme/               # CustomTkinter 现代暗黑主题定制 JSON
├── src/                     # 核心模块源码
│   ├── ui/                  # 现代化图形界面与上下文组件
│   │   ├── main_window.py   # 主窗体事件循环与高密度 Grid 布局
│   │   ├── plot_canvas.py   # 基于 Matplotlib 的 5 分钟时序滑动波形画布
│   │   └── diag_dialog.py   # DNS/ICMP 高级诊断交互弹窗
│   ├── alert_manager.py     # 纯数学正弦波音频自合成与 Webhook 告警通知总线
│   ├── config_manager.py    # 目标优先/全局兜底双层配置管理器
│   ├── data_store.py        # SQLite 时序核心、SLA 状态机与 Excel 取证导出引擎
│   ├── diag_sem.py          # 跨诊断组件全局单槽互斥信号量（防止带宽争抢失真）
│   ├── dns_diag.py          # DNSSEC/Authority Trace 核心密码学与路由迭代引擎
│   ├── icmp_diag.py         # PMTU 二分追踪与巨型包压测诊断探针
│   └── history_store.py     # 双端内存时序波形滑动缓冲区
├── build.bat                # 自动化隔离打包脚本
├── build_exe.spec           # PyInstaller 静态依赖全量钩子配置
├── check_build_env.py       # 打包前 pathlib 冲突自检与提权自愈脚本
├── fix_pathlib.bat          # 提权移除 pathlib 历史后端口冲突修复工具
├── main.py                  # 系统主程序入口与全线程崩溃覆盖捕获层
├── requirements.txt         # 严格版本依赖清单
└── setup.bat                # 自动化虚拟环境初始化与快速启动配置向导

📦 快速开始 (Quick Start)
💻 开发环境部署
克隆代码至本地：

Bash
git clone [https://github.com/ganepro220222/NetMonitor.git](https://github.com/ganepro220222/NetMonitor.git)
cd NetMonitor
执行自动化初始化向导（脚本会自动创建 .venv 虚拟环境并完成依赖对齐）：

Bash
setup.bat
运行程序：

Bash
start.bat
🚀 生产环境打包（绿色单目录分发）
系统内置了完善的环境冲突自愈和 spec 声明。如需分发单目录全功能绿色版，请直接双击运行：

Bash
build.bat
构建产物将输出在 dist/NetMonitor/ 路径下，双击 NetMonitor.exe 即可无黑框清爽运行。

📄 开源协议 (License)
本项目基于 MIT License 协议开源。