# Changelog · PortWrench 端口扳手

本文件记录每一版相对上一版的变化。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

---

## [1.0.0] - 2026-11-01 · 初始版本

> 一个本地网页看板：看清这台机器上谁占着哪个端口，点一下就能关干净。
> 零依赖：Python 3.10+ 标准库 + PowerShell，不引第三方包。

### Added（核心功能）

- **端口扫描与展示**：`Get-NetTCPConnection -State Listen` 扫描，前端表格展示本机全部 TCP 监听端口
- **自动认人规则系统**：`rules.json` 外置规则表，按命令行与进程名匹配；出厂 14 条（11 条应用识别 + 3 条系统兜底）。装新东西只改配置、不改代码
- **进程树关闭**：`taskkill /T /F`，子进程一并回收，不留残留
- **手工改名持久化**：`port_map.json` 按端口存名（不是按 PID），重启后名字还在
- **四色分级显示**：🔴 系统 / 🟡 他人 / 🟢 自己 / ⚪ 未知；按钮按级别禁用或二次确认
- **前端单页**：原生 HTML + JS，5 秒自动轮询 + 手动刷新
- **双击启动**：`启动端口控制台.bat`，默认 `http://127.0.0.1:3999/`，被占自动 +1 顺延

### Security（安全护栏）

- **杀前三关复核**：真正执行 `taskkill` 之前再验一次身份——**句柄还在、能打开、创建时间仍是那个**。任何一关不符即拒绝，并区分「目标已自行退出」与「目标被顶掉」两种情形
- **三元组 + 启动时间**：`(端口, PID, 进程名)` 之外再加进程创建时间，防 PID 复用误杀
- **指纹必填**：关闭请求必须携带 `snapshot_id`；缺失、空串、纯空白一律 400
- **快照按会话存**：一次快照一个 ID，多个调用方并发时不互相作废；伪造 ID 打不掉有效指纹
- **路径不可读 fail-closed**：可执行文件路径读不到的目标一律受保护（宁可少杀，不赌）
- **会话 0 一律保护**：Windows 系统服务所在会话的进程不可从面板关闭
- **两阶段退出**：先 `PostMessageW(WM_CLOSE)` 请它自己退，最多等 2 秒（每 200 ms 复核）；仍存活才允许强杀
- **只绑本机**：只监听 `127.0.0.1`，不绑 `0.0.0.0`
- **不做**：一键全杀、按名称批量清理、对无端口进程的操作、全程管理员

### 技术架构

- **零依赖**：Python 3.10+ 标准库 + PowerShell 原生命令，不引 psutil / Flask / Electron
- **单文件后端**：`port_console.py` 约 1,950 行
- **配置外置**：`rules.json`（识别）、`protection.json`（保护）、`port_map.json`（手工改名）全部外置，改配置不改代码

---

## [1.0.1] - 2026-11-01 · 端口知识库与 AI 接口

> 在 1.0 基础上加端口对照表、AI 回环 API、展示缓存。
> **关闭速度与 1.0 相同**——本版提速的是「看」，不是「杀」。

### Added（新增能力）

- **端口对照表集成**：`ports.json` / `ports.md` 内置 111 条端口知识（含国产数据库、中间件、常用软件），零代码侵入，只答「这个端口通常是什么」
- **AI Agent 回环 API**：`/api/v1/*` 统一路径，按权限分三档——L0 只读（无 token）、L1 UI 通道（本机同源证据）、L2 AI 通道（管理 token + `confirm`）
- **命令行客户端**：`portctl.py` 提供 `list / find / kill / protection / health` 五个命令，AI 与终端免拼 JSON
- **kill-by-port 按端口模式**：`POST /api/v1/agent/kill-by-port` 只收端口号 + `snapshot_id`，身份由服务端同轮新鲜扫描解析；多占用者一律 `409 multiple_owners` 拒绝，唯一占用者走全部护栏
- **AI skill 包**：`SKILL.md`，各壳复制到自家 skills 目录即自动触发
- **本地审计日志**：`kill_audit.jsonl` 记录谁 / 几点 / 杀了谁 / 结果；超 1 MiB 自动轮转，留 3 个备份

### Changed（优化改进）

- **5 秒 TTL 展示缓存**：`GET /api/v1/ports` 列表缓存 5 秒，展示耗时从 1.4 s 降到 20 ms 量级。**杀前重扫绝不缓存；杀后验证也是独立扫描**，不复用任何旧快照
- **`/protection` 换用 `GetActiveTcpListeners()`**：1.2 s → 0.2 s 量级
- **API 版本化**：全部路径统一 `/api/v1/*`，旧的 `/api/ports`、`/api/kill` 不再使用
- **错误人话化**：403 / 429 / 409 等返回码翻译成人话，附稳定小写 `reason` 字段
- **幂等关闭**：端口已空返回 `already_free`，调用方可省重试逻辑

### Removed（移除）

- **单端口快路径**：规划过、实测后**取消**。逐 PID 递归取子树在真实规模下需上百秒（611 个树成员 × WMI 冷启动约 268 ms），撞 8 秒超时线。改为「一次全量快照 + 内存构树」，仍是杀前重扫，但不走单端口查询

### Security（安全增强）

- **频率闸**：每通道每分钟 6 次真实强杀上限；`already_free` 不计费——闸门管的是「杀」这个动作，不是「请求」
- **Token 等同本机授权**：`api_token.txt` 不进仓库、不截图、不外传；轮换需停控制台 → 删或换 → 重启

---

## [1.1.0] - 2026-11-01 · 公开发布版

> 本版是**自家使用**的整理版：品牌正名、身份自认知、数据 schema 升级、编码兼容、仓库卫生。
> **代码功能语义与 1.0.1 一致**，原有判据与安全边界一条未动。
> **脱敏不在本版做**——面向公开发布的版本另起一版，届时再做私有规则分离与内部代号清理。

### Changed（已确定项）

- **品牌正名**：项目定名 **PortWrench（端口扳手）**；README、使用说明、SKILL、CHANGELOG 统一
- **身份自认知**：出厂规则新增「端口扳手本体」规则（`match: port_console`，`level: self`，order 12）。此前查控制台自身端口要靠 `protected_reason` 兜底才认得出，现走规则通道正常得名
- **数据 schema 升级**：`ports.json` 顶层 `categories` 从字符串数组升级为对象数组 `[{"name": 分类名, "count": 条数}, ...]`，字段自描述，且 `count` 与 `ports` 数组严格一致
- **编码兼容**：`portctl.py` 输出统一强制 UTF-8（`sys.stdout/stderr.reconfigure`），Windows Terminal / VSCode / PowerShell 7 开箱即用；老 `cmd`（GBK）用户保留 `PYTHONIOENCODING` 后门
### Fixed（体检修复）
- **health 端点开放 CORS**（`Access-Control-Allow-Origin: *` 仅限 health）：
  DSH 壳页从 DSH 源（如 :3080）跨源探测本体在线状态，无 ACAO 头会被浏览器拦截，
  壳将永远显示「未运行」引导页（验收必挂）。health 只暴露在线/版本/uptime，
  无敏感面；**其余端点（含 L0 列表）刻意不开**——不给恶意网页跨源枚举本机端口的口子
  （单测 70 把守：health 有 ACAO、agent/ports 无）。
- **文档数字漂移修正**：使用说明「出厂 21 条」→「22 条」（本体规则加入后未同步）。
- **`.gitignore` 补缺**：`*.bak-*`（编辑备份件）、`pcon-*.stale/.tmp`（运行残留）、
  `node_modules/`（薄壳未来 npm 依赖）。
- **已知不一致（自家版可留，发布版必修）**：`DEFAULT_RULES`（15 条）与 `rules.json`
  （22 条）两套列表自 1.0.1 起漂移——7 条对照表规则只在 `rules.json`。服务运行以
  `rules.json` 为权威，DEFAULT 仅作兜底；发布前建议同步。

### Changed（UI）
- **前端换装「深夜玻璃」**：深蓝黑底＋紫/青光斑、毛玻璃面板（`backdrop-filter`）、渐变标题字、玻璃 pill 筛选钮、行 hover 提亮、毛玻璃弹窗遮罩与 toast。**零外部资源不变**（无字体/图标 CDN，系统字体栈＋emoji＋纯 CSS），`textContent` 防注入渲染纪律不变，JS 逻辑零改动（仅「保护原因」小字由内联硬编码色改挂 CSS 类以适配深底）；四色级别徽章保留颜色＋文字双通道

### Added（本版新增）

- **LICENSE**：MIT
- **仓库卫生**：清运行时产物（`api_token.txt` / `instance.lock` / `runtime.json` / `unknown.json`）、补 `.gitignore`

### Added（UI 交互）

- **表头点击排序**：端口/地址/进程/归属/级别/启动时间六列表头可点（▲/▼/悬停提示），再点反向；
  级别列按**语义顺序**排（系统→他人→自己→未知），非字母序；空值（未命名归属等）恒排最后；
  纯客户端排序，5 秒轮询刷新后排序状态保持。默认端口升序。

### Changed（发布脱敏）
- **出厂规则通用化**：家人/内部规则 8 条 → 通用软件示例集（企业微信/微信/MySQL/
  VS Code/Jupyter 等 21 条），「具体规则先于宽泛规则」的教学语义保留
  （`wechat-work` 先于 `wechat`，有单测把守）；出厂 22 条 → 21 条。
- **知识库本机业务条移除**：3 条内部服务端口条删除，总数 111 → **108**
  （分类统计同步，`ports.md` 与 `ports.json` 一致，单测 59 把守）。
- **代码注释中性化**：内部工单编号、审查者称呼全部改为「安全审查建议 N」等
  中性表述（技术语义、实测数据全保留）；内部章节引用（§）清理。
- **测试数据面同步**：识别样本与断言随通用规则集更新，全部回归通过。
- **README 正文残留 3 处已清**（两个「Minimax 复审增补」→「安全审查增补」、
  识别率段拍板署名移除）；致谢分工表按作者署名保留。

### Added（发布清单）
- **`FINGERPRINTS.md`**：全包 28 件发布指纹清单（SHA256 前 16 · 全家认版口径），
  任何文件改动后由落码方重算。

### 兼容性说明

- `categories` 为**破坏性 schema 变更**，升级时需同步更新 `rules.json`

### Added（DSH 插件壳）

- **`packages/dsh-portwrench/` 薄壳**：DSH 设置页「端口扳手」tab，三态页面
  （本体健康 → iframe 嵌完整 UI / 本体未跑 → 下载引导页 / 非 Windows → 提示）。
  `dsh.bundle.patch` 经 `cordis.patch.yml` 声明（monorepo 子包合规）；
  壳只「接」不「装」——本体需用户自行下载运行，市场描述不作自动安装暗示。
  壳 API 逐行核对自 `dsh-breeze-tts` 源码；**坑：`client.js` 的 `id` 必须逐字等于
  npm 包名，否则前端白屏**。坑④已实测：本体响应无 `X-Frame-Options`，iframe 可嵌。

### Changed（一致性收口）
- **`DEFAULT_RULES` 与 `rules.json` 同步为 22 条**：两套列表自 1.0.1 起漂移
  （7 条对照表规则只在 `rules.json`，代码内置兜底缺这 7 条）——现一致。
  服务运行以 `rules.json` 为权威，代码内置仅作首启/兜底。
- **`icon.png` 落位**：品牌铃铛图（`assets/brand/bell-black-512.png`），
  满足市场对图标经 raw.githubusercontent 可访问的要求。

### Added（资源）
- **`assets/`**：`brand/`（铃铛图标 SVG＋黑白灰三色 × 48/128/512）、
  `截图/`（UI 截图，供市场条目 screenshots 使用）。
  `team/`（12 张家人头像，README 头像墙引用）。

---

## [1.1.1] - 2026-11-02 · 动态保护与编辑体验修复

### Added（用户手动保护）

- **行内「保护」按钮**：UI 每行新增一键保护——对识别不了或暂时归属未知的端口，
  用户点一下即立闸（`POST /api/v1/ui/protect`），关闭请求返回
  `403 kill_not_allowed`（保护原因「用户手动保护」）。设计动机：远程 AI 的宿主端口
  默认归属「他人」（可杀），机器主人未必知情——**先给自己人上保护，再谈清别人的端口**。
- **解除保护**：受保护行按钮变「解除保护」，自绘确认框防手滑
  （`POST /api/v1/ui/unprotect`）。三条边界焊死：
  ①静态系统保护（`protection.json`）不可通过 API 解除（403 `static_protected`）；
  ②只保护当前监听中的端口（不确定的不保）；
  ③动态保护表持久化至 `dynamic_protection.json`，**重启不丢**。
- **审计留痕**：protect / unprotect 事件写入 `kill_audit.jsonl`（带端口＋时间）。

### Fixed（编辑体验）

- **改名编辑不再被轮询冲掉**：此前行内改名输入框直接嵌在表格行里，
  5 秒轮询整表重渲染会把输入中的字连框冲掉、保存按钮点不到——
  现编辑期间暂停轮询（保存/取消/Esc 后恢复），手动刷新同样过闸。

### Tests

- 新增动态保护单测 5 例（功能流/静态边界/未监听拒绝/持久化重载/**真 HTTP 路由接线**），
  全套 **79 项单测**双版（家自用版＋发布版）全绿；小阿总三发真机验收
  （CLI 文案链／静态口拒解除／持久化＋审计）全过。

---

## [1.2.0] - 2026-11-03 · 跨源收口与端口顺延适配（未发布）

> 三份补丁可分别独立应用，亦按 ①→②→③ 顺序兼容连打。
> 全部静态校验与 `git apply --check` 在交付副本完成；单测/真机验收需在
> 装有 Python 3.10+ 的机器（224）上执行。

### Added（1.2 落码批 · 第二批九项）

> 三份补丁作为 **P1 基线**先行合入，第二批九项在其上落码。
> 每项都配「判据①正常路径 ＋ 判据②故意破坏必须变红」，六发破坏验证共 17 个断言全红锁死。

- **改-1 · 跨源判定统一谓词（白名单式）**：新增 `is_cross_origin_request()`，
  `/ports` 的 refresh 门与 `agent/ports` 共用一把尺子。
  **跨源当且仅当**：`Sec-Fetch-Site` 有值且不在 `{same-origin, none}` 内，或 `Origin` 存在且非本机同源。
  **为什么是白名单**：黑名单只认 `cross-site` 会漏掉 `same-site`——而 `same-site` 正是
  「本机另一个端口上的页面用 `<img>` 发简单 GET」的形状（真 Edge + CDP 实测：异端口 `<img>` →
  `Sec-Fetch-Site: same-site`、**不发 Origin**）。将来浏览器新增取值时白名单自动 fail-closed。
  **两端回退不同**：`agent/ports` 跨源直接 403；`/ports?refresh=1` 只降级为缓存查询（`refresh_ignored:true`）。
- **改-2 · `agent/ports` 收口**：顺序固定 **403（跨源）→ 429（限流）→ 503（在飞满）→ 才扫描**。
  匿名请求降为**纯只读**——不下发 `snapshot_id`、不写 `unknown.json` 台账；响应带 `authenticated`
  供调用方自辨语义。限流为滑动窗口＋在飞闸一体（匿名 30/min、token 60/min、在飞 2、窗口 60s，
  **四个具名常量**，真机可调）。`_AgentPortsGate` 与杀链路的 `try_consume_rate_slot` 互不相干——
  那把闸管杀，这把管读。
- **改-3 · 3999 从静态保护表移除（四处成组）**：`protection.json` 删 3999 那一行 ＋
  `DEFAULT_PROTECTION` 同步删 ＋ 注释改写缘由 ＋ `test_67`/`test_74b` 成对回改。
  **默认端口与顺延逻辑一字未动**（3999 起、`PORT_SCAN_RANGE=100`）。
  **为什么删**：本体端口会顺延，3999 迟早被别的程序占，静态表里留着它就等于**误护那个无关程序**；
  而本体自保走 `protection_reason` 的「控制台自身端口」（按实际绑定口无条件命中），与这张表无关。
- **改-4 · System 兜底规则只看进程名（甲案）**：`classify_entry` 里 `level=system` 的规则
  改用 `proc` 名匹配、**不看 cmdline**。应用识别规则（self/other）仍走 cmdline＋proc 双源。
  **为什么**：AI 程序命令行带 `--system-prompt` 是家常便饭，拼接匹配会把它们误标 system 级 →
  403 硬拒 →「关掉 DSH 全家」这个核心诉求被一个命令行参数打死。本机实测误标率
  **150/400（37.5%）→ 93/400（23.2%）**，掉的 57 个全是 cmdline-only 误标，剩下 88 个是
  `svchost.exe` 等正当命中。
- **改-5 · `port_map.json` 字段长度校验**：`proc` ≤ 260（NTFS 文件名上限）、`started` ≤ 64
  （ISO8601 时间戳），超长在加载处抛 `ConfigError`。此前这两个字段不设防，手工编辑塞进的
  垃圾串会一路带进 `classify_entry` 与 `fill_mapping_fingerprint`。
- **改-6 · `started` 换主源 ＋ 文案分流**：快照脚本主源改为 `Get-Process.StartTime`，
  CIM `CreationDate` 降为回退（**双源兜底**）。格式保持 `yyyy-MM-ddTHH:mm:sszzz`，
  消费方零改动（`pid_matches_start` 第③关按 `[:19]` 秒级比对）。
  **为什么换**：交付机对拍 `Get-Process.StartTime` **233/233 残差 0**，CIM `CreationDate` 仅 28/233。
  新增 reason `target_identity_unavailable` 与 `target_identity_required` 分流——
  「这台机器读不到该进程的启动时间」和「你没先查指纹」是两件事，混用会让 AI 陷入
  「取不到 → 再查 → 再 400」的重试循环。
- **改-8 · `protect_port` 503 稳定话术**：响应体改固定句，`{e}` 详情只进服务端 stderr（L-13 风格）。
- **改-9 · `.gitignore` 补 `dynamic_protection.json`**：它与 `unknown.json`/`port_map.json` 同属
  本机用户数据，此前漏列。

### Added（1.2 落码批 · 三附项与后续两刀）

- **附A · `acceptance_api.py` 适配**：step4/10/11/13 取 sid 处补 `agent_hdr()`，step4 增
  「匿名无 sid」断言。**收口后匿名不发 sid，旧脚本 step4 必卡**，这是必然推论不是额外需求。
  （与 06 参考实现独立落地，逐字节收敛到同一 sha16 `A7925B7F9ECD27A3`。）
- **附B · `fixture_windowed.ps1` 补 UTF-8 BOM**：**1.1 遗留伤**——1.0.1 有 BOM、1.1 重写时丢了，
  PowerShell 5.1 把中文注释按 GBK 误读，`param()` 解析失败。1.1 的 21 步自重写后从未整跑过，
  所以这颗雷一直埋着。内容零改动，只补 3 字节头。
- **改-10 · DSH 壳探活校验响应体（M-06 净增量）**：壳的 `probe()` 从「只判 `r.ok`」改为
  「读 body 判 `j.ok===true && j.api_version==='v1'`」。壳包 0.1.1 → **0.1.2**。
  **为什么**：3999–4098 是本体顺延区间，这一段里任何别的 dev server 返回 200 都会被旧逻辑
  当成本体嵌进来——**认错人**。真机 A/B 实测：1.1 旧逻辑选中 3999 的假诱饵，1.2 新逻辑选中
  4000 的真本体，100 口并发 40 ms。
- **改-11 · 时序审查补注**：`build_tree_with_session_filter` 的耦合声明补一层——
  **B1 杀前实时复核只复核 target 这一个 pid，不逐个复核子树成员**；而 `taskkill /T` 按实时
  父子关系杀。两者范围不相等，改这一带时必须知道。**纯注释，零逻辑改动。**

### Fixed（修复）

- **DSH 插件壳端口发现（补丁①）**：壳页不再硬编码 `127.0.0.1:3999`——
  打开时并发探测 `3999–4098`（与本体 `PORT_SCAN_RANGE` 顺延范围严格一致），
  自动选最低响应端口嵌入；本体被占顺延时面板不再假报「未运行」。
  壳包版本 0.1.0 → 0.1.1。
- **GET 副作用收口（补丁②）**：`/api/v1/ports?refresh=1` 对浏览器跨站请求
  （`Sec-Fetch-Site:cross-site`）降级为普通缓存查询（响应带
  `refresh_ignored:true`），堵住任意网页跨站触发 PowerShell 全表扫描的放大
  口子；不带 SFS 头的本机脚本/CLI/验收（沿用 README §5 单用户信任模型）与
  同源页面行为不变。
- **unknown 台账过滤（补丁②）**：受保护/系统级目标（`protection_reason` 非空、
  `level=system`）与进程信息缺失（`proc="?"`）的残影不再写入 `unknown.json`，
  普通可杀未知目标照常脱敏记账。旧台账条目不自动清理（用户数据不擅删）。
- **默认值与配置对齐（补丁②）**：`DEFAULT_RULES`（21 条示例规则）与
  `DEFAULT_PROTECTION`（6 个系统端口 ＋ 9 个系统进程名）与同目录
  `rules.json` / `protection.json` 严格一致，配置丢失重建不再缩水；
  新增单测 74 锁死两边一致性。**发布轨的默认值即通用示例，不含任何本机定制。**
- **审计成对收口（补丁③）**：枚举主窗口、关窗存活轮询、杀前身份复核、
  杀后存活验证四个 Win32 边界补 try/except——异常时补写 `finished`
  （`reason=internal_error:<类型>`）再返回 500，杜绝真实日志中出现过的
  started 悬空；taskkill 在杀前复核阶段不会被误执行。

### Removed（清理）

- 删除已被原子频率闸取代的死代码 `check_kill_rate_limit` / `record_kill_rate`
  （S1 之后全仓无调用；频率闸唯一入口为 `try_consume_rate_slot`）。

### Docs（口径统一）

- 规则条数与代码行数统一为 2026-11-03 实测值：发布轨示例规则 **21 条**；
  `port_console.py` 基线 **2212 行** → 三份补丁合入 **2254 行** → 第二批九项＋改-10/11 后
  **2421 行**；单测 **79 → 88（P1 基线）→ 103（1.2 终态）**。CHANGELOG 各历史版本的
  当期数字（14/15/21/22、约 1,950 行等）作为历史记录保留，不回改。
- README/使用说明中「出厂 20/21 条」等当前态表述改为「21 条示例规则」；
  识别率「54%」明确标注为 1.0.1 时 21 条规则下的历史实测。
- DEVELOPMENT.md 尾注版本号「1.1 · 2026-11」对齐为「1.1.1 · 2026-11」
  （历史遗留尾注，非本次新漂移）。
- `SKILL.md` 中「79 个单测」表述**已同步为 103**（1.2 终态实测）。

### 发布指纹

- 2026-11-03 对 1.1 包全量 53 行实测：仅 CHANGELOG.md 一行在清单中已陈旧
  （清单记 13,130/`371618B35DC928F5`，实测 13,133/`FD9F24A0FE550E37`，
  属定版后 3 字节改动未回算的历史遗留）；DEVELOPMENT.md 的 hash 与清单一致。
- 合入全部三份补丁后，必须按补丁③方案中的步骤重算 `FINGERPRINTS.md`：
  port_console.py、tests/test_port_console.py、README.md、使用说明.md、
  CHANGELOG.md（含修正既有陈旧行）、DEVELOPMENT.md、
  packages/dsh-portwrench/{package.json,README.md,lib/index.mjs}
  的字节数与 SHA256 前 16 位，并更新清单页脚时间。

---

## 版本时间线

| 版本 | 日期 | 阶段 |
|------|------|------|
| 1.0.0 | 2026-11-01 | 初始版本，核心四件套 + 四道安全闸 |
| 1.0.1 | 2026-11-01 | 端口知识库 + AI 接口 + 展示缓存 |
| 1.1.0 | 2026-11-01 | 公开发布版（含脱敏） |
| 1.1.1 | 2026-11-02 | 用户手动保护 + 编辑体验修复 |
| 1.2.0 | 2026-11-03 | 壳端口发现＋探活校验 / GET 收口＋跨源白名单谓词 / agent 收口与限流 / 3999 移除 / System 甲案 / ticks 换源 / 台账过滤 / 审计收口（未发布） |

---

*CHANGELOG · PortWrench 端口扳手 · 最后更新 2026-11-03（1.2.0 未发布）*
