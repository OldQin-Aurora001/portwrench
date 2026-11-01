# dsh-portwrench

PortWrench（端口扳手）的 DSH 插件壳：在 **DSH 设置 → 插件** 里加一个「端口扳手」面板，
内嵌本机 PortWrench 完整 UI——查看监听端口、识别归属、关闭进程树。

## 它是什么、不是什么

- 这只是**壳**：它把 DSH 和本机 PortWrench 服务连起来。
- PortWrench 本体（`port_console.py`，Python）**不随本插件安装**——需要你自己在
  本机下载并运行（见下方三步）。
- 所有安全闸（杀前身份复核、保护线、审计、频率闸）都在 PortWrench 本体服务端，
  本壳不引入任何新权限。

## 使用三步

1. 从 [PortWrench Releases](https://github.com/OldQin-Aurora001/portwrench/releases)
   下载 zip，解压到任意目录；
2. 双击 `启动端口控制台.bat`（Windows、Python 3.10+；默认 `http://127.0.0.1:3999/`）；
3. 回到 DSH 设置 → 插件 →「端口扳手」，面板会自动检测并嵌入 UI。

PortWrench 未运行时，面板显示引导页（不会白屏）。

## 卸载

**DSH 插件**：设置 → 插件 →「端口扳手」→ 卸载；或命令行 `dsh plugin remove dsh-portwrench`。

**PortWrench 本体**：直接删掉解压出来的目录即可——它不写注册表、不做开机自启、不留后台服务，删目录就干净了。

## 平台

- PortWrench 本体目前**仅支持 Windows**（依赖 `taskkill` / `Win32_Process` /
  `Get-NetTCPConnection`）。非 Windows 平台面板会提示暂不支持。

## 出问题怎么办

| 现象 | 先查什么 |
|---|---|
| 面板一直显示「PortWrench 未运行」 | ① 本体到底跑没跑：浏览器打开 `http://127.0.0.1:3999/` 看一眼<br>② 本体是不是换了端口（被占会自动 +1 顺延，看启动窗口打印的地址） |
| 面板白屏 | 打开 DSH 的开发者工具看 Console——多半是壳没注册上（模块 `id` 与包名不一致会报 `loaded without registering`） |
| 设置页找不到「端口扳手」 | 插件没启用，或 DSH 版本低于插件要求 |
| 点了关闭没反应 | 那是本体的护栏在拦（目标受保护 / 端口易主 / 触发频率闸），看返回里的 `reason` 字段 |

**面板里能看到端口列表 = 链路通了。** 面板里能点、能关，说明 iframe 嵌的确实是本机那个本体。

## 隐私与安全

- 只监听 `127.0.0.1`，绝不开放外网；不做开机自启、不写注册表、不改防火墙。
- 关闭动作全部落审计日志；`api_token.txt` 等同本机授权，不随壳分发。

## 来源

- 本体与设计：[PortWrench](https://github.com/OldQin-Aurora001/portwrench)（MIT）
