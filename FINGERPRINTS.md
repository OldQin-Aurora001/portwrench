# PortWrench 端口扳手 · 指纹清单（1.3.1 开发版）

> **发布版**：21 条通用示例规则 ＋ 6 个系统保护端口，不含任何本机定制。
> **认版口径**：SHA256 前 16 位。运行时自建件（`runtime.json` / `port_map.json` /
> `dynamic_protection.json` / `unknown.json` / `kill_audit.jsonl` / `api_token.txt`）不入表。

## 本体与 CLI（7 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `port_console.py` | 128,642 | `113633C375515AA6` |
| `portctl.py` | 21,504 | `DE1DF28F904422E6` |
| `index.html` | 30,108 | `339FB01C5615F6B7` |
| `rules.json` | 2,000 | `D7868BC85C1CFBCF` |
| `protection.json` | 176 | `088CF0D167A2CE96` |
| `ports.json` | 47,595 | `0DC0F560D532EA31` |
| `ports.md` | 9,010 | `024B3209DEFF1B49` |

## 文档（13 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `README.md` | 25,162 | `72136404CE74EAA3` |
| `README.en.md` | 30,083 | `93B7873EBB4C9CD6` |
| `使用说明.md` | 9,939 | `335986F5095770F7` |
| `DEVELOPMENT.md` | 10,070 | `2F953BDFD8C157F8` |
| `CHANGELOG.md` | 26,361 | `58D9984FC14EC552` |
| `SKILL.md` | 7,831 | `DAABF73387FCD736` |
| `NOTICE.md` | 7,665 | `80F41D7229D95817` |
| `NOTICE.en.md` | 8,339 | `EB94935F67C93E0F` |
| `LICENSE` | 1,070 | `0783452F7ED48AE9` |
| `icon.png` | 13,751 | `7AFF6A9D46155FDD` |
| `启动端口控制台.bat` | 615 | `EEAD371F44B83BD1` |
| `.gitattributes` | 502 | `CC3B1A191CD01369` |
| `.gitignore` | 612 | `F7845261A7BD4A5E` |

## DSH 薄壳（5 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `packages/dsh-portwrench/package.json` | 769 | `4E07D1DFB86F9B19` |
| `packages/dsh-portwrench/cordis.patch.yml` | 60 | `583BC1E423C8CF36` |
| `packages/dsh-portwrench/lib/index.mjs` | 4,984 | `3B38E9EA0E5BE6E0` |
| `packages/dsh-portwrench/lib/client.js` | 981 | `EA11135286326CA1` |
| `packages/dsh-portwrench/README.md` | 3,294 | `A88D0503C49CA25D` |

## 测试（4 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `tests/test_port_console.py` | 164,139 | `91C400940C95586A` |
| `tests/acceptance_api.py` | 30,101 | `D213E813C24897AA` |
| `tests/fixture_process_tree.py` | 2,555 | `0F3DE8E73EAA003A` |
| `tests/fixture_windowed.ps1` | 1,529 | `95B4CD36235DB02A` |

## assets（26 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `assets/brand/bell-black-128.png` | 3,141 | `D3ACB651D3D4CCA9` |
| `assets/brand/bell-black-48.png` | 1,195 | `AB92EF13AFD3B4D8` |
| `assets/brand/bell-black-512.png` | 13,751 | `7AFF6A9D46155FDD` |
| `assets/brand/bell-gray-128.png` | 3,245 | `1D91718681C058CC` |
| `assets/brand/bell-gray-48.png` | 1,193 | `35E3578A40AA99EB` |
| `assets/brand/bell-gray-512.png` | 14,108 | `4DC35F7EC76F19BD` |
| `assets/brand/bell-white-128.png` | 3,287 | `C6D372FEFFD2CBF6` |
| `assets/brand/bell-white-48.png` | 1,214 | `2193EBA41DB35AB8` |
| `assets/brand/bell-white-512.png` | 14,558 | `21FD90BBFCF326BE` |
| `assets/brand/bell.svg` | 1,580 | `18EC31976EDBB052` |
| `assets/team/avatar-ashu.png` | 404,750 | `6991E2730D8A5F7D` |
| `assets/team/avatar-azi.png` | 450,855 | `09E4C85FB34AF76D` |
| `assets/team/avatar-daa.png` | 480,997 | `42CE7798ACAC3EA4` |
| `assets/team/avatar-daniu.png` | 424,143 | `ACCBF839FFD63C20` |
| `assets/team/avatar-laodou.png` | 440,813 | `8DA0FAC1DC6D51D2` |
| `assets/team/avatar-laoqin.png` | 413,944 | `9486A71ACC0E5B3E` |
| `assets/team/avatar-neko.png` | 598,216 | `FFDC7C219F856D87` |
| `assets/team/avatar-pro.png` | 476,518 | `7C30CAFD71353AF9` |
| `assets/team/avatar-turbo.png` | 417,620 | `030A4D2034A3C1CE` |
| `assets/team/avatar-xiaoa.png` | 384,312 | `B32EEA394A523019` |
| `assets/team/avatar-xiaoniu.png` | 492,048 | `C6A8DF9A02E90879` |
| `assets/team/avatar-xiaoshen.png` | 411,902 | `65A3FF74C5207D06` |
| `assets/截图/ScreenShot_2026-11-01_191715_797.png` | 385,553 | `668DDD81B3DC280E` |
| `assets/截图/ScreenShot_2026-11-01_191715_797_地址脱敏.png` | 362,580 | `379938D70F006033` |
| `assets/截图/ScreenShot_2026-11-01_191845_385.png` | 35,435 | `6E02C141683DCDF7` |
| `assets/截图/ScreenShot_2026-11-01_191935_345.png` | 58,568 | `D847D5BAE9A21226` |

- 清单文件数：55；生成时间：2026-11-04 22:00（**1.3.1 发布版**：在 1.2.0 公开版基础上完成八项整改——stderr 三级解码＋CLIXML 先剥后截、Server 头 1.3.1、15 处异常原文收口、版本字 1.3.1、CHANGELOG 口径；**159 单测全绿**；1.2 时代「21 步 acceptance 全过、真机实测跨端口 same-site、壳探活挡 200 假诱饵选对本体」为作者环境实测）
- **换行口径（1.3 项⑧a）：本清单所有字节数/SHA256 锚定 LF 字节；发布流程禁止 CRLF 检出打 zip，仓库已加 `.gitattributes` 强制 LF。**
- **验证归属（1.3 项⑧b）：1.2 发布版页脚所列「21 步 acceptance 全过；真机实测跨端口 Sec-Fetch-Site=same-site、壳能挡 200 假诱饵选对本体」均为作者环境实测；本包验证以 `tests/` 自跑结果为准，不把作者环境结论当成任何其他机器的背书。**
