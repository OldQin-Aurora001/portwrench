# PortWrench 端口扳手 · 发布指纹清单

> 认版口径：SHA256 前 16 位 · 全家约定（v1.1）。对码用——任何文件改动后本表由落码方重算。
> 本表不含自身。运行时自建件（api_token.txt / runtime.json / instance.lock /
> kill_audit.jsonl / unknown.json / port_map.json / __pycache__）不进发布包，故不入表。

## 本体与 CLI（7 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `port_console.py` | 96,676 | `268435006AC7D698` |
| `portctl.py` | 11,314 | `01AABE9B2DF730E1` |
| `index.html` | 26,937 | `89F10A98AF1D07F7` |
| `rules.json` | 2,000 | `D7868BC85C1CFBCF` |
| `protection.json` | 176 | `088CF0D167A2CE96` |
| `ports.json` | 47,595 | `0DC0F560D532EA31` |
| `ports.md` | 9,039 | `66D9283749032659` |

## 文档（12 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `README.md` | 21,469 | `C0CF8A75C015C683` |
| `README.en.md` | 25,845 | `D86F7BD167C38855` |
| `使用说明.md` | 8,592 | `EFEACAB8DA80B1A1` |
| `DEVELOPMENT.md` | 10,061 | `2B302D24D639013E` |
| `CHANGELOG.md` | 11,418 | `7F595E18BC6A1CEA` |
| `SKILL.md` | 6,959 | `B8D46160F94166A1` |
| `NOTICE.md` | 7,665 | `80F41D7229D95817` |
| `NOTICE.en.md` | 8,339 | `EB94935F67C93E0F` |
| `LICENSE` | 1,070 | `0783452F7ED48AE9` |
| `icon.png` | 13,751 | `7AFF6A9D46155FDD` |
| `启动端口控制台.bat` | 615 | `EEAD371F44B83BD1` |
| `.gitignore` | 497 | `E04AAD42913785FA` |

## DSH 薄壳（5 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `packages/dsh-portwrench/package.json` | 769 | `E1563FDAE24974B5` |
| `packages/dsh-portwrench/cordis.patch.yml` | 60 | `583BC1E423C8CF36` |
| `packages/dsh-portwrench/lib/index.mjs` | 2,786 | `C36C10E2BC10AED6` |
| `packages/dsh-portwrench/lib/client.js` | 981 | `EA11135286326CA1` |
| `packages/dsh-portwrench/README.md` | 2,652 | `55D0FF9849C64B60` |

## 测试（4 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---|---|
| `tests/test_port_console.py` | 95,311 | `CDE4DA523AAB3535` |
| `tests/acceptance_api.py` | 28,722 | `D9629E87C13E89E2` |
| `tests/fixture_process_tree.py` | 2,555 | `0F3DE8E73EAA003A` |
| `tests/fixture_windowed.ps1` | 1,526 | `233DD83095BE0349` |

## assets（25 件）

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
| `assets/截图/ScreenShot_2026-11-01_191845_385.png` | 35,435 | `6E02C141683DCDF7` |
| `assets/截图/ScreenShot_2026-11-01_191935_345.png` | 58,568 | `D847D5BAE9A21226` |

- 清单文件数：53；生成时间：2026-11-01 23:33（发布终稿态 · 内部编号清理后重算）
