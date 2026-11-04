---
name: portwrench
version: "1.3.1"
author: PortWrench Team
license: MIT
metadata:
  hermes:
    tags: [ports, processes, ops, windows, family-tool]
description: "Use when 查本机哪个端口被谁占了、关掉关了黑框还赖着的残留进程、AI 程序化清端口；or when the user asks to check which process occupies a port, kill a leftover process, or close ports programmatically — PortWrench usage rules (query-before-kill, status-code table, red lines)."
---

# PortWrench 端口扳手使用口径（中文）

> **本机端口管家**（本包所在目录：`port_console.py` / `portctl.py` / `使用说明.md` 都在这里）。
> 完整操作手册在**本包 `使用说明.md`**，工程/安全文档在 **`README.md`**；
> 本 skill 是"遇到端口问题时的最短正确路径"。English version below.

## 何时用本 skill

- 要查"本机哪个端口被谁占了"；
- 要把某个关了黑框还赖着不走的残留进程清干净；
- 用户让你"看看端口"/"杀掉 XX 端口的进程"。

## 铁律（先读这个再动手）

1. **先查后杀，固定口径**——不许跳过查询直接猜端口/猜 PID；
2. **禁扫端口找服务**——用 `python <包>\portctl.py health` 做地址发现（内置
   **有界发现**：3999–4098 逐个验 `ok:true ＋ api_version:"v1" ＋ port`，
   并用实例号确认是本包实例）；手动排障先读本包 `runtime.json` 的 `base_url`
   （写在监听成功之后）；**别自己写循环扫区间**，也别把「3999 不通」当成
   「服务没起」——被占会顺延（3999–4098）。
3. **403 不要再试**——受保护目标（保护端口/Session 0/System32 宿主/信息读不到
   fail closed/用户在面板上手动保护的目标），工具拒杀是设计不是故障；
4. **只有 `ok:true 且 remaining=[]` 才算关干净**；
5. token（本包 `api_token.txt`）等同本机授权：不打印、不落聊天窗、不外传。

## 最短路径（优先 CLI）

```
python <本包>\portctl.py list            # 全表一览（L0 无 token）
python <本包>\portctl.py find  <端口>    # 精查：归属/可杀/指纹
python <本包>\portctl.py kill  <端口>    # 先查后杀一条龙（人话报结果）
python <本包>\portctl.py protection      # 保护自检
python <本包>\portctl.py health          # 在线检查
```

- 服务没起 → 提醒用户双击本包 `启动端口控制台.bat`（不要自己用管理员硬起）；
- 没有 CLI 环境时用 HTTP 口径：

```
GET /api/v1/agent/ports?port=<端口>   → 看名字/级别/kill_allowed，拿 snapshot_id
POST /api/v1/agent/kill-by-port      {"port":<端口>,"snapshot_id":"<上一步>","confirm":true}
Header: X-Port-Console-Token: <token>（建议再加 X-Port-Console-Client: <你的名字>，审计留名）
```

## 返回码速查

| 返回 | 含义 | 该干嘛 |
|---|---|---|
| `already_free`（200） | 端口本来就空 | 收工 |
| `400 target_identity_required` | 指纹缺失/过期 | 重新 GET 取 snapshot_id |
| `409 target_changed` | 端口易主/PID 复用 | 重新确认，别硬来 |
| `409 multiple_owners` | 多个占用者 | 退回 GET 看清单，严格模式点名 |
| `403 kill_not_allowed` | 受保护 | **不要再试**，向用户说明是保护线 |
| `429 rate_limited` | 频率闸（每通道 6 次/分钟） | 等一分钟，检查调用循环 |

## 容易踩的坑

- `GET /api/v1/ports` 有 5 秒展示缓存，判定身份/杀前确认一律用
  `agent/ports?port=X`（永远新鲜扫描）或 `?refresh=1`；
- 杀不动≠工具有问题：exe/会话/启动时间读不到的目标一律 fail closed
  （宁可拒杀不赌）——同一软件"用户态可杀、服务态不可杀"是保护线在正确工作；
- 端口还占着看返回 `remaining`，按它给的当前占用者重新确认——
  工具不会拿旧快照追杀新进程。

## 自验

```
py -3 -B -m unittest discover -s tests -v        # 159 个单测
py -3 -B tests\acceptance_api.py --base-url <BASE> --token-file api_token.txt   # 21 步（<BASE> 取 portctl.py health 输出）
```

---

> **【中文到此为止】** 家人日常读到这里即可；以下为英文对照段（发布版保留），非必读。

# PortWrench Usage Rules (English)

> The local port manager lives in this package directory (`port_console.py`,
> `portctl.py`, `使用说明.md`). Full manual: `使用说明.md`; engineering and
> security notes: `README.md`. This skill is the shortest correct path when
> a port problem comes up.

## When to use

- Checking which process occupies a local TCP port;
- Closing a leftover process that keeps its port bound after the window is gone;
- Programmatically listing / closing ports on the user's request.

## Hard rules (read before acting)

1. **Query before kill — always.** Never guess ports or PIDs;
2. **Never scan ports to find the service yourself.** Use `portctl.py health` — it has
   bounded discovery over 3999–4098 (verifying `ok:true + api_version:"v1" + port`)
   plus an instance id proving it is *this* package's console; otherwise read
   `base_url` from `runtime.json` in this package (written only after listen succeeds);
3. **On 403, stop.** The target is protected (protected ports / Session 0 /
   System32 hosts / unreadable info → fail-closed / user-protected via the panel).
   Refusal is by design;
4. **Done means `ok:true` AND `remaining=[]`.** Anything else is not clean;
5. The token (`api_token.txt`) equals local authorization: never print it,
   never paste it into chats, never share it.

## Shortest path (CLI first)

```
python <package>\portctl.py list            # all listeners (L0, no token)
python <package>\portctl.py find  <port>    # owner / kill_allowed / fingerprint
python <package>\portctl.py kill  <port>    # query + kill in one command
python <package>\portctl.py protection      # protection self-check
python <package>\portctl.py health          # liveness check
```

- Service not running → ask the user to start `启动端口控制台.bat`
  (Windows, Python 3.10+; default `http://127.0.0.1:3999/` — if taken, the
  console shifts to 3999–4098; take the real URL from `portctl.py health`
  or `runtime.json`).
- Without a shell, use HTTP:

```
GET /api/v1/agent/ports?port=<port>   → name / level / kill_allowed + snapshot_id
POST /api/v1/agent/kill-by-port      {"port":<port>,"snapshot_id":"...","confirm":true}
Header: X-Port-Console-Token: <token>   (add X-Port-Console-Client: <your-name> for the audit trail)
```

## Status codes

| Response | Meaning | Action |
|---|---|---|
| `already_free` (200) | Port was already free | Done |
| `400 target_identity_required` | Fingerprint missing/expired | GET a fresh `snapshot_id` |
| `409 target_changed` | Port owner changed / PID reused | Re-confirm; do not force |
| `409 multiple_owners` | Several owners | Back to GET, use strict mode to name one |
| `403 kill_not_allowed` | Protected | **Do not retry**; explain the protection line |
| `429 rate_limited` | Rate gate (6 real kills/min/channel) | Wait a minute; check for loops |

## Pitfalls

- `GET /api/v1/ports` is a 5-second display cache; for identity checks use
  `agent/ports?port=X` (always fresh) or `?refresh=1`;
- "Cannot kill" ≠ broken tool: unreadable exe/session/start-time targets are
  fail-closed by design — the same app being killable as a user process but
  protected as a service is the protection line working correctly;
- Port still bound? Read `remaining` and re-confirm against the current owner —
  the tool never hunts a new process with an old snapshot.

## Self-test

```
py -3 -B -m unittest discover -s tests -v        # 159 unit tests
py -3 -B tests\acceptance_api.py --base-url <BASE> --token-file api_token.txt   # 21 steps (<BASE> from portctl.py health)
```
