# -*- coding: utf-8 -*-
"""portctl · 端口控制台命令行客户端（1.0.1 配套）。

用法：
  python portctl.py list                 全表一览（L0 无 token）
  python portctl.py find  <端口>          精查一个端口（附指纹）
  python portctl.py kill  <端口>          先查后杀（自动取指纹走 kill-by-port）
  python portctl.py protection           保护自检
  python portctl.py health               地址发现/健康检查

只读同目录 runtime.json / api_token.txt；只连 127.0.0.1；所有闸在服务端，
本工具是纯客户端薄壳。退出码：0 成功（含 already_free），1 失败。
"""

import ctypes
import json
import socket
import sys
import time
from pathlib import Path

# Windows 上 stdout 默认跟随控制台代码页（cmd 常为 GBK），UTF-8 终端会显乱。
# 统一强制 UTF-8 输出：Windows Terminal / VSCode / PowerShell 7 开箱即用；
# 老 cmd(GBK) 用户如遇乱码，可自行保留 PYTHONIOENCODING 后门。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PORT = 3999
SCAN_RANGE = 100           # 与本体 DEFAULT_PORT + PORT_SCAN_RANGE 同段（单测 88 锁对齐）
CONNECT_TIMEOUT = 0.6      # TCP 握手；只作用于 connect，不拖住读
READ_TIMEOUT = 2.0         # 单次 recv（对齐本体 _health_identity 的 2s）
PROBE_BUDGET = 1.8         # 单个候选的总时限：防"每 0.4 秒吐 1 字节"的滴流服务
DISCOVERY_ATTEMPTS = 2     # 覆盖"刚双击、本体还没监听"的启动窗口
DISCOVERY_RETRY = 0.5
INSTANCE_HEADER = "X-Port-Console-Instance"
USAGE = __doc__


def _pid_alive(pid) -> bool:
    """只问"这个 pid 现在是否存在"，绝不发信号（Windows 上 os.kill 会真杀进程）。"""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(0x1000, False, int(pid))   # QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        k32.CloseHandle(handle)
    except Exception:
        return False
    return True


def _read_runtime_claim():
    """读本包 runtime.json 的租约，返回 {port,pid,instance_id} 或 None。

    1.3 R2：旧实现直接 data.get()，runtime.json 若是合法 JSON 但非对象（[]、null、
    123）就 AttributeError 带栈退出；base_url 尾段不是数字也会 ValueError。
    这里把"不是一张能用的租约"统一收敛成 None。
    """
    rt = BASE_DIR / "runtime.json"
    if not rt.exists():
        return None
    try:
        data = json.loads(rt.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    base = str(data.get("base_url") or "")
    if not base.startswith("http://127.0.0.1:"):
        return None
    tail = base.rsplit(":", 1)[1]
    if not tail.isdigit():
        return None
    port = int(tail)
    if not (1 <= port <= 65535):
        return None
    pid = data.get("pid")
    return {
        "port": port,
        "pid": pid if isinstance(pid, int) and not isinstance(pid, bool) else 0,
        "instance_id": str(data.get("instance_id") or ""),
    }


def _candidates(claim):
    """候选端口：租约端口优先，其后是 3999 起的有界区间（去重）。

    测试缝：纯函数，供测试注入（生产只用默认区间）。"""
    ports = []
    if claim:
        ports.append(claim["port"])
    for p in range(DEFAULT_PORT, DEFAULT_PORT + SCAN_RANGE):
        if p not in ports:
            ports.append(p)
    return ports


def _health(port):
    """探一个候选端口；返回 health body（dict）或 None。

    认人判据（全中才认）：状态行 200、JSON 对象、ok is True、api_version == "v1"、
    port == 本端口。1.3 R2 之前只判"TCP 能连"：3999 被别的软件占着时它算"在线"，
    而本体其实已经顺延到 4000，调用方停在这个假命中上继续用错端口。
    """
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        return None
    deadline = time.monotonic() + PROBE_BUDGET
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(READ_TIMEOUT)
            s.sendall((
                "GET /api/v1/health HTTP/1.1\r\n"
                "Host: 127.0.0.1:" + str(port) + "\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii"))
            data = b""
            while True:
                if time.monotonic() > deadline or len(data) > 8192:
                    return None          # 滴流/超大响应：不认
                chunk = s.recv(2048)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    parts = head.split(b"\r\n", 1)[0].split()
    if len(parts) < 2 or parts[1] != b"200":
        return None
    try:
        obj = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("ok") is not True:
        return None
    if obj.get("api_version") != "v1" or obj.get("port") != port:
        return None
    return obj


_REFUSED = ""   # 非空＝本次失败是"明确拒绝"，不是"不在线"（两条文案不再互相打脸）


def _discover():
    """地址发现：租约优先 ＋ 身份核对 ＋ 歧义拒绝。返回 (port, instance_id) 或 None。

    跨时刻的三条规矩：
      ① runtime.json 只在 listen 成功之后写（见本体 main），所以"文件里的端口"
         在文件存在的每一刻都真的能收连接；
      ② 端口上的应答必须自报 instance_id，与租约里的同一个才算"本包实例"；
      ③ 租约不可用（pid 已退）时允许区间兜底，但只认"唯一一个控制台"，
         有两三个就明确拒绝——宁可不认，也不认错人。
    1.2 遗留租约（有 pid、无 instance_id）＝**降级为无租约路径**：
      · 不按租约端口"信任这一次"，也不因租约 pid 活着就拒绝——这两条都会让
        1.2 现场上的 CLI 全线误拒；
      · 做法＝忽略这份租约，只做区间有界发现：唯一命中就放行（告警一次），
        两个以上仍按"歧义拒绝"；请求期校验按"应答不自报实例号"的降级口径走
        （见 _request 的 expect_instance=""）。
    这一步只读 json 与 health，不读 token、不发命令。
    """
    global _REFUSED
    _REFUSED = ""
    claim = _read_runtime_claim()
    claim_live = bool(claim and claim["pid"] and _pid_alive(claim["pid"]))
    want = claim["instance_id"] if claim else ""
    if claim_live and not want:
        print("[!] runtime.json 是 1.2 遗留租约（有 pid、无 instance_id）：本次按"
              "**无租约路径**处理，只做区间有界发现。重启控制台后会写入实例号，"
              "本提示消失。", file=sys.stderr)
        claim_live = False          # 降级：不拿它当租约，也不据此拒绝
    ports = _candidates(claim)
    found = []
    for attempt in range(DISCOVERY_ATTEMPTS):
        found = []
        for p in ports:
            ident = _health(p)
            if not ident:
                continue
            iid = str(ident.get("instance_id") or "")
            found.append((p, iid))
            if want and iid == want:
                return p, iid
        if found:
            break
        if attempt + 1 < DISCOVERY_ATTEMPTS:
            time.sleep(DISCOVERY_RETRY)   # 刚双击：本体可能还在配置校验/取锁
    if claim_live:
        who = "、".join(f"{p}（{i or '无实例号'}）" for p, i in found)
        if found:
            _REFUSED = (f"runtime.json 记的实例还活着（pid {claim['pid']}），但找到的控制台"
                        f"是另一个实例（{who}）；拒绝替别的实例执行命令。"
                        f"想用当前目录的控制台，删掉从别处抄来的 runtime.json 再试。")
        else:
            _REFUSED = (f"runtime.json 的租约还活着（pid {claim['pid']}），但没有找到可确认"
                        f"的控制台应答（可能进程卡死、被防火墙挡住，或端口上是别的服务）。"
                        f"先查清 pid {claim['pid']} 现在是谁：tasklist /fi \"pid eq {claim['pid']}\" ——是控制台"
                        f"就结束后重启；不是（pid 已被别的进程领走）就删掉本目录的 runtime.json 再启动。")
        return None
    if len(found) == 1:
        p, iid = found[0]
        print(f"[!] 未能确认身份：runtime.json 无可用租约，按区间唯一命中的控制台 "
              f"{p}（实例 {iid or '无实例号'}）继续。", file=sys.stderr)
        return p, iid
    if len(found) > 1:
        who = "、".join(f"{p}（{i or '无实例号'}）" for p, i in found)
        _REFUSED = (f"区间里同时有 {len(found)} 个控制台（{who}），无法判断哪个是本包的；"
                    f"拒绝在这种歧义下执行命令。先启动本包控制台，或关掉别的实例再试。")
    return None


def _offline_exit():
    """五个命令（list/find/kill/protection/health）唯一的出口。1.3 R2：四种情形各说各的事实，文案互不复用——

      ① 无租约（或租约已退）且区间无控制台 → 这里打「不在线」（唯一出现处）；
      ② 租约带号、找到的控制台却是另一个实例 → _REFUSED，拒绝执行；
      ③ 租约还活着、但没有可确认的控制台应答 → _REFUSED，也拒绝执行；
      ④ 无租约但区间命中多个控制台 → _REFUSED（歧义），**不走唯一命中放行**。

    拒绝原因整句由 _discover 写进 _REFUSED，这里原样打印，不再补一句通用的
    「端口上有应答」——情形③并不能确定端口是否应答，补了就与事实打架。
    """
    if _REFUSED:
        print(f"[X] {_REFUSED}")
        return 1
    print(f"[X] 控制台不在线：runtime.json 记的端口和 "
          f"{DEFAULT_PORT}~{DEFAULT_PORT + SCAN_RANGE - 1} 都没有应答为"
          "「本包端口控制台」的服务。")
    print("    刚双击启动就报这个：等一两秒再试（本体先监听、后写 runtime.json）。")
    return 1


class ConsoleChanged(Exception):
    """发现之后、发命令时，端口上的应答者已经换了实例（跨时刻窗口）。"""


def _request(method: str, path: str, port: int, body=None, token: str = "",
             client: str = "portctl", timeout: float = 20, expect_instance=None):
    """裸 socket HTTP（零 urllib）。连接目标仅限 127.0.0.1 + int 端口。

    1.3 R2：每个应答都要对实例号。发现到发命令之间端口可能被顶（旧实例退出、
    新实例顺延接手），没有这一步时 list/health 会把别家实例的结果当成本包的；
    状态行也先验形态再转 int（旧实现遇非 HTTP 应答直接 ValueError 带栈退出）。

    expect_instance 三态：None＝不校验（探活内部用）；""＝要求应答**不自报**实例号
    （1.2 遗留租约的降级路径）；具体串＝必须同号。所以"无实例号"不会顺带把
    请求期校验关掉——这一点是 P-14/ N-03 的对策。
    """
    headers = {"Host": f"127.0.0.1:{int(port)}"}
    data = b""
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Port-Console-Token"] = token
    headers["X-Port-Console-Client"] = client
    raw = f"{method} {path} HTTP/1.1\r\n"
    for k, v in headers.items():
        raw += f"{k}: {v}\r\n"
    raw += f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as s:
        s.sendall(raw.encode("utf-8") + data)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    head, _, payload = buf.partition(b"\r\n\r\n")
    parts = head.split(b"\r\n", 1)[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ConsoleChanged("非 HTTP 应答")
    status = int(parts[1])
    got = ""
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == INSTANCE_HEADER.encode("ascii").lower():
            got = value.strip().decode("utf-8", "replace")
    if expect_instance is not None and got != expect_instance:
        raise ConsoleChanged(got or "无实例头")
    try:
        obj = json.loads(payload.decode("utf-8")) if payload else None
    except json.JSONDecodeError:
        obj = None
    return status, obj


def _load_token():
    f = BASE_DIR / "api_token.txt"
    if not f.exists():
        return ""
    return f.read_text(encoding="utf-8-sig").strip()


def _read_token():
    tok = _load_token()
    if not tok:
        print("[X] api_token.txt 不存在（服务首启自动生成）。先启动控制台再试。")
        sys.exit(1)
    return tok


LEVEL_TXT = {"system": "系统", "other": "他人", "self": "自己", "unknown": "未知"}


def _fmt_port(p):
    name = p.get("name") or "未知"
    lvl = LEVEL_TXT.get(p.get("level"), "?")
    ok = "是" if p.get("kill_allowed") else "否"
    return (f"{p['port']:>6}  {p['addr']:<15} {p['pid']:>7}  {(p['proc'] or '?'):<22} "
            f"{name:<14} {lvl:<4} {ok}")


def cmd_list(srv_port, instance_id):
    st, obj = _request("GET", "/api/v1/agent/ports", srv_port,
                       expect_instance=instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        print(f"[X] 查询失败 HTTP {st}: {(obj or {}).get('message', '')}")
        return 1
    items = obj.get("items", [])
    print(f"{'端口':>6}  {'地址':<15} {'PID':>7}  {'进程':<22} {'归属':<14} 级别 可杀")
    for p in items:
        print(_fmt_port(p))
    print(f"\n共 {len(items)} 条监听（{obj.get('generated_at', '')}）")
    return 0


def _find_one(port_no, srv_port, token, instance_id):
    st, obj = _request("GET", f"/api/v1/agent/ports?port={int(port_no)}",
                       srv_port, token=token, expect_instance=instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        return st, obj, None
    items = obj.get("items", [])
    sid = items[0].get("snapshot_id") if items else None
    return st, obj, sid


def cmd_find(port_no, srv_port, token, instance_id):
    st, obj, sid = _find_one(port_no, srv_port, token, instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        print(f"[X] 查询失败 HTTP {st}: {(obj or {}).get('message', '')}")
        return 1
    items = obj.get("items", [])
    if not items:
        print(f"[OK] 端口 {port_no} 当前没有监听者（空闲）")
        return 0
    if len(items) > 1:
        print(f"[!] 端口 {port_no} 有 {len(items)} 个占用者：")
        for p in items:
            print("   ", _fmt_port(p))
        print("    多占用不自动选择，请确认目标后用 kill 前先人工核对。")
        return 1
    p = items[0]
    name = p.get("name") or "未知"
    lvl = LEVEL_TXT.get(p.get("level"), "?")
    killable = "可杀" if p.get("kill_allowed") else "不可杀"
    print(f"[OK] 端口 {port_no}: {p['proc']} (PID {p['pid']}, {name}, {lvl}, {killable})")
    if sid and p.get("kill_allowed"):
        print(f"     指纹已下发（60 秒有效），可直接 kill")
    elif sid:
        print("     指纹仅供核对（60 秒有效），不可 kill——目标是受保护的")
    else:
        print("     未下发指纹（可能受保护或多占用），kill 前先看 kill_allowed")
    if p.get("protected_reason"):
        print(f"     保护原因: {p['protected_reason']}")
    return 0


def cmd_kill(port_no, srv_port, token, instance_id):
    print(f"[1/2] 查询端口 {port_no} ……")
    st, obj, sid = _find_one(port_no, srv_port, token, instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        print(f"[X] 查询失败 HTTP {st}: {(obj or {}).get('message', '')}")
        return 1
    items = obj.get("items", [])
    if not items:
        print(f"[OK] 端口 {port_no} 本来就没有监听者（already_free）")
        return 0
    if len(items) > 1:
        print(f"[X] 端口 {port_no} 有 {len(items)} 个占用者，拒绝盲杀：")
        for p in items:
            print("   ", _fmt_port(p))
        return 1
    p = items[0]
    name = p.get("name") or "未知"
    print(f"      目标: {p['proc']} (PID {p['pid']}, {name})")
    if not sid:
        print(f"[X] 未取得指纹（kill_allowed={p.get('kill_allowed')}，"
              f"原因: {p.get('protected_reason') or '多占用或快照未下发'}）——不硬来")
        return 1
    print("[2/2] 发送关闭请求（confirm=true）……")
    st, obj = _request("POST", "/api/v1/agent/kill-by-port", srv_port,
                       body={"port": int(port_no), "snapshot_id": sid, "confirm": True},
                       token=token, expect_instance=instance_id)
    if obj is None:
        print(f"[X] 服务异常 HTTP {st}")
        return 1
    if obj.get("ok"):
        if obj.get("already_free"):
            print("[OK] 端口已空闲（already_free）")
            return 0
        killed = obj.get("killed", [])
        rem = obj.get("remaining", [])
        print(f"[OK] 关闭完成：killed {len(killed)} 个进程"
              f"（{', '.join((k.get('proc') or '?') for k in killed[:5])}）")
        if rem:
            print(f"[!] 端口仍有占用: {rem}")
            return 1
        print("     端口已释放，关干净了。")
        return 0
    reason = obj.get("reason", "?")
    msg = obj.get("message", "")
    hints = {
        "target_identity_required": "指纹缺失/过期——重新跑一次 kill 会自动取新指纹",
        "target_changed": "端口易主——重新确认目标，别硬来",
        "kill_not_allowed": f"受保护（{(obj.get('protected_reason') or msg)}）——不要再试",
        "rate_limited": "频率闸（6 次/分钟）——等一分钟",
        "multiple_owners": "多个占用者——先 find 看清单",
        "command_failed": "强杀没生效——多半是权限不够，试试用管理员身份重跑控制台",
    }
    if reason == "multiple_owners":
        for c in obj.get("candidates", []):
            print(f"     candidate: 端口 {c['port']} PID {c['pid']} {c['proc']} "
                  f"({c.get('name') or '未知'}, 可杀={c.get('kill_allowed')})")
    print(f"[X] {reason}: {hints.get(reason, msg)}")
    return 1


def cmd_protection(srv_port, instance_id):
    st, obj = _request("GET", "/api/v1/protection", srv_port,
                       expect_instance=instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        print(f"[X] 查询失败 HTTP {st}")
        return 1
    print(f"在监听的保护端口: {obj.get('active_ports')}")
    print(f"历史保护端口:     {obj.get('history_ports')}")
    print(f"保护进程名:       {obj.get('protected_processes')}")
    for w in obj.get("warnings", []):
        print(f"[!] {w}")
    return 0


def cmd_health(srv_port, instance_id):
    st, obj = _request("GET", "/api/v1/health", srv_port, expect_instance=instance_id)
    if st == 200 and obj and obj.get("ok"):
        print(f"[OK] 端口控制台在线: http://127.0.0.1:{srv_port}/ (api {obj.get('api_version')})")
        return 0
    print(f"[X] 健康检查失败 HTTP {st}")
    return 1


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if len(argv) >= 2 else 1
    cmd = argv[1]
    if cmd not in ("list", "find", "kill", "protection", "health"):
        print(f"[X] 未知命令: {cmd}\n" + USAGE)
        return 1
    port_no = 0
    if cmd in ("find", "kill"):
        if len(argv) < 3:
            print(f"[X] 用法: python portctl.py {cmd} <端口号>")
            return 1
        try:
            port_no = int(argv[2])
        except ValueError:
            print("[X] 端口必须是整数")
            return 1
        if not (1 <= port_no <= 65535):
            print("[X] 端口超出 1..65535")
            return 1
    found = _discover()
    if found is None:
        return _offline_exit()
    srv_port, instance_id = found
    try:
        if cmd == "list":
            return cmd_list(srv_port, instance_id)
        if cmd == "protection":
            return cmd_protection(srv_port, instance_id)
        if cmd == "health":
            return cmd_health(srv_port, instance_id)
        token = _read_token()
        if cmd == "find":
            return cmd_find(port_no, srv_port, token, instance_id)
        return cmd_kill(port_no, srv_port, token, instance_id)
    except ConsoleChanged as e:
        print(f"[X] 发现后端口易主：应答者已不是刚才认到的实例（{e}）。重跑一次命令。")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
