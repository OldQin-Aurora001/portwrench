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

import json
import socket
import sys
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
USAGE = __doc__


def _resolve_base_port():
    """地址发现：默认 3999；不通读 runtime.json 的 base_url（禁端口扫描）。"""
    if _probe(DEFAULT_PORT):
        return DEFAULT_PORT
    rt = BASE_DIR / "runtime.json"
    if rt.exists():
        try:
            data = json.loads(rt.read_text(encoding="utf-8"))
            base = str(data.get("base_url", ""))
            # base_url 形如 http://127.0.0.1:4000 —— 只认回环（与 acceptance Api 同款）
            if base.startswith("http://127.0.0.1:"):
                port = int(base.rsplit(":", 1)[1])
                if _probe(port):
                    return port
        except (json.JSONDecodeError, ValueError, OSError):
            pass
    return None


def _probe(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=0.6) as s:
            s.sendall(b"")
        return True
    except OSError:
        return False


def _request(method: str, path: str, port: int, body=None, token: str = "",
             client: str = "portctl", timeout: float = 20):
    """裸 socket HTTP（零 urllib）。连接目标仅限 127.0.0.1 + int 端口。"""
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
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
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


def cmd_list(port):
    st, obj = _request("GET", "/api/v1/agent/ports", port)
    if st != 200 or not obj or not obj.get("ok"):
        print(f"[X] 查询失败 HTTP {st}: {(obj or {}).get('message', '')}")
        return 1
    items = obj.get("items", [])
    print(f"{'端口':>6}  {'地址':<15} {'PID':>7}  {'进程':<22} {'归属':<14} 级别 可杀")
    for p in items:
        print(_fmt_port(p))
    print(f"\n共 {len(items)} 条监听（{obj.get('generated_at', '')}）")
    return 0


def _find_one(port_no, srv_port, token):
    st, obj = _request("GET", f"/api/v1/agent/ports?port={int(port_no)}",
                       srv_port, token=token)
    if st != 200 or not obj or not obj.get("ok"):
        return st, obj, None
    items = obj.get("items", [])
    sid = items[0].get("snapshot_id") if items else None
    return st, obj, sid


def cmd_find(port_no, srv_port, token):
    st, obj, sid = _find_one(port_no, srv_port, token)
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


def cmd_kill(port_no, srv_port, token):
    print(f"[1/2] 查询端口 {port_no} ……")
    st, obj, sid = _find_one(port_no, srv_port, token)
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
                       token=token)
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
    }
    if reason == "multiple_owners":
        for c in obj.get("candidates", []):
            print(f"     candidate: 端口 {c['port']} PID {c['pid']} {c['proc']} "
                  f"({c.get('name') or '未知'}, 可杀={c.get('kill_allowed')})")
    print(f"[X] {reason}: {hints.get(reason, msg)}")
    return 1


def cmd_protection(port):
    st, obj = _request("GET", "/api/v1/protection", port)
    if st != 200 or not obj or not obj.get("ok"):
        print(f"[X] 查询失败 HTTP {st}")
        return 1
    print(f"在监听的保护端口: {obj.get('active_ports')}")
    print(f"历史保护端口:     {obj.get('history_ports')}")
    print(f"保护进程名:       {obj.get('protected_processes')}")
    for w in obj.get("warnings", []):
        print(f"[!] {w}")
    return 0


def cmd_health(port):
    st, obj = _request("GET", "/api/v1/health", port)
    if st == 200 and obj and obj.get("ok"):
        print(f"[OK] 端口控制台在线: http://127.0.0.1:{port}/ (api {obj.get('api_version')})")
        return 0
    print(f"[X] 健康检查失败 HTTP {st}")
    return 1


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if len(argv) >= 2 else 1
    cmd = argv[1]
    if cmd == "list":
        srv = _resolve_base_port()
        if srv is None:
            print("[X] 控制台不在线：默认 3999 与 runtime.json 都不通。先启动控制台。")
            return 1
        return cmd_list(srv)
    if cmd == "protection":
        srv = _resolve_base_port()
        if srv is None:
            print("[X] 控制台不在线。先启动控制台。")
            return 1
        return cmd_protection(srv)
    if cmd == "health":
        srv = _resolve_base_port()
        if srv is None:
            print("[X] 控制台不在线：默认 3999 与 runtime.json 都不通。")
            return 1
        return cmd_health(srv)
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
        srv = _resolve_base_port()
        if srv is None:
            print("[X] 控制台不在线。先启动控制台。")
            return 1
        token = _read_token()
        if cmd == "find":
            return cmd_find(port_no, srv, token)
        return cmd_kill(port_no, srv, token)
    print(f"[X] 未知命令: {cmd}\n" + USAGE)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
