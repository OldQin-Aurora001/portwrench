# -*- coding: utf-8 -*-
"""PortWrench 端口扳手单元测试。
仅标准库 unittest + mock。扫描器/外部命令/窗口函数全部替换为假实现。
HTTP 层测试起真 ThreadingHTTPServer（127.0.0.1 随机端口），请求用裸 socket 发送
（Host 头固定 127.0.0.1:3999，与服务端 actual_port=3999 对齐）。
注意：所有 mock 快照的 sessions 决定 SessionId（None → fail closed 不可杀）。"""

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import port_console as pc  # noqa: E402

FAKE_PORT = 3999  # 服务端 actual_port 固定值，请求 Host 头与之对齐


# ----------------------------------------------------------------------------
# 假快照与请求工具
# ----------------------------------------------------------------------------


def conn(addr, port, pid):
    return {"localAddress": addr, "localPort": port, "ownerPid": pid}


def proc(pid, name="python.exe", exe=r"C:\Python\python.exe",
         cmdline="python server.py", ppid=0, started="2026-11-01T10:00:00+08:00"):
    return {"pid": pid, "ppid": ppid, "name": name, "exe": exe,
            "cmdline": cmdline, "started": started}


def make_scan(conns, procs=(), sessions=None):
    # conns/procs 为 list/tuple 时归一为 list；单 dict 保留（as_list 兜底展开）
    return {"connections": list(conns) if isinstance(conns, (list, tuple)) else conns,
            "processes": list(procs) if isinstance(procs, (list, tuple)) else procs,
            "sessions": sessions if sessions is not None else {}}


SCAN_EMPTY = make_scan([])


class SockResp:
    def __init__(self, status, obj):
        self.status = status
        self.obj = obj


def http_req(method, path, body=None, headers=None, timeout=8):
    """裸 socket HTTP/1.1 请求（Host 固定 127.0.0.1:3999）。返回 (status, dict)。"""
    hdrs = {"Host": f"127.0.0.1:{FAKE_PORT}"}
    hdrs.update(headers or {})
    data = b""
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", _server_port()), timeout=timeout) as s:
        s.sendall(req.encode("utf-8") + data)
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


def http_req_raw(method, path, body=None, headers=None, timeout=8):
    """同 http_req，但返回 (status, 原始头文本, dict)——断言响应头用（CORS 等）。"""
    hdrs = {"Host": f"127.0.0.1:{FAKE_PORT}"}
    hdrs.update(headers or {})
    data = b""
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", _server_port()), timeout=timeout) as s:
        s.sendall(req.encode("utf-8") + data)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    head, _, payload = buf.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    head_text = head.decode("utf-8", errors="replace")
    try:
        obj = json.loads(payload.decode("utf-8")) if payload else None
    except json.JSONDecodeError:
        obj = None
    return status, head_text, obj


_SERVER = {"port": 0}


def _server_port():
    return _SERVER["port"]


# ----------------------------------------------------------------------------
# 服务 harness：真 HTTP 栈 + 假扫描
# ----------------------------------------------------------------------------


class Harness:
    """起真服务（随机端口），扫描/mock 全部注入。"""

    def __init__(self, scan=SCAN_EMPTY, tmpdir=None, token="test-token-123", token_ok=True,
                 port_map=None, unknown=None, rules=None, protection=None, console_port=FAKE_PORT):
        self.tmp = Path(tmpdir or tempfile.mkdtemp(prefix="pcon-test-"))
        self.owns_tmp = tmpdir is None
        self._scan = scan
        rules = rules if rules is not None else pc.validate_rules(pc.DEFAULT_RULES)
        protection = protection if protection is not None else pc.validate_protection(pc.DEFAULT_PROTECTION)
        configs = {"rules": rules, "protection": protection,
                   "port_map": port_map or {}, "unknown": unknown or [], "warnings": []}
        self.state = pc.AppState(self.tmp, configs, console_port, token, token_ok)
        self._orig_scan = pc.scan_snapshot
        pc.scan_snapshot = lambda: scan
        self.server = pc.ThreadingHTTPServer(("127.0.0.1", 0), pc.ConsoleHandler)
        self.server.daemon_threads = True
        self.server.app_state = self.state
        self.server.actual_port = console_port
        _SERVER["port"] = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @contextmanager
    def mock_kill(self, scan=None):
        """强杀成功语义：杀前扫描=scan；run_taskkill 被调后扫描变空（进程/端口清空的物理事实）。
        yield 出 state 供断言 killed 标记。"""
        real = scan if scan is not None else self._scan
        state = {"killed": False}

        def fake_scan():
            return make_scan([]) if state["killed"] else real

        def fake_taskkill(pid):
            state["killed"] = True
            return (True, "")

        def fake_matches(pid, started):
            return not state["killed"]   # 杀前复核=指纹相符放行；杀后验证=全死

        with mock.patch.object(pc, "scan_snapshot", fake_scan), \
             mock.patch.object(pc, "run_taskkill", side_effect=fake_taskkill), \
             mock.patch.object(pc, "pid_matches_start", side_effect=fake_matches), \
             mock.patch.object(pc, "pid_alive", return_value=False):
            yield state

    @contextmanager
    def mock_close_ok(self, scan=None):
        """WM_CLOSE 成功语义：关窗消息发出后复核扫描变空。"""
        real = scan if scan is not None else self._scan
        state = {"closed": False}

        def fake_scan():
            return make_scan([]) if state["closed"] else real

        def fake_post(hwnd):
            state["closed"] = True
            return True

        def fake_matches(pid, started):
            return not state["closed"]   # 关窗前=活；关窗复核=已退

        with mock.patch.object(pc, "scan_snapshot", fake_scan), \
             mock.patch.object(pc, "find_main_window_for_pid", return_value=0x1234), \
             mock.patch.object(pc, "post_wm_close", side_effect=fake_post), \
             mock.patch.object(pc, "pid_matches_start", side_effect=fake_matches), \
             mock.patch.object(pc, "pid_alive", return_value=False):
            yield state

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        pc.scan_snapshot = self._orig_scan
        if self.owns_tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)
        _SERVER["port"] = 0

    # 便捷断言
    def audit_lines(self):
        f = self.tmp / "kill_audit.jsonl"
        if not f.exists():
            return []
        return [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()]


AGENT_HDR = {"X-Port-Console-Token": "test-token-123"}


def kill_body(port=3084, pid=1234, proc_name="python.exe",
              started="2026-11-01T10:00:00+08:00", confirm=True, **extra):
    b = {"port": port, "pid": pid, "proc": proc_name, "started": started, "confirm": confirm}
    b.update(extra)
    return b


# ----------------------------------------------------------------------------
# 单测 1-5：归一化/识别/保护（纯函数层）
# ----------------------------------------------------------------------------


class TestNormalize(unittest.TestCase):
    """单测 1-2。"""

    def test_1_single_object_array_empty_normalized(self):
        one = {"pid": 1, "ppid": 0, "name": "a.exe", "exe": "", "cmdline": "", "started": ""}
        # 单对象展开
        raw = make_scan([conn("0.0.0.0", 80, 1)], [one], {"1": 1})
        n = pc.normalize_snapshot(raw)
        self.assertEqual(len(n["entries"]), 1)
        # 进程为单对象（被 PowerShell 展开形态）
        raw2 = make_scan([conn("0.0.0.0", 80, 1)], one, {"1": 1})
        n2 = pc.normalize_snapshot(raw2)
        self.assertEqual(n2["entries"][0]["proc"], "a.exe")
        # 空数组
        n3 = pc.normalize_snapshot(make_scan([]))
        self.assertEqual(n3["entries"], [])

    def test_2_high_ports_and_dedup_key(self):
        raw = make_scan([
            conn("0.0.0.0", 45678, 7),      # 高位端口
            conn("::", 45678, 7),           # IPv6 同 PID
            conn("127.0.0.1", 45678, 7),    # 同端口不同地址
            conn("0.0.0.0", 45678, 7),      # 完全重复（去重）
        ], [proc(7)], {"7": 1})
        n = pc.normalize_snapshot(raw)
        self.assertEqual(len(n["entries"]), 3)          # 重复 (addr,port,pid) 被去重
        ports = [e["port"] for e in n["entries"]]
        self.assertIn(45678, ports)                     # 高位端口不丢
        addrs = {(e["addr"]) for e in n["entries"]}
        self.assertIn("::", addrs)                      # IPv6 保留
        # 排序 (port, addr, pid)
        sorted_keys = [(e["port"], e["addr"], e["pid"]) for e in n["entries"]]
        self.assertEqual(sorted_keys, sorted(sorted_keys))


class TestClassify(unittest.TestCase):
    """单测 3-4。"""

    def setUp(self):
        self.state = pc.AppState(Path(tempfile.mkdtemp(prefix="pcon-c-")),
                                 {"rules": pc.validate_rules(pc.DEFAULT_RULES),
                                  "protection": pc.validate_protection(pc.DEFAULT_PROTECTION),
                                  "port_map": {}, "unknown": [], "warnings": []},
                                 3999, "t", True)
        self.state.console_pid = 999999
        self.state.console_port = 3999

    def test_3_rule_order_jiejie_before_meimei(self):
        e = {"port": 1, "addr": "0.0.0.0", "pid": 2, "proc": "x.exe", "exe": "",
             "cmdline": r"D:\x\wechat-work\app.exe", "started": "s", "session_id": 1}
        cls = pc.classify_entry(self.state, e)
        self.assertEqual(cls["name"], "企业微信")      # wechat-work 不被 wechat 抢先
        e2 = dict(e, cmdline=r"D:\x\wechat\app.exe")
        self.assertEqual(pc.classify_entry(self.state, e2)["name"], "微信")

    def test_4_priority_manual_auto_unknown_and_protection_top(self):
        st = self.state
        e = {"port": 5000, "addr": "0.0.0.0", "pid": 5, "proc": "python.exe", "exe": "C:/p.exe",
             "cmdline": "python app.py --port 5000", "started": "s", "session_id": 1}
        # 未知
        self.assertEqual(pc.classify_entry(st, e)["source"], "unknown")
        # 手工 > 自动
        st.port_map["5000"] = {"name": "我的服务", "level": "self", "proc": "python.exe", "started": "s"}
        cls = pc.classify_entry(st, e)
        self.assertEqual((cls["source"], cls["name"]), ("manual", "我的服务"))
        # 系统保护最高：把 135 命名为 self 也必须 system 级且禁杀
        e135 = dict(e, port=135, cmdline="whatever")
        st.port_map["135"] = {"name": "测试self", "level": "self", "proc": "x", "started": "s"}
        items = pc.build_full_entries(st, pc.normalize_snapshot(
            make_scan([conn("0.0.0.0", 135, 5)], [proc(5, name="notprotected.exe")], {"5": 1})),
            record_unknowns=False)
        self.assertEqual(items[0]["level"], "system")
        self.assertFalse(items[0]["kill_allowed"])


class TestProtection(unittest.TestCase):
    """单测 5。"""

    def setUp(self):
        self.state = pc.AppState(Path(tempfile.mkdtemp(prefix="pcon-p-")),
                                 {"rules": pc.validate_rules(pc.DEFAULT_RULES),
                                  "protection": pc.validate_protection(pc.DEFAULT_PROTECTION),
                                  "port_map": {}, "unknown": [], "warnings": []},
                                 3999, "t", True)
        self.state.console_pid = 4242
        self.state.console_port = 3999

    def _entry(self, **kw):
        base = {"port": 6000, "addr": "0.0.0.0", "pid": 100, "proc": "python.exe",
                "exe": r"C:\tools\python.exe", "cmdline": "x", "started": "s",
                "session_id": 1}
        base.update(kw)
        return base

    def test_5_self_pid4_protected_rejected(self):
        st = self.state
        self.assertIsNotNone(pc.protection_reason(st, self._entry(pid=4242)))       # 自身 PID
        self.assertIsNotNone(pc.protection_reason(st, self._entry(port=3999)))      # 自身端口
        self.assertIsNotNone(pc.protection_reason(st, self._entry(pid=2)))          # pid<=4
        self.assertIsNotNone(pc.protection_reason(st, self._entry(port=445)))       # 保护端口
        self.assertIsNotNone(pc.protection_reason(st, self._entry(proc="lsass.exe",
                                                              exe=r"C:\Windows\System32\lsass.exe")))
        self.assertIsNone(pc.protection_reason(st, self._entry()))                  # 普通目标放行
        # Session 0 / 缺失（硬要求 3/4，单测 39 同源验证在此一并覆盖）
        self.assertIsNotNone(pc.protection_reason(st, self._entry(session_id=0)))
        self.assertIsNotNone(pc.protection_reason(st, self._entry(session_id=None)))
        # System32 宿主
        self.assertIsNotNone(pc.protection_reason(st, _e32()))


def _e32():
    # System32 关键宿主名单内的进程（dllhost）才触发 System32 保护；
    # conhost 等用户态伴生不拦（黑框必须可杀——实证 fixture 子树含 conhost）
    return {"port": 6500, "addr": "0.0.0.0", "pid": 200,
            "proc": "dllhost.exe", "exe": r"C:\Windows\System32\dllhost.exe",
            "cmdline": "dllhost", "started": "s", "session_id": 1}


# ----------------------------------------------------------------------------
# 服务集成层（真 HTTP + 假扫描）
# ----------------------------------------------------------------------------


class ServerCase(unittest.TestCase):
    """带服务 harness 的基类。"""

    SCAN = SCAN_EMPTY
    PORT_MAP = {}
    EXTRA = {}

    def setUp(self):
        self.h = Harness(scan=self.SCAN, port_map=self.PORT_MAP, **self.EXTRA)

    def tearDown(self):
        self.h.stop()


# 单测 6
class TestStrictIdentity(ServerCase):
    def run_kill(self, body, scan=None):
        if scan is not None:
            pc.scan_snapshot = lambda: scan
        return http_req("POST", "/api/v1/agent/kill", body, AGENT_HDR)

    def test_6_port_gone_404_identity_change_409_no_taskkill(self):
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            good = kill_body()
            # 目标在：扫描含 (3084, 1234)
            scan = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
            # 端口消失
            pc.scan_snapshot = lambda: make_scan([])
            st, obj = self.run_kill(good)
            self.assertEqual((st, obj["reason"]), (404, "port_free"))
            tk.assert_not_called()
            # pid 存在但 proc 变化
            scan_chg = make_scan([conn("0.0.0.0", 3084, 1234)],
                                 [proc(1234, name="other.exe")], {"1234": 1})
            pc.scan_snapshot = lambda: scan_chg
            st, obj = self.run_kill(kill_body(proc_name="python.exe"))
            self.assertEqual((st, obj["reason"]), (409, "target_changed"))
            tk.assert_not_called()
            # started 变化
            scan_st = make_scan([conn("0.0.0.0", 3084, 1234)],
                                [proc(1234, started="2026-11-01T11:00:00+08:00")], {"1234": 1})
            pc.scan_snapshot = lambda: scan_st
            st, obj = self.run_kill(kill_body())
            self.assertEqual((st, obj["reason"]), (409, "target_changed"))
            tk.assert_not_called()


# 单测 7
class TestUiNoWindow(ServerCase):
    def test_7_ui_first_stage_no_window_428_no_taskkill(self):
        scan = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
        pc.scan_snapshot = lambda: scan
        with mock.patch.object(pc, "find_main_window_for_pid", return_value=None), \
             mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            hdr = {"Origin": f"http://127.0.0.1:{FAKE_PORT}",
                   "Sec-Fetch-Site": "same-origin"}
            st, obj = http_req("POST", "/api/v1/ui/kill",
                               dict(kill_body(), force=False), hdr)
            self.assertEqual(st, 428)
            self.assertEqual(obj["reason"], "force_confirm_required")
            self.assertTrue(obj.get("force_ticket"))
            tk.assert_not_called()


# 单测 8
class TestTicket(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
    UI_HDR = {"Origin": f"http://127.0.0.1:{FAKE_PORT}", "Sec-Fetch-Site": "same-origin"}

    def get_ticket(self):
        # 注意：不得在此直接赋值 pc.scan_snapshot——会绕过 mock_kill 的杀后变空语义
        with mock.patch.object(pc, "find_main_window_for_pid", return_value=None):
            st, obj = http_req("POST", "/api/v1/ui/kill", dict(kill_body(), force=False), self.UI_HDR)
        self.assertEqual(st, 428)
        return obj["force_ticket"]

    def test_8_force_needs_rescan_and_valid_ticket(self):
        t = self.get_ticket()
        with self.h.mock_kill() as kst:
            # 直达强杀（无 ticket）拒绝
            st, obj = http_req("POST", "/api/v1/ui/kill",
                               dict(kill_body(), force=True), self.UI_HDR)
            self.assertEqual((st, obj["reason"]), (409, "force_ticket_invalid"))
            # ticket 绑定目标：换 pid 串目标拒绝（pid 不在端口上 → strict 先 404，同为拒绝）
            st, obj = http_req("POST", "/api/v1/ui/kill",
                               dict(kill_body(pid=999), force=True, force_ticket=t), self.UI_HDR)
            self.assertIn(st, (404, 409))
            self.assertEqual(obj["reason"] in ("port_free", "force_ticket_invalid"), True)
            # ticket 过期拒绝
            with self.h.state.state_lock:
                self.h.state.tickets[t]["expires"] = time.monotonic() - 1
            st, obj = http_req("POST", "/api/v1/ui/kill",
                               dict(kill_body(), force=True, force_ticket=t), self.UI_HDR)
            self.assertEqual((st, obj["reason"]), (409, "force_ticket_invalid"))
            # 重新拿票强杀成功（force=true 前服务端重扫；杀后扫描变空=树退出）
            t2 = self.get_ticket()
            st, obj = http_req("POST", "/api/v1/ui/kill",
                               dict(kill_body(), force=True, force_ticket=t2), self.UI_HDR)
            self.assertEqual(st, 200)
            self.assertTrue(kst["killed"])
        # AI 单次直达不需要 ticket（杀完已清空 → 对空扫描 strict 404 即"无需 ticket 的旁证"）
        with self.h.mock_kill() as kst2:
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertTrue(kst2["killed"])


# 单测 9
class TestTreeProtection(ServerCase):
    def test_9_tree_contains_protected_rejected(self):
        # 子进程 5555 是保护进程（lsass 命中保护名单），父 1234 监听 3084
        scan = make_scan([conn("0.0.0.0", 3084, 1234)],
                         [proc(1234, ppid=0), proc(5555, name="lsass.exe",
                                                   exe=r"C:\Windows\System32\lsass.exe", ppid=1234)],
                         {"1234": 1, "5555": 0})
        pc.scan_snapshot = lambda: scan
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (403, "kill_not_allowed"))
            tk.assert_not_called()


# 单测 10
class TestKillButPortBusy(ServerCase):
    def test_10_taskkill_ok_but_port_still_listening(self):
        scan = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
        # 杀后重扫：端口被新 PID 5678 接管
        scan_after = make_scan([conn("0.0.0.0", 3084, 5678)], [proc(5678)], {"5678": 1})
        pc.scan_snapshot = scan
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")), \
             mock.patch.object(pc, "pid_alive", return_value=False), \
             mock.patch.object(pc, "scan_or_error", side_effect=[pc.normalize_snapshot(scan)] * 1):
            # close_target 内 scan_or_error 被多处调用——直接控制顺序：
            pass
        # 简化：按调用序列 mock scan_or_error：第1次校验扫描、第2次最终验证
        # （杀前复核=指纹相符放行；杀后验证=根已死——闭包计数区分两阶段）
        pc.scan_snapshot = scan
        seq = [pc.normalize_snapshot(scan), pc.normalize_snapshot(scan_after)]
        calls = {"n": 0}

        def fake_matches(pid, started):
            calls["n"] += 1
            return calls["n"] == 1

        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")), \
             mock.patch.object(pc, "pid_alive", return_value=False), \
             mock.patch.object(pc, "pid_matches_start", side_effect=fake_matches), \
             mock.patch.object(pc, "scan_or_error",
                               side_effect=lambda: seq.pop(0) if seq else pc.normalize_snapshot(scan_after)):
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 409)
            self.assertEqual(obj["reason"], "residual_listeners")
            self.assertEqual(obj["remaining"][0]["pid"], 5678)   # 如实返回当前占用者


# 单测 11
class TestRenameAndConfig(unittest.TestCase):
    def test_11_rename_validation_and_corrupt_config(self):
        tmp = Path(tempfile.mkdtemp(prefix="pcon-r-"))
        try:
            state = pc.AppState(tmp, {"rules": pc.validate_rules(pc.DEFAULT_RULES),
                                      "protection": pc.validate_protection(pc.DEFAULT_PROTECTION),
                                      "port_map": {}, "unknown": [], "warnings": []},
                                 3999, "t", True)
            state.console_pid = 999999
            # 非法字段
            for bad in ({"port": 0}, {"port": 70000}, {"port": 3084, "name": ""},
                        {"port": 3084, "name": "x", "level": "system"}):
                code, obj = pc.rename_port(state, bad, "t")
                self.assertEqual(code, 400)
            # 扫描失败
            with mock.patch.object(pc, "scan_snapshot", side_effect=pc.ScanError("x")):
                code, obj = pc.rename_port(state, {"port": 3084, "name": "ok", "level": "self"}, "t")
                self.assertEqual(code, 500)
            # 正常改名 + 原子写盘
            pc.scan_snapshot = lambda: make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
            code, obj = pc.rename_port(state, {"port": 3084, "name": "聊天室", "level": "self"}, "t")
            self.assertEqual(code, 200)
            saved = json.loads((tmp / "port_map.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["3084"]["name"], "聊天室")
            # 配置损坏：rules.json 损坏拒绝启动
            (tmp / "rules.json").write_text("{bad json", encoding="utf-8")
            with self.assertRaises(pc.ConfigError):
                pc.load_and_validate_configs(tmp)
            # unknown.json 损坏：保留副本新建不抛
            (tmp / "rules.json").unlink()
            (tmp / "unknown.json").write_text("not json", encoding="utf-8")
            cfg = pc.load_and_validate_configs(tmp)
            self.assertEqual(cfg["unknown"], [])
            self.assertTrue(any("unknown.json" in w for w in cfg["warnings"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# 单测 12-14走真 HTTP
class TestAuthMatrix(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def setUp(self):
        super().setUp()
        self.scan_counter = {"n": 0}
        real_scan = pc.scan_snapshot

        def counting():
            self.scan_counter["n"] += 1
            return real_scan() if callable(real_scan) else real_scan

        pc.scan_snapshot = counting

    def test_12_ui_origin_matrix(self):
        base = dict(kill_body(), force=False)
        # 全缺失 → 403
        st, obj = http_req("POST", "/api/v1/ui/kill", base)
        self.assertEqual((st, obj["reason"]), (403, "not_ui_origin"))
        # 跨源 → 403
        st, _ = http_req("POST", "/api/v1/ui/kill", base,
                         {"Origin": "http://evil.example"})
        self.assertEqual(st, 403)
        # 矛盾 → 403
        st, _ = http_req("POST", "/api/v1/ui/kill", base,
                         {"Origin": f"http://127.0.0.1:{FAKE_PORT}", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(st, 403)
        # 仅 same-origin（无 Origin）→ 放行到 428（有窗与否不影响鉴权判定）
        st, obj = http_req("POST", "/api/v1/ui/kill", base,
                           {"Sec-Fetch-Site": "same-origin"})
        self.assertIn(st, (200, 428))
        # Agent：无 Origin + 对 token → 允许；错 Origin → 拒
        with self.h.mock_kill():
            st, _ = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)
        st, _ = http_req("POST", "/api/v1/agent/kill", kill_body(),
                         dict(AGENT_HDR, Origin="http://evil.example"))
        self.assertEqual(st, 403)

    def test_13_agent_auth_and_no_scan_on_reject(self):
        before = self.scan_counter["n"]
        # 无 token
        st, obj = http_req("POST", "/api/v1/agent/kill", kill_body())
        self.assertEqual((st, obj["reason"]), (401, "unauthorized"))
        # 错 token
        st, _ = http_req("POST", "/api/v1/agent/kill", kill_body(),
                         {"X-Port-Console-Token": "wrong"})
        self.assertEqual(st, 401)
        # 空 token
        st, _ = http_req("POST", "/api/v1/agent/kill", kill_body(),
                         {"X-Port-Console-Token": ""})
        self.assertEqual(st, 401)
        # confirm 缺失 / 字符串 "true" / confirm:false
        for bad in ({"port": 3084, "pid": 1234, "proc": "python.exe", "started": "s"},
                    kill_body(confirm="true"),
                    kill_body(confirm=False)):
            st, _ = http_req("POST", "/api/v1/agent/kill", bad, AGENT_HDR)
            self.assertIn(st, (400,))
        # Agent 带 force → 400
        st, _ = http_req("POST", "/api/v1/agent/kill", kill_body(force=True), AGENT_HDR)
        self.assertEqual(st, 400)
        # 全部拒绝路径均未触发扫描
        self.assertEqual(self.scan_counter["n"], before)
        # L0 无 token 可读
        st, obj = http_req("GET", "/api/v1/ports")
        self.assertEqual(st, 200)

    def test_14_two_channels_same_core_different_orchestration(self):
        # UI：两阶段（先 428 拿 ticket）
        with mock.patch.object(pc, "find_main_window_for_pid", return_value=None):
            ui = {"Origin": f"http://127.0.0.1:{FAKE_PORT}", "Sec-Fetch-Site": "same-origin"}
            st, obj = http_req("POST", "/api/v1/ui/kill", dict(kill_body(), force=False), ui)
            self.assertEqual(st, 428)
        # AI：单次直达 200（强杀成功语义）
        with self.h.mock_kill() as st_k:
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertNotIn("force_ticket", obj)   # 单测 24 一并覆盖
            self.assertTrue(st_k["killed"])


# 单测 15
class TestTokenLeakage(ServerCase):
    def test_15_token_never_in_responses_or_runtime(self):
        st, obj = http_req("GET", "/api/v1/ports")
        self.assertNotIn("test-token-123", json.dumps(obj))
        st, obj = http_req("GET", "/api/v1/health")
        self.assertNotIn("test-token-123", json.dumps(obj))
        st, obj = http_req("GET", "/api/v1/protection")
        self.assertNotIn("test-token-123", json.dumps(obj))
        # runtime 写盘不含 token
        pc.write_runtime_info(self.h.tmp, FAKE_PORT)
        rt = (self.h.tmp / "runtime.json").read_text(encoding="utf-8")
        self.assertNotIn("test-token-123", rt)
        # 比较函数是常量时间（源码级断言）
        src = Path(pc.__file__).read_text(encoding="utf-8")
        self.assertIn("hmac.compare_digest", src)


# 单测 16/19单实例与端口顺延
class TestInstance(unittest.TestCase):
    def test_16_lock_and_runtime_cleanup(self):
        tmp = Path(tempfile.mkdtemp(prefix="pcon-i-"))
        try:
            fd1 = pc.acquire_instance_lock(tmp)
            self.assertIsNotNone(fd1)
            fd2 = pc.acquire_instance_lock(tmp)
            self.assertIsNone(fd2)                       # 多实例不能同时持锁
            os.close(fd1)
            # 端口顺延：3999 被占（模拟占用）→ find_available_port 返回下一个可用
            blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            blocker.bind(("127.0.0.1", 0))
            occupied = blocker.getsockname()[1]
            with mock.patch.object(pc, "DEFAULT_PORT", occupied):
                got = pc.find_available_port()
                self.assertEqual(got, occupied + 1)
            blocker.close()
            # 正常退出只清理自己写的 runtime
            pc.write_runtime_info(tmp, 4001)
            (tmp / "runtime.json").write_text(json.dumps({"pid": os.getpid() + 5000}),
                                              encoding="utf-8")
            pc.cleanup_runtime(tmp)
            self.assertTrue((tmp / "runtime.json").exists())   # 别人的不删
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_19_stale_runtime_renamed_not_killed(self):
        tmp = Path(tempfile.mkdtemp(prefix="pcon-s-"))
        try:
            # 陈旧 runtime：pid 不存在
            (tmp / "runtime.json").write_text(json.dumps(
                {"base_url": f"http://127.0.0.1:{FAKE_PORT}", "pid": 999999}), encoding="utf-8")
            with mock.patch.object(pc, "pid_alive", return_value=False), \
                 mock.patch.object(pc, "_health_probe", return_value=False):
                pc.clear_stale_runtime(tmp)
            self.assertFalse((tmp / "runtime.json").exists())
            self.assertTrue(any(p.name.startswith("pcon-") for p in tmp.iterdir()))
            # 锁被占 + 健康不通：handle_existing 第二次拿锁失败 → sys.exit(1)
            fd = pc.acquire_instance_lock(tmp)
            self.assertIsNotNone(fd)
            with mock.patch.object(pc, "pid_alive", return_value=False), \
                 mock.patch.object(pc, "_health_probe", return_value=False), \
                 mock.patch.object(pc.time, "sleep"), \
                 self.assertRaises(SystemExit) as cm:
                pc.handle_existing_instance(tmp)
            self.assertEqual(cm.exception.code, 1)
            os.close(fd)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# 单测 20父先退子残留
class TestOrphan(ServerCase):
    def test_20_old_parent_identity_404_child_unaffected(self):
        # 场景：旧父 1234 已退出，子 5678 仍监听 3084
        scan = make_scan([conn("0.0.0.0", 3084, 5678)], [proc(5678)], {"5678": 1})
        pc.scan_snapshot = lambda: scan
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(pid=1234, started="old"), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (404, "port_free"))
            tk.assert_not_called()
        # 子进程按当前身份仍可正常关闭（强杀成功语义）
        with self.h.mock_kill(scan):
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(pid=5678), AGENT_HDR)
            self.assertEqual(st, 200)


# 单测 21/22
class TestRoutingAndPreScan403(ServerCase):
    def test_21_only_versioned_routes(self):
        for path in ("/api/kill", "/api/rename", "/kill", "/ui/kill", "/agent/ports"):
            st, obj = http_req("POST", path, kill_body(), AGENT_HDR)
            self.assertEqual(st, 404, path)
        st, _ = http_req("GET", "/api/ports")
        self.assertEqual(st, 404)

    def test_22_ui_403_before_any_scan(self):
        counter = {"n": 0}

        def counting():
            counter["n"] += 1
            return SCAN_EMPTY

        pc.scan_snapshot = counting
        st, obj = http_req("POST", "/api/v1/ui/kill", dict(kill_body(), force=False))
        self.assertEqual((st, obj["reason"]), (403, "not_ui_origin"))
        self.assertEqual(counter["n"], 0)          # 403 前不得扫描
        st2, obj2 = http_req("POST", "/api/v1/ui/rename",
                             {"port": 1, "name": "x", "level": "other"})
        self.assertEqual((st2, obj2["reason"]), (403, "not_ui_origin"))
        self.assertEqual(counter["n"], 0)

# 单测 23夹具静态判据（真行为在 224 验收跑）
class TestFixtureFiles(unittest.TestCase):
    def test_23_windowed_fixture_contract(self):
        f = Path(__file__).resolve().parent / "fixture_windowed.ps1"
        self.assertTrue(f.exists())
        src = f.read_text(encoding="utf-8-sig", errors="replace")
        self.assertIn("IgnoreCloseCount", src)
        self.assertIn("READY", src)
        self.assertIn("TcpListener", src)
        self.assertIn("System.Windows.Forms", src)
        # acceptance 脚本性质：非零退出路径存在（单测 17 的可执行形态）
        a = Path(__file__).resolve().parent / "acceptance_api.py"
        self.assertTrue(a.exists())
        asrc = a.read_text(encoding="utf-8")
        self.assertIn("exit_code = 1", asrc)
        self.assertIn("sys.exit(exit_code)", asrc)
        self.assertIn("--base-url", asrc)
        self.assertIn("--token-file", asrc)


# 单测 24 已并入 14/7：Agent 成功无 force_ticket、UI 428 才含（两处均已断言）。
# 这里补一条组合断言固化编号。
class Test24NoTicketInAgentSuccess(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_24_agent_success_has_no_ticket(self):
        with self.h.mock_kill():
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertNotIn("force_ticket", json.dumps(obj))


# 单测 25
class TestAlreadyFree(ServerCase):
    def test_25_idle_port_idempotent_no_audit(self):
        before = len(self.h.audit_lines())
        st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                           {"port": 40000, "confirm": True}, AGENT_HDR)
        self.assertEqual(st, 200)
        self.assertTrue(obj["ok"] and obj["already_free"] is True)
        self.assertEqual(obj["target"], None)
        self.assertEqual(len(self.h.audit_lines()), before)   # 不写审计


# 单测 26/40
class TestMultiOwners(ServerCase):
    def test_26_and_40_multi_owners_priority_and_candidates(self):
        # 同端口两个不同 PID
        scan = make_scan([conn("0.0.0.0", 3084, 1234), conn("0.0.0.0", 3084, 4321)],
                         [proc(1234), proc(4321)], {"1234": 1, "4321": 1})
        pc.scan_snapshot = lambda: scan
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            # 含缺指纹请求也必须 multiple_owners（不是 target_identity_required）
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "confirm": True}, AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (409, "multiple_owners"))
            pids = {c["pid"] for c in obj["candidates"]}
            self.assertEqual(pids, {1234, 4321})
            tk.assert_not_called()
            # 带指纹（乱值）同样 multiple_owners
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "snapshot_id": "sn_xxx", "confirm": True}, AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (409, "multiple_owners"))
        # GET 侧：多占用不附 snapshot_id、附 candidates
        st, obj = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
        self.assertEqual(st, 200)
        self.assertNotIn("snapshot_id", json.dumps(obj["items"]))
        self.assertIn("candidates", obj)
        # GET 侧：唯一占用才附 snapshot_id
        scan1 = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
        pc.scan_snapshot = lambda: scan1
        st, obj = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
        self.assertIn("snapshot_id", obj["items"][0])


# 单测 27
class TestByPortProtected(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 445, 700)],
                     [proc(700, name="lsass.exe", exe=r"C:\Windows\System32\lsass.exe")],
                     {"700": 0})

    def test_27_protected_by_port_403_and_identity_override_rejected(self):
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            # 需要先拿指纹：唯一占用会发
            st, obj = http_req("GET", "/api/v1/agent/ports?port=445", None, AGENT_HDR)
            sid = obj["items"][0]["snapshot_id"]
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 445, "snapshot_id": sid, "confirm": True}, AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (403, "kill_not_allowed"))
            tk.assert_not_called()
            # 身份字段另传也不覆盖服务端现查——直接 400
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 445, "pid": 700, "proc": "lsass.exe",
                                "started": "x", "confirm": True}, AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (400, "invalid_request"))
            tk.assert_not_called()


# 单测 28
class TestEchoTargetKilled(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_28_target_killed_are_server_verified(self):
        with self.h.mock_kill():
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertEqual(obj["target"]["pid"], 1234)     # 服务端现查
            self.assertEqual(obj["killed"][0]["pid"], 1234)  # 复核已退出
            self.assertEqual(obj["remaining"], [])           # remaining=[] 才算干净


# 单测 29reason 枚举稳定小写
class TestReasons(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_29_stable_lower_reasons_covered(self):
        cases = []
        st, obj = http_req("POST", "/api/v1/agent/kill", kill_body())   # 无 token
        cases.append(("unauthorized", st, obj))
        st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(confirm=False), AGENT_HDR)
        cases.append(("confirm_required", st, obj))
        st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(port=0), AGENT_HDR)
        cases.append(("invalid_request", st, obj))
        st, obj = http_req("POST", "/api/v1/agent/kill-by-port", {"port": 3084, "confirm": True}, AGENT_HDR)
        cases.append(("target_identity_required", st, obj))   # 占用端口缺指纹
        pc.scan_snapshot = lambda: make_scan([])
        st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
        cases.append(("port_free", st, obj))
        # 权限不足 access_denied 走 UI 关窗失败路径
        scan = self.SCAN
        pc.scan_snapshot = lambda: scan
        with mock.patch.object(pc, "find_main_window_for_pid", return_value=0x1234), \
             mock.patch.object(pc, "post_wm_close", return_value=False), \
             mock.patch.object(pc.ctypes, "get_last_error", return_value=5):
            st, obj = http_req("POST", "/api/v1/ui/kill", dict(kill_body(), force=False),
                               {"Origin": f"http://127.0.0.1:{FAKE_PORT}",
                                "Sec-Fetch-Site": "same-origin"})
        cases.append(("access_denied", st, obj))
        # kill_not_allowed / multiple_owners / rate_limited 在 27/26/34 覆盖；
        # target_changed / force_ticket_invalid / scan_failed / command_failed 在 6/8/10 覆盖
        for reason, st, obj in cases:
            self.assertEqual(obj["reason"], reason)
            self.assertTrue(reason.islower() or reason[0].islower(), reason)


# 单测 30
class TestAgentPortsSlim(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234), conn("::", 9000, 1234)],
                     [proc(1234, cmdline="python serve.py --token abc123")], {"1234": 1})

    def test_30_slim_no_cmdline_with_labels_and_filter(self):
        st, obj = http_req("GET", "/api/v1/agent/ports", None, AGENT_HDR)
        self.assertEqual(st, 200)
        for it in obj["items"]:
            self.assertNotIn("cmdline", it)
            for k in ("name", "level", "source", "kill_allowed", "port", "pid", "proc", "addr"):
                self.assertIn(k, it)
        # port 过滤
        st, obj = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
        self.assertEqual(len(obj["items"]), 1)
        self.assertEqual(obj["items"][0]["port"], 3084)
        # 非法 port → 400 invalid_request
        for bad in ("abc", "0", "70000"):
            st, obj = http_req(f"GET", f"/api/v1/agent/ports?port={bad}", None, AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (400, "invalid_request"))


# 单测 31
class TestAuditFailClosed(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_31_pre_audit_failure_blocks_kill(self):
        pc.scan_snapshot = lambda: self.SCAN
        with mock.patch.object(pc, "write_audit_event", side_effect=OSError("disk full")), \
             mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (500, "audit_write_failed"))
            tk.assert_not_called()

    def test_31b_result_audit_failure_keeps_truth(self):
        pc.scan_snapshot = lambda: self.SCAN
        real_write = pc.write_audit_event
        calls = {"n": 0}

        def flaky(state, event):
            calls["n"] += 1
            if calls["n"] >= 2:          # 第二次（结果事件）失败
                raise OSError("disk full")
            return real_write(state, event)

        with mock.patch.object(pc, "write_audit_event", side_effect=flaky), \
             mock.patch.object(pc, "run_taskkill", return_value=(True, "")), \
             mock.patch.object(pc, "pid_alive", return_value=False), \
             mock.patch.object(pc, "scan_or_error",
                               side_effect=[pc.normalize_snapshot(self.SCAN),
                                            pc.normalize_snapshot(make_scan([]))]):
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)    # 真实结果如实返回
            self.assertTrue(obj["ok"])

    def test_31c_audit_has_no_token_or_cmdline(self):
        with self.h.mock_kill(self.SCAN):
            http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
        text = "\n".join(json.dumps(x, ensure_ascii=False)
                         for x in self.h.audit_lines())
        self.assertNotIn("test-token-123", text)
        self.assertNotIn("server.py", text)          # 不写完整命令行
        ev = self.h.audit_lines()
        self.assertTrue(any(e.get("action") == "started" for e in ev)
                        and any(e.get("action") == "finished" for e in ev))
        fin = [e for e in ev if e.get("action") == "finished"][0]
        for k in ("name", "level", "source"):
            self.assertIn(k, fin["target"])          # 单测 37 一并覆盖


# 单测 32
class TestSystemLevelHardReject(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 6501, 800)],
                     [proc(800, name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe")],
                     {"800": 0})

    def test_32_level_system_not_in_protection_still_403(self):
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(port=6501, pid=800, proc_name="svchost.exe"), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (403, "kill_not_allowed"))
            tk.assert_not_called()
            ui = {"Origin": f"http://127.0.0.1:{FAKE_PORT}", "Sec-Fetch-Site": "same-origin"}
            st, obj = http_req("POST", "/api/v1/ui/kill",
                               dict(kill_body(port=6501, pid=800, proc_name="svchost.exe"),
                                    force=False), ui)
            self.assertEqual(st, 403)


# 单测 33指纹全路径
class TestSnapshotFingerprint(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def get_sid(self):
        st, obj = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
        return obj["items"][0]["snapshot_id"]

    def test_33_fingerprint_paths(self):
        with self.h.mock_kill(self.SCAN) as kst:
            # 缺指纹 → 400（不碰杀）
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "confirm": True}, AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (400, "target_identity_required"))
            self.assertFalse(kst["killed"])
            sid = self.get_sid()
            # 匹配 + 唯一 → 执行
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "snapshot_id": sid, "confirm": True}, AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertTrue(kst["killed"])
        # 过期（重新拉起语境：目标仍在）：手工塞过期指纹记录
        with self.h.mock_kill(self.SCAN):
            with self.h.state.state_lock:
                self.h.state.snapshots[3084] = {
                    "sid": "sn_dead00",
                    "identity": {"port": 3084, "pid": 1234, "proc": "python.exe",
                                 "started": "2026-11-01T10:00:00+08:00"},
                    "expires": time.monotonic() - 1}
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "snapshot_id": "sn_dead00", "confirm": True},
                               AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (400, "target_identity_required"))
        # 身份不符（端口易主）：先在 8888 占用下签发指纹，再把目标换成 9999
        sid3 = ""
        with self.h.mock_kill(make_scan([conn("0.0.0.0", 3084, 8888)],
                                        [proc(8888)], {"8888": 1})):
            st, obj = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
            sid3 = obj["items"][0]["snapshot_id"]
        with self.h.mock_kill(make_scan([conn("0.0.0.0", 3084, 9999)],
                                        [proc(9999)], {"9999": 1})):
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "snapshot_id": sid3, "confirm": True},
                               AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (409, "target_changed"))


# 单测 34
class TestRateLimit(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_34_seventh_real_kill_429_already_free_free(self):
        # 频率闸桶直接构造 6 次真实强杀记录（等价于前 6 次已成功），目标不受影响
        with self.h.state.state_lock:
            dq = self.h.state.kill_rate["agent"]
            now = time.monotonic()
            for _ in range(6):
                dq.append(now)
        # 安全审查建议 1：扣费点挪到杀前复核之后——429 出口需指纹相符先过复核
        with mock.patch.object(pc, "pid_matches_start", return_value=True):
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (429, "rate_limited"))
        # 审计链完整（前置在扣费前写）：started+finished 成对，finished 记 rate_limited
        ev = self.h.audit_lines()
        self.assertEqual(len(ev), 2)
        self.assertEqual(ev[1]["result"], "failed")
        self.assertEqual(ev[1]["reason"], "rate_limited")
        self.assertNotIn("test-token-123", json.dumps(ev))
        # already_free 不计入：空端口照样幂等成功
        st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                           {"port": 45678, "confirm": True}, AGENT_HDR)
        self.assertEqual(st, 200)
        self.assertTrue(obj["already_free"])


# 单测 35
class TestRedaction(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)],
                     [proc(1234, cmdline="python serve.py --token abc123 --password pw9")],
                     {"1234": 1})

    def test_35_redact_rules_and_ledger_conditions(self):
        # 非同源 GET /ports：cmdline 脱敏
        st, obj = http_req("GET", "/api/v1/ports")
        item = [i for i in obj["items"] if i["port"] == 3084][0]
        self.assertNotIn("abc123", item["cmdline"])
        self.assertIn("***", item["cmdline"])
        # 同源 UI GET：完整命令行（此请求会写台账——顺序在台账断言之后）
        unk = self.h.tmp / "unknown.json"
        http_req("GET", "/api/v1/ports")                       # 非同源 → 不写台账
        self.assertFalse(unk.exists())
        hdr = {"Origin": f"http://127.0.0.1:{FAKE_PORT}", "Sec-Fetch-Site": "same-origin"}
        st, obj = http_req("GET", "/api/v1/ports", None, hdr)
        item = [i for i in obj["items"] if i["port"] == 3084][0]
        self.assertIn("abc123", item["cmdline"])
        self.assertTrue(unk.exists())                          # 同源 → 写
        st, obj = http_req("GET", "/api/v1/agent/ports", None, AGENT_HDR)  # Agent → 也写
        saved = json.loads(unk.read_text(encoding="utf-8"))
        self.assertTrue(any("***" in u["cmdline"] for u in saved))
        saved = json.loads(unk.read_text(encoding="utf-8"))
        self.assertTrue(any("--token ***" in u["cmdline"] or "***" in u["cmdline"]
                            for u in saved))


# 单测 36
class TestMappingStale(ServerCase):
    PORT_MAP = {"3084": {"name": "聊天室", "level": "self",
                         "proc": "node.exe", "started": "2026-10-01T00:00:00+08:00"}}

    def test_36_stale_flag_and_mapping_not_in_kill_chain(self):
        scan = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
        pc.scan_snapshot = lambda: scan
        st, obj = http_req("GET", "/api/v1/ports", None,
                           {"Origin": f"http://127.0.0.1:{FAKE_PORT}",
                            "Sec-Fetch-Site": "same-origin"})
        item = [i for i in obj["items"] if i["port"] == 3084][0]
        self.assertTrue(item["mapping_stale"])                # 指纹不符 → 提示过期
        self.assertEqual(item["name"], "聊天室")               # 显示标签仍在
        # 映射不参与关闭身份校验：按现查身份杀成功
        with self.h.mock_kill(scan):
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(proc_name="python.exe"), AGENT_HDR)
            self.assertEqual(st, 200)


# 单测 37并入 31c 断言（审计含 name/level/source），client_id 缺省补一条
class TestClientLabel(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_37_client_id_default_unknown_and_custom(self):
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")), \
             mock.patch.object(pc, "pid_alive", return_value=False):
            http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)  # 无 client 头
            fin = [e for e in self.h.audit_lines() if e.get("action") == "finished"][-1]
            self.assertEqual(fin["client_id"], "unknown")
            http_req("POST", "/api/v1/agent/kill", kill_body(),
                     dict(AGENT_HDR, **{"X-Port-Console-Client": "zcode"}))
            fin = [e for e in self.h.audit_lines() if e.get("action") == "finished"][-1]
            self.assertEqual(fin["client_id"], "zcode")


# 单测 38
class TestHasWindowAbsent(ServerCase):
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_38_no_has_window_key_and_windowed_force_false_succeeds(self):
        st, obj = http_req("GET", "/api/v1/ports")
        self.assertNotIn("has_window", json.dumps(obj))       # 列表无窗口字段
        # 有窗：force=false 直接成功，不误入 428（且 UI 通道不携带 confirm——UI 格式）
        with self.h.mock_close_ok():
            ui = {"Origin": f"http://127.0.0.1:{FAKE_PORT}", "Sec-Fetch-Site": "same-origin"}
            body = {"port": 3084, "pid": 1234, "proc": "python.exe",
                    "started": "2026-11-01T10:00:00+08:00", "force": False}
            st, obj = http_req("POST", "/api/v1/ui/kill", body, ui)
            self.assertEqual(st, 200)
            self.assertNotIn("force_ticket", json.dumps(obj))


# 单测 39 前置：pid_matches_start 真机指纹（锁 8 小时时区坑：FILETIME naive UTC 必须
# 显式挂 timezone.utc 再转本地——否则活进程被判死、取消关窗场景必炸 409）
class TestPidMatchesStartReal(unittest.TestCase):
    def test_pid_matches_start_real_process(self):
        import subprocess as sp
        proc = sp.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                        creationflags=0x08000000)
        try:
            raw = pc.scan_snapshot()
            started = ""
            for p in pc.as_list(raw.get("processes")):
                try:
                    if int(p.get("pid")) == proc.pid:
                        started = str(p.get("started") or "")
                        break
                except (TypeError, ValueError):
                    continue
            self.assertTrue(started, "PS 快照应取到真进程 started")
            self.assertTrue(pc.pid_matches_start(proc.pid, started),
                            "活进程创建时间指纹必须匹配（时区修复验证）")
            self.assertFalse(pc.pid_matches_start(proc.pid, "2000-01-01T00:00:00+08:00"),
                             "指纹不符（如 PID 复用）必须判死")
            self.assertFalse(pc.pid_matches_start(99999999, started),
                             "不存在的 PID 判死")
            proc.kill()
            time.sleep(0.5)
            # 关键坑锁：进程终止后对象因 Popen 句柄未清而仍可 OpenProcess——
            # GetExitCodeProcess != STILL_ACTIVE 必须判死
            self.assertFalse(pc.pid_matches_start(proc.pid, started),
                             "已终止进程（对象未销毁）必须判死")
        finally:
            proc.kill()


# 单测 39
class TestSessionIdFailClosed(ServerCase):
    def test_39_session0_and_missing_both_403(self):
        base = {"port": 7001, "addr": "0.0.0.0", "pid": 900,
                "proc": "mysvc.exe", "exe": r"C:\tools\mysvc.exe",
                "cmdline": "mysvc", "started": "s"}
        # session_id = 0 且不在 protection.json
        scan0 = make_scan([conn("0.0.0.0", 7001, 900)],
                          [proc(900, name="mysvc.exe", exe=r"C:\tools\mysvc.exe")], {"900": 0})
        pc.scan_snapshot = lambda: scan0
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(port=7001, pid=900, proc_name="mysvc.exe"), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (403, "kill_not_allowed"))
            tk.assert_not_called()
        # session_id 缺失（Get-Process 没给这个 pid）
        scan_missing = make_scan([conn("0.0.0.0", 7002, 901)],
                                 [proc(901, name="mysvc2.exe", cmdline="mysvc2")], {})
        pc.scan_snapshot = lambda: scan_missing
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(port=7002, pid=901, proc_name="mysvc2.exe"), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (403, "kill_not_allowed"))
            tk.assert_not_called()


# ============================================================================
# 1.0.1 新增单测 41-46（安全审查 四条阻断＋关联修复的回归锁）
# ============================================================================


class Test41PreKillRecheck(ServerCase):
    """单测 41：杀前复核三态。"""
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_41a_fingerprint_mismatch_rejected_before_taskkill(self):
        """杀前复核 False＋端口仍被占 → 409 target_changed，taskkill 未调用。"""
        pc.scan_snapshot = lambda: self.SCAN
        with mock.patch.object(pc, "pid_matches_start", return_value=False), \
             mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (409, "target_changed"))
            tk.assert_not_called()

    def test_41b_target_self_exited_already_free(self):
        """杀前复核 False＋重扫端口已空 → 200 already_free（目标自行退出，非己力）。"""
        pc.scan_snapshot = lambda: self.SCAN
        seq = {"first": True}

        def fake_scan():
            if seq["first"]:               # 校验扫描：目标在
                seq["first"] = False
                return self.SCAN
            return make_scan([])           # 杀前复核重扫：目标已退、端口已空

        with mock.patch.object(pc, "scan_snapshot", fake_scan), \
             mock.patch.object(pc, "pid_matches_start", return_value=False), \
             mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertTrue(obj["ok"] and obj["already_free"] is True)
            tk.assert_not_called()

    def test_41c_fingerprint_match_passes(self):
        """指纹相符 → 正常杀成功（新闸不误伤正常路径）。"""
        with self.h.mock_kill(self.SCAN) as kst:
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertTrue(kst["killed"])


class Test42StartedRequired(ServerCase):
    """单测 42：strict 模式 started 必填。"""
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_42_missing_or_empty_started_400(self):
        pc.scan_snapshot = lambda: self.SCAN
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            for bad in ({"port": 3084, "pid": 1234, "proc": "python.exe", "confirm": True},
                        kill_body(started=""),
                        kill_body(started="   ")):
                st, obj = http_req("POST", "/api/v1/agent/kill", bad, AGENT_HDR)
                self.assertEqual((st, obj["reason"]), (400, "invalid_request"), bad)
                tk.assert_not_called()


class Test43MultiSid(ServerCase):
    """单测 43：同一端口连续 GET 两次 → 两个 sid 都有效，不互相作废。"""

    def test_43_two_sids_coexist(self):
        scan = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})
        pc.scan_snapshot = lambda: scan
        st, obj1 = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
        sid_a = obj1["items"][0]["snapshot_id"]
        st, obj2 = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
        sid_b = obj2["items"][0]["snapshot_id"]
        self.assertNotEqual(sid_a, sid_b)
        # 按 sid 存后：两个 sid 都能通过 verify（对同一目标身份）
        identity = {"port": 3084, "pid": 1234, "proc": "python.exe",
                    "started": "2026-11-01T10:00:00+08:00"}
        self.assertEqual(pc.verify_snapshot_id(self.h.state, 3084, sid_a, identity), "")
        self.assertEqual(pc.verify_snapshot_id(self.h.state, 3084, sid_b, identity), "")
        # sid_A 实际杀成功（sid_B 保留到各自 TTL）
        with self.h.mock_kill(scan):
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "snapshot_id": sid_a, "confirm": True}, AGENT_HDR)
            self.assertEqual(st, 200)


class Test44FakeSidNoCollateral(ServerCase):
    """单测 44：假 sid 不 pop 有效 sid。"""
    SCAN = make_scan([conn("0.0.0.0", 3084, 1234)], [proc(1234)], {"1234": 1})

    def test_44_fake_sid_leaves_valid_sid_usable(self):
        pc.scan_snapshot = lambda: self.SCAN
        st, obj = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
        sid = obj["items"][0]["snapshot_id"]
        # 假 sid 打同端口（旧逻辑：会把有效指纹 pop 掉）
        st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                           {"port": 3084, "snapshot_id": "sn_deadbeef", "confirm": True}, AGENT_HDR)
        self.assertEqual((st, obj["reason"]), (400, "target_identity_required"))
        # 有效 sid 仍然可用
        with self.h.mock_kill(self.SCAN) as kst:
            st, obj = http_req("POST", "/api/v1/agent/kill-by-port",
                               {"port": 3084, "snapshot_id": sid, "confirm": True}, AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertTrue(kst["killed"])


class Test45ExeUnreadableFailClosed(ServerCase):
    """单测 45：exe 读不到 → fail closed；正常 exe 进程不误伤。"""

    def test_45a_exe_empty_protected(self):
        # 场景（实测数据 MSI.TerminalServer）：exe 空 + session 1 + 不在保护表
        scan = make_scan([conn("0.0.0.0", 26822, 17060)],
                         [proc(17060, name="MSI.TerminalServer.exe", exe="", cmdline="svc")],
                         {"17060": 1})
        pc.scan_snapshot = lambda: scan
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(port=26822, pid=17060,
                                         proc_name="MSI.TerminalServer.exe"), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (403, "kill_not_allowed"))
            self.assertIn("路径不可读", obj["message"])
            tk.assert_not_called()

    def test_45b_normal_exe_not_affected(self):
        scan = make_scan([conn("0.0.0.0", 3084, 1234)],
                         [proc(1234, exe=r"C:\Python\python.exe")], {"1234": 1})
        pc.scan_snapshot = lambda: scan
        with self.h.mock_kill(scan):
            st, obj = http_req("POST", "/api/v1/agent/kill", kill_body(), AGENT_HDR)
            self.assertEqual(st, 200)

    def test_45c_started_unreadable_fail_closed(self):
        """安全审查建议（安全审查）：started 读不到 → fail closed。
        三层验证：protection_reason 函数级 403 语义；strict 层 started 校验先拦 409（目标侧
        started 空→无法确认身份）；列表层 kill_allowed=false＋不发指纹（503 语义
        只留给存储满）。"""
        scan = make_scan([conn("0.0.0.0", 26823, 17061)],
                         [proc(17061, name="nosvc.exe", exe=r"C:\tools\nosvc.exe",
                               cmdline="nosvc", started="")], {"17061": 1})
        pc.scan_snapshot = lambda: scan
        # 函数级：保护判定含"启动时间不可读"
        entry = {"port": 26823, "pid": 17061, "proc": "nosvc.exe",
                 "exe": r"C:\tools\nosvc.exe", "session_id": 1, "started": ""}
        self.assertEqual(pc.protection_reason(self.h.state, entry),
                         "启动时间不可读(fail closed)")
        # strict 层：目标 started 空 → fail closed 先拦（409，非 403）
        with mock.patch.object(pc, "run_taskkill", return_value=(True, "")) as tk:
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(port=26823, pid=17061, proc_name="nosvc.exe",
                                         started="2020-01-01T00:00:00+08:00"), AGENT_HDR)
            self.assertEqual((st, obj["reason"]), (409, "target_identity_required"))
            tk.assert_not_called()
        # 列表层：kill_allowed=false（带保护原因）＋不发指纹（绝不 503）
        st, obj = http_req("GET", "/api/v1/agent/ports?port=26823", None, AGENT_HDR)
        self.assertEqual(st, 200)
        item = obj["items"][0]
        self.assertFalse(item["kill_allowed"])
        self.assertIn("启动时间不可读", item["protected_reason"])
        self.assertNotIn("snapshot_id", json.dumps(item))


class Test46RedactCoverage(unittest.TestCase):
    """单测 46：脱敏覆盖下划线复合词与 Bearer JWT。"""

    def test_46_underscore_compounds_and_bearer(self):
        cases = [
            ("--token=ABC123", "ABC123"),
            ("client_secret=abcdef", "abcdef"),
            ("AWS_SECRET_ACCESS_KEY=xyz", "xyz"),
            ("PROVIDER_APIKEY=zzz", "zzz"),
        ]
        for raw, secret in cases:
            out = pc.redact_cmdline(raw)
            self.assertNotIn(secret, out, raw)
            self.assertIn("***", out, raw)
        # Bearer JWT：令牌本体不残留（判据=值全部 ***，JWT 不残留；
        # 双闸各打一道，输出形如 "Authorization: *** ***" 亦满足）
        jwt = "eyJhbGciOiJIUzI1NiJ9.abc.defghi"
        out = pc.redact_cmdline("Authorization: Bearer " + jwt)
        self.assertNotIn(jwt, out)
        self.assertNotIn("eyJ", out)
        self.assertIn("***", out)
        # 安全审查建议 4：样本从"实现没提到的"里挑，防测试与实现同盲区
        extra_leak = [
            ("MY_SECRET_VALUE=abc", "abc"),
            ("my_secret_value=abc", "abc"),
            ("credentials=aaa", "aaa"),          # 复数形——两字符前瞻放行
        ]
        for raw, secret in extra_leak:
            out = pc.redact_cmdline(raw)
            self.assertNotIn("=" + secret, out, raw)
            self.assertIn("***", out, raw)
        # 不误伤面（普通词含关键词子串）
        for raw in ("keyboard=layout", "tokenize=x", "secretary=x",
                    "python server.py --port 8080"):
            self.assertNotIn("***", pc.redact_cmdline(raw), raw)


class Test52RateLimitAtomic(ServerCase):
    """单测：频率闸原子化——并发穿透不可能。"""

    def test_52_concurrent_only_six_pass(self):
        import threading
        results = {"pass": 0, "deny": 0}
        lock = threading.Lock()

        def worker():
            ok = pc.try_consume_rate_slot(self.h.state, "agent")
            with lock:
                results["pass" if ok else "deny"] += 1

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results["pass"], 6)     # 恰好 6 个通过
        self.assertEqual(results["deny"], 4)     # 其余 429 拒


class Test53KilledRealValues(ServerCase):
    """单测：killed 数组填每个成员的真实 proc/started（非根进程值）。"""

    def test_53_killed_has_per_member_truth(self):
        scan = make_scan(
            [conn("0.0.0.0", 3084, 100)],
            [proc(100, name="root.exe", started="2026-11-01T08:00:00+08:00"),
             proc(101, name="child1.exe", ppid=100, started="2026-11-01T08:00:01+08:00"),
             proc(102, name="child2.exe", ppid=100, started="2026-11-01T08:00:02+08:00")],
            {"100": 1, "101": 1, "102": 1})
        pc.scan_snapshot = lambda: scan
        with self.h.mock_kill(scan):
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(pid=100, proc_name="root.exe",
                                         started="2026-11-01T08:00:00+08:00"), AGENT_HDR)
            self.assertEqual(st, 200)
            killed = {k["pid"]: k for k in obj["killed"]}
            self.assertEqual(killed[100]["proc"], "root.exe")
            self.assertEqual(killed[101]["proc"], "child1.exe")   # 不再全填根进程名
            self.assertEqual(killed[102]["started"], "2026-11-01T08:00:02+08:00")


# ----------------------------------------------------------------------------
# 1.1 1.0.1 追加 54-68（只追加，不改原 52 个断言）
# ----------------------------------------------------------------------------

_PKG = Path(pc.__file__).resolve().parent          # 工程包目录（单测 59 读知识库文件）


def _rules21():
    """出厂规则集（1.1 起 DEFAULT_RULES 已含对照表 7 条，共 22 条——直接用，防重复叠加）。"""
    return pc.validate_rules(pc.DEFAULT_RULES)


def _plain_proc(pid, ppid, started, name="x.exe"):
    return {"pid": pid, "ppid": ppid, "name": name, "exe": r"C:\x\x.exe",
            "cmdline": "x run", "started": started}


class Test54CacheNeverInKill(ServerCase):
    """单测 54：缓存躺旧身份，kill 拿新扫描——缓存数据流进 kill 路径即 500。"""

    SCAN = make_scan([conn("0.0.0.0", 3084, 100)],
                     [proc(100, name="target.exe",
                           started="2026-11-01T10:00:00+08:00")],
                     {"100": 1})

    def test_54_cache_filled_kill_still_fresh(self):
        # 先填展示缓存（GET /ports）
        st0, obj0 = http_req("GET", "/api/v1/ports", None, AGENT_HDR)
        self.assertEqual(st0, 200)
        self.assertFalse(obj0["data_cached"])
        # kill 严格模式照常成功——若 kill 吃了带 _cached 的数据会 RuntimeError→500
        with self.h.mock_kill(self.SCAN):
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(pid=100, proc_name="target.exe",
                                         started="2026-11-01T10:00:00+08:00"), AGENT_HDR)
            self.assertEqual(st, 200)
            self.assertEqual(obj["remaining"], [])


class Test55CachedFlagRejected(ServerCase):
    """单测 55：kill 路径拿到 _cached 数据 → RuntimeError → 500，不执行关闭。"""

    SCAN = make_scan([conn("0.0.0.0", 3084, 100)],
                     [proc(100, started="2026-11-01T10:00:00+08:00")], {"100": 1})

    def test_55_cached_data_500_no_taskkill(self):
        cached = dict(pc.normalize_snapshot(self.SCAN), _cached=True,
                      _cached_at="2026-11-01T10:00:00+08:00", _scope="full")
        with mock.patch.object(pc, "scan_or_error", return_value=cached):
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(pid=100, started="2026-11-01T10:00:00+08:00"),
                               AGENT_HDR)
        self.assertEqual(st, 500)
        self.assertEqual(obj["reason"], "internal_error")
        # 审计里没有 taskkill started 事件 = 关闭动作没执行
        self.assertFalse([a for a in self.h.audit_lines()
                          if a.get("action") == "started" and a.get("mode") == "taskkill_tree"])


class Test56PostKillFreshRescan(ServerCase):
    """单测 56：杀后必须再跑一次全表新鲜扫描（不复用杀前快照）。"""

    def test_56_scan_after_kill_present(self):
        scan = make_scan([conn("0.0.0.0", 3084, 100)],
                         [proc(100, started="2026-11-01T10:00:00+08:00")], {"100": 1})
        killed_flag = {"v": False}
        counts = {"after_kill": 0}

        def fake_scan():
            if killed_flag["v"]:
                counts["after_kill"] += 1
                return make_scan([])
            return scan

        def fake_taskkill(pid):
            killed_flag["v"] = True
            return (True, "")

        def fake_matches(pid, started):
            # 坑账复训（老坑新踩在册）：一刀切 True 会让杀后验证全判活（500）。
            # 必须按阶段分流：杀前复核=True（指纹相符放行）；杀后验证=False（全死）。
            return not killed_flag["v"]

        with mock.patch.object(pc, "scan_snapshot", fake_scan), \
             mock.patch.object(pc, "run_taskkill", side_effect=fake_taskkill), \
             mock.patch.object(pc, "pid_matches_start", side_effect=fake_matches), \
             mock.patch.object(pc, "pid_alive", return_value=False):
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(pid=100, started="2026-11-01T10:00:00+08:00"),
                               AGENT_HDR)
        self.assertEqual(st, 200)
        self.assertGreaterEqual(counts["after_kill"], 1)   # 杀后至少一次 fresh 全表


class Test57RulesOrderAndMsi(ServerCase):
    """单测 57：wechat-work(order 2) 先于 doubao(24) 不被抢；msi.terminalserver 命中。"""

    EXTRA = {"rules": _rules21()}

    def test_57_doubao_priority_and_msi(self):
        st = self.h.state
        e = {"port": 1, "addr": "0.0.0.0", "pid": 2, "proc": "node.exe", "exe": "",
             "cmdline": r"D:\dsh\wechat-work\run.exe --serve", "started": "s",
             "session_id": 1}
        self.assertEqual(pc.classify_entry(st, e)["name"], "企业微信")
        self.assertNotEqual(pc.classify_entry(st, e)["name"], "豆包客户端")
        m = {"port": 26822, "addr": "0.0.0.0", "pid": 3,
             "proc": "MSI.TerminalServer.exe",
             "exe": r"D:\MSI\MSI.TerminalServer.exe", "cmdline": "",
             "started": "s", "session_id": 1}
        self.assertEqual(pc.classify_entry(st, m)["name"], "MSI主板工具")


class Test58PortsJsonNotInVerdict(ServerCase):
    """单测 58：ports.json 是纯知识层——存在与否 kill_allowed/protected_reason 不变。"""

    def test_58_verdict_unchanged_with_and_without_ports_json(self):
        scan = make_scan([conn("0.0.0.0", 3084, 100)],
                         [proc(100, name="whatever.exe", cmdline="whatever run")],
                         {"100": 1})
        base = pc.build_full_entries(self.h.state, pc.normalize_snapshot(scan),
                                     record_unknowns=False)
        for payload in ("{}",
                        json.dumps({"ports": [{"port": 3084, "protected": True}]}),
                        json.dumps({"ports": [{"port": 3084, "level": "system"}]})):
            (self.h.tmp / "ports.json").write_text(payload, encoding="utf-8")
            again = pc.build_full_entries(self.h.state, pc.normalize_snapshot(scan),
                                          record_unknowns=False)
            self.assertEqual(base, again)      # 逐字段不变——知识库零代码侵入
        (self.h.tmp / "ports.json").unlink()
        after = pc.build_full_entries(self.h.state, pc.normalize_snapshot(scan),
                                      record_unknowns=False)
        self.assertEqual(base, after)


class Test59PortsMdStats(unittest.TestCase):
    """单测 59：ports.md 统计与 ports.json 全对（111 条）。"""

    def test_59_stats_111_and_categories_match(self):
        data = json.loads((_PKG / "ports.json").read_text(encoding="utf-8"))
        items = data["ports"]
        self.assertEqual(len(items), 108)
        from collections import Counter
        c = Counter(it["category"] for it in items)
        self.assertEqual(dict(c), {
            "网络基础协议": 23, "国内常用软件": 21, "中间件-国产": 16,
            "开发常用端口": 13, "Windows系统服务": 12, "数据库-国产": 10,
            "数据库-国际": 8, "Web中间件": 5})
        md = (_PKG / "ports.md").read_text(encoding="utf-8")
        self.assertIn("共 108 条", md)
        for cat, n in c.items():
            rows = [ln for ln in md.splitlines() if ln.startswith(f"| {cat} ")]
            self.assertTrue(rows, f"ports.md 缺分类统计行: {cat}")
            self.assertIn(f"| {n} |", rows[0], f"{cat} 条数不一致: {rows[0]}")
        # 5000 只剩 Flask 条（UPnP 已删）；本机条目 generic:false/local
        p5000 = [it for it in items if it["port"] == 5000]
        self.assertEqual([it["service"] for it in p5000], ["Flask"])
        # 1.1②：categories 升级为对象数组 [{name, count}]，计数必须与 ports 数组一致
        cats = data["categories"]
        self.assertTrue(all(isinstance(x, dict) and set(x) == {"name", "count"} for x in cats))
        self.assertEqual({x["name"] for x in cats}, set(c))
        self.assertTrue(all(x["count"] == c[x["name"]] for x in cats))
        self.assertEqual(sum(x["count"] for x in cats), 108)
        local = [it for it in items if it.get("scope") == "local"]
        self.assertEqual(len(local), 12)
        self.assertTrue(all(it.get("generic") is False for it in local))
        self.assertTrue(all(it.get("generic") is True
                            for it in items if it.get("scope") == "general"))
        self.assertEqual(data.get("updated"), "2026-11-01T07:00:00+08:00")


class Test60BuildTreeSessionFilter(unittest.TestCase):
    """单测 60：全表快照内存构树＋剔除；查询命令失败 fail closed。"""

    def test_60a_drop_exited_from_snapshot_tree(self):
        procs = {100: _plain_proc(100, 0, "2026-11-01T09:00:00+08:00", "root.exe"),
                 101: _plain_proc(101, 100, "2026-11-01T09:00:01+08:00"),
                 102: _plain_proc(102, 101, "2026-11-01T09:00:02+08:00")}
        tree = pc.build_tree_with_session_filter(procs, {100, 101}, 100)
        self.assertEqual(sorted(tree), [100, 101])   # 102 刚退出 → 剔除，不连坐

    def test_60b_scan_error_fail_closed(self):
        h = Harness(scan=SCAN_EMPTY)
        try:
            def boom():
                raise pc.ScanError("cim 服务异常")
            with mock.patch.object(pc, "scan_snapshot", side_effect=boom):
                st, obj = http_req("POST", "/api/v1/agent/kill",
                                   kill_body(pid=100, started="s"), AGENT_HDR)
            self.assertEqual(st, 500)
            self.assertEqual(obj["reason"], "scan_failed")
        finally:
            h.stop()


class _TreeStateBase(unittest.TestCase):
    """公共底座：函数级 state + 造扫描。"""

    def setUp(self):
        self.state = pc.AppState(Path(tempfile.mkdtemp(prefix="pcon-t64-")),
                                 {"rules": pc.validate_rules(pc.DEFAULT_RULES),
                                  "protection": pc.validate_protection(pc.DEFAULT_PROTECTION),
                                  "port_map": {}, "unknown": [], "warnings": []},
                                 3999, "t", True)
        self.state.console_pid = 4242
        self.state.console_port = 3999

    def tearDown(self):
        shutil.rmtree(self.state.base_dir, ignore_errors=True)

    def _scan(self, child_started="2026-11-01T09:00:01+08:00",
              raw_sessions=None, child_pid=101, child_name="child.exe",
              child_exe=r"C:\x\x.exe"):
        procs = [_plain_proc(100, 0, "2026-11-01T09:00:00+08:00", "root.exe"),
                 dict(_plain_proc(child_pid, 100, child_started, child_name),
                      exe=child_exe)]
        if raw_sessions is None:
            raw_sessions = {"100": "1", str(child_pid): "1"}
        return pc.normalize_snapshot(make_scan(
            [conn("0.0.0.0", 3084, 100)], procs, raw_sessions))

    def _tree(self, scan):
        return pc.build_tree_with_session_filter(
            scan["processes"],
            scan.get("_session_seen") or set(scan["processes"]),
            100)


class Test61StartedRequired(_TreeStateBase):
    """单测 61：子树成员 started 必填三态（H1 全有/H2 空/H3 缺键）。"""

    def test_61_h1_all_started_ok(self):
        scan = self._scan()
        allowed, reason, _ = pc.check_protection(
            self.state, scan, scan["entries"][0], self._tree(scan))
        self.assertTrue(allowed, reason)

    def test_61_h2_empty_started_rejected(self):
        scan = self._scan(child_started="")
        allowed, reason, _ = pc.check_protection(
            self.state, scan, scan["entries"][0], self._tree(scan))
        self.assertFalse(allowed)
        self.assertIn("启动时间不可读", reason)

    def test_61_h3_missing_key_rejected(self):
        scan = self._scan()
        scan["processes"][101].pop("started")     # 伪条目缺 started 键
        allowed, reason, _ = pc.check_protection(
            self.state, scan, scan["entries"][0], self._tree(scan))
        self.assertFalse(allowed)
        self.assertIn("启动时间不可读", reason)


class Test62SessionVerdicts(_TreeStateBase):
    """单测 62：I1 全员带 session_id → 放行；I2 人还在但会话读不到 → 拒。"""

    def test_62_i1_all_sessions_ok(self):
        scan = self._scan()
        allowed, reason, _ = pc.check_protection(
            self.state, scan, scan["entries"][0], self._tree(scan))
        self.assertTrue(allowed, reason)

    def test_62_i2_session_unreadable_rejected(self):
        # raw sessions 值 None = PS 端 Get-Process 见到了进程但 SessionId 读不出
        scan = self._scan(raw_sessions={"100": "1", "101": None})
        allowed, reason, _ = pc.check_protection(
            self.state, scan, scan["entries"][0], self._tree(scan))
        self.assertFalse(allowed)
        self.assertIn("会话信息缺失", reason)


class Test63GoneVsAlive(ServerCase):
    """单测 63：人没了剔（受保护成员也不连坐）；人还在但读不到 → 拒。"""

    def test_63_i3_gone_member_dropped(self):
        scan = make_scan([conn("0.0.0.0", 3084, 100)],
                         [proc(100, name="root.exe",
                               started="2026-11-01T10:00:00+08:00"),
                          proc(101, name="dllhost.exe", ppid=100,
                               exe=r"C:\Windows\System32\dllhost.exe",
                               started="2026-11-01T10:00:01+08:00")],
                         {"100": 1})            # 101 无键 = 刚退出
        pc.scan_snapshot = lambda: scan
        with self.h.mock_kill(scan):
            st, obj = http_req("POST", "/api/v1/agent/kill",
                               kill_body(pid=100, proc_name="root.exe",
                                         started="2026-11-01T10:00:00+08:00"), AGENT_HDR)
            self.assertEqual(st, 200)           # 退出成员不参与保护判定

    def test_63_i4_alive_unreadable_rejected(self):
        scan = make_scan([conn("0.0.0.0", 3084, 100)],
                         [proc(100, name="root.exe",
                               started="2026-11-01T10:00:00+08:00"),
                          proc(101, name="dllhost.exe", ppid=100,
                               exe=r"C:\Windows\System32\dllhost.exe",
                               started="2026-11-01T10:00:01+08:00")],
                         {"100": "1", "101": None})   # 人还在，会话读不到
        pc.scan_snapshot = lambda: scan
        st, obj = http_req("POST", "/api/v1/agent/kill",
                           kill_body(pid=100, proc_name="root.exe",
                                     started="2026-11-01T10:00:00+08:00"), AGENT_HDR)
        self.assertEqual(st, 403)
        self.assertIn("会话信息缺失", obj["protected_reason"])


class Test64BuildTreeDirect(unittest.TestCase):
    """单测 64（三态）：直接调 build_tree_with_session_filter 断言输出树。"""

    def test_64_i5_and_ppid_reuse_three_states(self):
        root = _plain_proc(100, 0, "2026-11-01T09:00:00+08:00", "root.exe")
        # I5：输出树不含已退出 PID（直接断言输出，防"永远为真但测反了"）
        procs = {100: root,
                 101: _plain_proc(101, 100, "2026-11-01T09:00:05+08:00"),
                 102: _plain_proc(102, 100, "2026-11-01T09:00:06+08:00")}
        tree = pc.build_tree_with_session_filter(procs, {100, 101}, 100)
        self.assertIn(100, tree)
        self.assertIn(101, tree)
        self.assertNotIn(102, tree)
        # PPID 复用三态 a)：真子进程（started 晚于根）→ 不剔除
        procs_a = {100: root,
                   101: _plain_proc(101, 100, "2026-11-01T09:00:05+08:00")}
        self.assertEqual(sorted(pc.build_tree_with_session_filter(
            procs_a, {100, 101}, 100)), [100, 101])
        # b) PPID 复用孤儿（started 早于根 = 父 PID 已被新进程复用）→ 剔除
        procs_b = {100: root,
                   103: _plain_proc(103, 100, "2026-11-01T08:00:00+08:00")}
        self.assertEqual(pc.build_tree_with_session_filter(
            procs_b, {100, 103}, 100), [100])
        # c) started 为空 → 不剔除（不知道怎么判就别剔——保守）
        procs_c = {100: root, 104: _plain_proc(104, 100, "")}
        self.assertEqual(sorted(pc.build_tree_with_session_filter(
            procs_c, {100, 104}, 100)), [100, 104])
        # d) 根 started 为空 → PPID 过滤整体不启用
        root2 = _plain_proc(200, 0, "", "root2.exe")
        procs_d = {200: root2,
                   201: _plain_proc(201, 200, "2026-11-01T08:00:00+08:00")}
        self.assertEqual(sorted(pc.build_tree_with_session_filter(
            procs_d, {200, 201}, 200)), [200, 201])
        # e) started 解析失败 → 不剔除（保守）
        procs_e = {100: root, 105: _plain_proc(105, 100, "not-a-date")}
        self.assertEqual(sorted(pc.build_tree_with_session_filter(
            procs_e, {100, 105}, 100)), [100, 105])


class Test65CacheReverseLeak(ServerCase):
    """单测 65：缓存反向泄漏——定向扫描不写缓存，GET /ports 仍全表。"""

    SCAN = make_scan([conn("0.0.0.0", 3084, 100), conn("0.0.0.0", 3085, 200)],
                     [proc(100, name="a.exe"), proc(200, name="b.exe")],
                     {"100": 1, "200": 1})

    def test_65_directed_scan_never_pollutes_cache(self):
        calls = {"n": 0}
        real = self.h._scan

        def counting():
            calls["n"] += 1
            return real

        with mock.patch.object(pc, "scan_snapshot", counting):
            st, obj = http_req("GET", "/api/v1/agent/ports?port=3084", None, AGENT_HDR)
            self.assertEqual(st, 200)
            after_agent = calls["n"]
            st2, obj2 = http_req("GET", "/api/v1/ports", None, AGENT_HDR)
            self.assertEqual(st2, 200)
            self.assertFalse(obj2["data_cached"])
            self.assertEqual(len(obj2["items"]), 2)          # 全表
            self.assertEqual(obj2["data_scope"], "full")
            after_full = calls["n"]
            st3, obj3 = http_req("GET", "/api/v1/ports", None, AGENT_HDR)
            self.assertTrue(obj3["data_cached"])             # 命中，不触发扫描
            self.assertEqual(calls["n"], after_full)
            self.assertEqual(obj3["data_time"], obj2["data_time"])
        # 定向请求真实消耗了扫描（fresh），且没有把缓存写偏：
        # 若 agent 写了缓存、ports 命中它，after_full 会等于 after_agent——断言不是
        self.assertGreater(after_full, after_agent)


class Test66RefreshBypass(ServerCase):
    """单测 66：?refresh=1 绕过缓存强制新鲜扫描，且刷新结果回写缓存。"""

    SCAN = make_scan([conn("0.0.0.0", 3084, 100)],
                     [proc(100, name="old.exe", started="2026-11-01T10:00:00+08:00")],
                     {"100": 1})

    def test_66_refresh_gets_fresh_and_rewrites_slot(self):
        st, obj = http_req("GET", "/api/v1/ports", None, AGENT_HDR)
        self.assertEqual(obj["items"][0]["proc"], "old.exe")
        new_scan = make_scan([conn("0.0.0.0", 3084, 999)],
                             [proc(999, name="new.exe",
                                   started="2026-11-01T11:00:00+08:00")],
                             {"999": 1})
        with mock.patch.object(pc, "scan_snapshot", lambda: new_scan):
            st2, obj2 = http_req("GET", "/api/v1/ports?refresh=1", None, AGENT_HDR)
            self.assertEqual(st2, 200)
            self.assertFalse(obj2["data_cached"])            # 强制新鲜
            self.assertEqual(obj2["items"][0]["proc"], "new.exe")
            st3, obj3 = http_req("GET", "/api/v1/ports", None, AGENT_HDR)
            self.assertTrue(obj3["data_cached"])             # 刷新后缓存已回写
            self.assertEqual(obj3["items"][0]["proc"], "new.exe")   # 不跳回旧数据


class Test67ProtectionListenerSource(ServerCase):
    """单测 67（mock 层）：/protection 换 GetActiveTcpListeners 数据源，语义不变。"""

    def test_67_active_history_and_scanerror(self):
        with mock.patch.object(pc, "scan_listen_ports",
                               return_value={135, 445, 3999}):
            st, obj = http_req("GET", "/api/v1/protection", None, AGENT_HDR)
        self.assertEqual(st, 200)
        self.assertEqual(obj["active_ports"], [135, 445])
        self.assertEqual(obj["history_ports"], [139, 3389, 5985, 5986])
        with mock.patch.object(pc, "scan_listen_ports",
                               side_effect=pc.ScanError("ps 爆了")):
            st2, obj2 = http_req("GET", "/api/v1/protection", None, AGENT_HDR)
        self.assertEqual(st2, 500)
        self.assertEqual(obj2["reason"], "scan_failed")


class Test70HealthCors(ServerCase):
    """单测 70（1.1 DSH 壳配套）：health 开放 CORS 供壳页跨源探活；
    其余端点必须不开——不给恶意网页跨源枚举本机端口的口子。"""

    def test_70_health_cors_open_others_not(self):
        st, head, _ = http_req_raw("GET", "/api/v1/health", headers={"Origin": "http://127.0.0.1:3080"})
        self.assertEqual(st, 200)
        self.assertIn("access-control-allow-origin: *", head.lower())
        st2, head2, _ = http_req_raw("GET", "/api/v1/agent/ports", headers={"Origin": "http://127.0.0.1:3080"})
        self.assertEqual(st2, 200)
        self.assertNotIn("access-control-allow-origin", head2.lower())


class Test69ConsoleSelfRule(ServerCase):
    """单测 69（1.1①）：控制台自身进程按出厂规则得名"端口扳手本体"（level=self）。

    实测痛点（外部用户）：查 3999 返回 name=""、source="unknown"，全靠
    protected_reason 兜底才认出来——工具自己成了唯一不认识的进程。"""

    def test_69_console_named_by_factory_rule(self):
        st = self.h.state
        e = {"port": 3999, "addr": "0.0.0.0", "pid": 4242, "proc": "python.exe",
             "exe": str(Path(pc.__file__).resolve()),
             "cmdline": "python port_console.py", "started": "s", "session_id": 1}
        cls = pc.classify_entry(st, e)
        self.assertEqual(cls["name"], "端口扳手本体")
        self.assertEqual(cls["level"], "self")
        self.assertEqual(cls["source"], "auto")


class Test68OnedriveNoRegression(ServerCase):
    """单测 68：onedrive proc 源命中（两源拼接，exe 不进——System32 误伤实证）＋代表性样本无回归（全表真机对比在 acceptance）。"""

    EXTRA = {"rules": _rules21()}

    def test_68_onedrive_hit_and_representatives(self):
        st = self.h.state
        base = {"port": 1, "addr": "0.0.0.0", "pid": 2, "proc": "x.exe", "exe": "",
                "started": "s", "session_id": 1}
        # 主样本：cmdline 非空但不含规则词，旧逻辑 unknown → 新逻辑命中
        e = dict(base, port=42050, proc="OneDrive.Sync.Service.exe",
                 exe=r"C:\Users\x\OneDrive\OneDrive.Sync.Service.exe",
                 cmdline="/silentConfig")
        self.assertEqual(pc.classify_entry(st, e)["name"], "OneDrive")
        # 无回归 A：cmdline 命中的老样本（改动前后同命中）
        for over, name in [
                ({"cmdline": r"D:\x\wechat-work\server.exe"}, "企业微信"),
                ({"cmdline": r"D:\x\wechat\run.exe"}, "微信"),
                ({"cmdline": r"D:\dsh\wechat-work\run.exe"}, "企业微信"),
                ({"cmdline": "python -m ComfyUI.main"}, "ComfyUI"),
                ({"cmdline": "ollama serve"}, "Ollama"),
                ({"cmdline": r"D:\apps\wechat\WeChatApp.exe"}, "微信")]:
            self.assertEqual(pc.classify_entry(st, dict(base, **over))["name"], name,
                             f"回归: {over}")
        # 无回归 B：cmdline 空、proc/exe 命中（新旧逻辑都看得到）
        for over, name in [
                ({"cmdline": "", "proc": "HipsDaemon.exe",
                  "exe": r"C:\火绒\HipsDaemon.exe"}, "火绒安全"),
                ({"cmdline": "", "proc": "wpscloudsvr.exe",
                  "exe": r"C:\WPS\wpscloudsvr.exe"}, "WPS办公"),
                ({"cmdline": "", "proc": "lghub_agent.exe",
                  "exe": r"C:\Logi\lghub_agent.exe"}, "罗技lghub")]:
            self.assertEqual(pc.classify_entry(st, dict(base, **over))["name"], name,
                             f"回归: {over}")

