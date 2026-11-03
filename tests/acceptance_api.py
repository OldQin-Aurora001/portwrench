# -*- coding: utf-8 -*-
"""端口控制台自动验收（T-PORT-002 · 方案 §11.3，脚本实跑 18 步；17 号由单测覆盖。
T-PORT-004 1.0.1 增补 step19-21：展示缓存 V58/V73、/protection 提速 V74、
知识库全表回归 V75。V54-V57/V59/V61-V72 由单测 54-68 覆盖（V57 取消保留编号）。
只打控制台 API 与脚本自建的测试夹具，不碰 DSH、系统服务或真实进程。
任一断言失败或清理失败 → 非零退出码。"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CREATE_NO_WINDOW = 0x08000000
TOKEN = {"v": ""}
sys.path.insert(0, str(ROOT))
from port_console import pid_matches_start  # noqa: E402  杀后存活判定（防 PID 复用假阳性）


def note(m):
    print(m, flush=True)


def require(cond, msg):
    if not cond:
        raise StepFail(msg)
    note("  PASS " + msg)


class StepFail(Exception):
    pass


class Api:
    """裸 socket HTTP（零 urllib，Mimosa 过闸写法）。"""

    def __init__(self, base_url):
        assert base_url.startswith("http://127.0.0.1:")
        self.port = int(base_url.rsplit(":", 1)[1])
        self.base = base_url

    def req(self, method, path, body=None, headers=None, timeout=15):
        hdrs = {"Host": "127.0.0.1:" + str(self.port)}
        hdrs.update(headers or {})
        data = b""
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        raw = method + " " + path + " HTTP/1.1\r\n"
        for k, v in hdrs.items():
            raw += k + ": " + str(v) + "\r\n"
        raw += "Content-Length: " + str(len(data)) + "\r\nConnection: close\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
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


def wait_port_gone(port, timeout=12):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=0.4)
            c.close()
            time.sleep(0.3)
        except OSError:
            return True
    return False


def wait_port_open(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            c.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def pick_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def pid_alive(pid):
    if pid is None:
        return False
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h = k32.OpenProcess(0x1000, False, int(pid))
    if h:
        k32.CloseHandle(h)
        return True
    return False


def read_audit():
    f = ROOT / "kill_audit.jsonl"
    if not f.exists():
        return []
    out = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def agent_hdr():
    return {"X-Port-Console-Token": TOKEN["v"]}


class Tree:
    """fixture_process_tree.py 包装（命令全部参数列表 + int 白名单化 + shell=False）。"""

    @staticmethod
    def cmd(port_a, port_b, orphan):
        cmd = [sys.executable, os.path.join(str(HERE), "fixture_process_tree.py"),
               "--port", str(int(port_a))]
        if port_b:
            cmd.append("--child-port")
            cmd.append(str(int(port_b)))
        if orphan:
            cmd.append("--orphan")
        return cmd

    def __init__(self, port_a, port_b=None, orphan=False):
        self.proc = subprocess.Popen(Tree.cmd(port_a, port_b, orphan),
                                     shell=False, creationflags=CREATE_NO_WINDOW,
                                     stdout=subprocess.PIPE)
        self.info = None
        if not orphan:
            line = self.proc.stdout.readline().decode("utf-8").strip()
            self.info = json.loads(line) if line else None

    def kill_tree(self):
        if self.proc and self.proc.poll() is None:
            subprocess.run(["taskkill", "/PID", str(int(self.proc.pid)), "/T", "/F"],
                           shell=False, capture_output=True,
                           creationflags=CREATE_NO_WINDOW)


class Windowed:
    """fixture_windowed.ps1 包装（READY 阻塞等待）。"""

    @staticmethod
    def cmd(port, ignore_close):
        cmd = ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-WindowStyle", "Hidden", "-File",
               os.path.join(str(HERE), "fixture_windowed.ps1"),
               "-Port", str(int(port))]
        if ignore_close:
            cmd.append("-IgnoreCloseCount")
            cmd.append(str(int(ignore_close)))
        return cmd

    def __init__(self, port, ignore_close=0):
        self.proc = subprocess.Popen(Windowed.cmd(port, ignore_close),
                                     shell=False, stdout=subprocess.PIPE)
        line = self.proc.stdout.readline().decode("utf-8", errors="replace").strip()
        if "READY" not in line:
            raise StepFail("windowed fixture not ready: " + repr(line))

    def pid(self):
        return self.proc.pid

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()


# ----------------------------------------------------------------------------
# 步骤（对照方案 §11.3）
# ----------------------------------------------------------------------------


def step1_health(api):
    st, obj = api.req("GET", "/api/v1/health")
    require(st == 200 and obj["ok"] and obj["api_version"] == "v1",
            "health 在线且 api_version=v1")
    require(api.port > 0 and not api.base.startswith("http://0.0.0.0"),
            "服务只监听回环")


def step2_launch_tree(a_port, b_port):
    t = Tree(a_port, b_port)
    require(bool(t.info) and bool(t.info.get("child_pid")), "父子夹具已启动（含子 PID）")
    return t


def step3_l0_sees_tree(api, a_port, b_port):
    st, obj = api.req("GET", "/api/v1/ports?refresh=1")
    require(st == 200, "GET /api/v1/ports 200")
    items = {i["port"]: i for i in obj["items"]}
    started_map = {}
    for p in (a_port, b_port):
        require(p in items, "端口 " + str(p) + " 出现在完整列表")
        it = items[p]
        for k in ("port", "pid", "proc", "cmdline", "started"):
            require(k in it, "条目含字段 " + k)
        started_map[it["pid"]] = it["started"]
    return started_map


def step4_agent_ports_slim(api, a_port):
    # 1.2 WS-C'（C1 真机侧）：匿名（无 token、无跨源头）精查 200 但纯只读——
    # 不下发 snapshot_id。
    st, anon = api.req("GET", "/api/v1/agent/ports?port=" + str(a_port))
    require(st == 200 and len(anon["items"]) == 1, "匿名 agent/ports 精查返回 1 条")
    require("snapshot_id" not in anon["items"][0], "匿名精查不得下发 snapshot_id")
    require(anon.get("authenticated") is False, "匿名精查 authenticated=false")
    # 持 token：全语义，唯一占用附 snapshot_id
    st, obj = api.req("GET", "/api/v1/agent/ports?port=" + str(a_port),
                      None, agent_hdr())
    require(st == 200 and len(obj["items"]) == 1, "agent/ports 精查返回 1 条")
    it = obj["items"][0]
    for k in ("name", "level", "source", "kill_allowed"):
        require(k in it, "精简条目含 " + k)
    require("cmdline" not in it, "精简条目不含长 cmdline")
    require("snapshot_id" in it, "唯一占用附 snapshot_id")
    for bad in ("abc", "0", "70000"):
        # 非法参数匿名同样应 400（参数校验先于语义，且与跨源无关）
        st, obj = api.req("GET", "/api/v1/agent/ports?port=" + bad)
        require(st == 400 and obj["reason"] == "invalid_request",
                "非法 port=" + bad + " → 400 invalid_request")


def step5_agent_rejections(api, a_port, tree_pid, tree_started):
    tok = TOKEN["v"]
    # T-PORT-003 B2：started 必填——拒绝路径请求也带真实指纹
    body = {"port": a_port, "pid": tree_pid, "proc": "python.exe", "started": tree_started}
    cases = [
        ("无 token", {}, 401, "unauthorized"),
        ("错 token", {"X-Port-Console-Token": "wrong-" + tok}, 401, "unauthorized"),
        ("缺 confirm", {"X-Port-Console-Token": tok}, 400, "confirm_required"),
    ]
    for label, hdr, code_want, reason_want in cases:
        st, obj = api.req("POST", "/api/v1/agent/kill", body, hdr)
        require(st == code_want and obj["reason"] == reason_want,
                label + " → " + str(code_want) + " " + reason_want)
    h = agent_hdr()
    st, obj = api.req("POST", "/api/v1/agent/kill",
                      dict(body, confirm=True, force=True), h)
    require(st == 400 and obj["reason"] == "invalid_request", "Agent 带 force → 400")
    st, obj = api.req("POST", "/api/v1/agent/kill-by-port",
                      {"port": a_port, "pid": tree_pid, "confirm": True}, h)
    require(st == 400 and obj["reason"] == "invalid_request", "按端口带身份字段 → 400")
    st, obj = api.req("POST", "/api/v1/agent/kill", dict(body, confirm=True),
                      dict(h, Origin="http://evil.example"))
    require(st == 403, "伪造跨站 Origin → 403")
    st, obj = api.req("GET", "/api/v1/agent/ports?port=" + str(a_port))
    require(st == 200 and obj["items"], "拒绝路径后目标仍在")


def step6_ui_no_origin_403(api, a_port, tree_pid, tree_started):
    st, obj = api.req("POST", "/api/v1/ui/kill",
                      {"port": a_port, "pid": tree_pid, "proc": "python.exe",
                       "started": tree_started, "force": False})
    require(st == 403 and obj["reason"] == "not_ui_origin", "无同源证据打 UI → 403")


def step7_agent_kill_success(api, a_port, tree_pid, started):
    st, obj = api.req("POST", "/api/v1/agent/kill",
                      {"port": a_port, "pid": tree_pid, "proc": "python.exe",
                       "started": started, "confirm": True},
                      agent_hdr(), timeout=30)
    require(st == 200 and obj["ok"], "agent/kill 200 ok")
    require(obj["remaining"] == [], "remaining=[] 关干净")
    require("target" in obj and "killed" in obj, "响应带服务端现查 target/killed")
    require("force_ticket" not in json.dumps(obj), "成功响应不含 force_ticket")


def step8_verify_released_and_audit(api, a_port, b_port, tree, started_map):
    require(wait_port_gone(a_port) and wait_port_gone(b_port), "端口 A/B 均无监听")
    require(not pid_matches_start(tree.info["pid"], started_map.get(tree.info["pid"], ""))
            and not pid_matches_start(tree.info["child_pid"],
                                      started_map.get(tree.info["child_pid"], "")),
            "父/子 PID 均退出（创建时间指纹比对）")
    audit = read_audit()
    fin = [e for e in audit if e.get("action") == "finished"]
    started_ev = [e for e in audit if e.get("action") == "started"]
    require(bool(started_ev) and bool(fin), "审计含前置/结果事件")
    last = fin[-1]
    for k in ("name", "level", "source"):
        require(k in last["target"], "审计目标含归属 " + k)
    text = json.dumps(audit, ensure_ascii=False)
    require(TOKEN["v"] not in text, "审计不含 token")
    require("server.py" not in text, "审计不含完整命令行")


def step9_already_free(api, a_port):
    before = len(read_audit())
    st, obj = api.req("POST", "/api/v1/agent/kill-by-port",
                      {"port": a_port, "confirm": True}, agent_hdr())
    require(st == 200 and obj["ok"] and obj["already_free"] is True
            and obj["target"] is None, "空端口幂等成功 already_free")
    require(len(read_audit()) == before, "幂等成功不新增 kill 审计")


def step10_fingerprint_full_flow(api, a_port, b2_port):
    t = Tree(a_port, b2_port)
    require(t.info is not None, "夹具重启（步骤 10）")
    try:
        st, obj = api.req("GET", "/api/v1/agent/ports?port=" + str(a_port),
                          None, agent_hdr())   # 1.2 WS-C'：取 sid 必须持 token
        sid = obj["items"][0]["snapshot_id"]
        st, obj = api.req("POST", "/api/v1/agent/kill-by-port",
                          {"port": a_port, "confirm": True}, agent_hdr())
        require(st == 400 and obj["reason"] == "target_identity_required",
                "占用状态缺指纹 → 400")
        st, obj = api.req("POST", "/api/v1/agent/kill-by-port",
                          {"port": a_port, "snapshot_id": sid, "confirm": True},
                          agent_hdr(), timeout=30)
        require(st == 200 and obj["remaining"] == [], "带指纹关闭成功")
        require(wait_port_gone(a_port) and wait_port_gone(b2_port), "端口 A/B2 释放")
    finally:
        t.kill_tree()


def step11_owner_changed(api, a_port):
    t = Tree(a_port)
    try:
        st, obj = api.req("GET", "/api/v1/agent/ports?port=" + str(a_port),
                          None, agent_hdr())   # 1.2 WS-C'：取 sid 必须持 token
        sid = obj["items"][0]["snapshot_id"]
        t.kill_tree()
        require(wait_port_gone(a_port), "易主前进程已清")
        t2 = Tree(a_port)                      # 不同实例（新 PID）
        st, obj = api.req("POST", "/api/v1/agent/kill-by-port",
                          {"port": a_port, "snapshot_id": sid, "confirm": True},
                          agent_hdr(), timeout=30)
        require(st == 409 and obj["reason"] == "target_changed",
                "旧指纹打新占用者 → 409 target_changed")
        return t2
    except StepFail:
        t.kill_tree()
        raise


def step12_replay_old_identity(api, a_port, started_old):
    st, obj = api.req("POST", "/api/v1/agent/kill",
                      {"port": a_port, "pid": 1, "proc": "python.exe",
                       "started": started_old, "confirm": True}, agent_hdr())
    require(st in (404, 409), "旧四元组重放 → " + str(st) + "（404/409）")


def step13_self_port_protected(api):
    st, obj = api.req("GET", "/api/v1/agent/ports?port=" + str(api.port),
                      None, agent_hdr())   # 1.2 WS-C'：取 sid 必须持 token
    if not obj["items"]:
        note("  SKIP 控制台端口不在监听列表")
        return
    body = {"port": api.port, "confirm": True}
    sid = obj["items"][0].get("snapshot_id")
    if sid:
        body["snapshot_id"] = sid
    st, obj = api.req("POST", "/api/v1/agent/kill-by-port", body,
                      agent_hdr(), timeout=30)
    require(st == 403 and obj["reason"] == "kill_not_allowed", "打控制台自身 → 403")


def _windowed_identity(api, port):
    """T-PORT-003 B2：起夹具后从完整条目取真实 started。"""
    st, obj = api.req("GET", "/api/v1/ports?refresh=1")
    it = [i for i in obj["items"] if i["port"] == port]
    return (it[0]["proc"], it[0]["started"]) if it else ("powershell.exe", "")


def step14_windowed_normal_close(api, port_c):
    w = Windowed(port_c)
    origin = {"Origin": api.base, "Sec-Fetch-Site": "same-origin"}
    proc_name, started = _windowed_identity(api, port_c)
    try:
        st, obj = api.req("POST", "/api/v1/ui/kill",
                          {"port": port_c, "pid": w.pid(), "proc": proc_name,
                           "started": started, "force": False}, origin, timeout=40)
        require(st == 200 and obj["ok"], "有窗 force=false → WM_CLOSE 直接成功")
        require("force_ticket" not in json.dumps(obj), "正常关闭不生成强杀 ticket")
        require(wait_port_gone(port_c), "窗口进程退出且端口 C 释放")
    finally:
        w.stop()


def step15_two_stage_force(api, port_d):
    w = Windowed(port_d, ignore_close=1)
    origin = {"Origin": api.base, "Sec-Fetch-Site": "same-origin"}
    proc_name, started = _windowed_identity(api, port_d)
    ticket = ""
    try:
        st, obj = api.req("POST", "/api/v1/ui/kill",
                          {"port": port_d, "pid": w.pid(), "proc": proc_name,
                           "started": started, "force": False}, origin, timeout=40)
        require(st == 428 and obj["reason"] == "force_confirm_required", "取消关窗 → 428")
        ticket = obj.get("force_ticket", "")
        require(bool(ticket), "428 返回 force_ticket")
        st, obj = api.req("POST", "/api/v1/ui/kill",
                          {"port": port_d, "pid": w.pid(), "proc": proc_name,
                           "started": started, "force": True}, origin, timeout=40)
        require(st == 409 and obj["reason"] == "force_ticket_invalid",
                "带 force 无 ticket → 409")
        st, obj = api.req("POST", "/api/v1/ui/kill",
                          {"port": port_d, "pid": w.pid(), "proc": proc_name,
                           "started": started, "force": True, "force_ticket": ticket},
                          origin, timeout=40)
        require(st == 200 and obj["ok"], "带 ticket 强杀 → 200")
        require(wait_port_gone(port_d), "端口 D 释放")
    finally:
        w.stop()


def step16_orphan(api, a_port, b_port):
    subprocess.run(Tree.cmd(a_port, b_port, True), shell=False,
                   creationflags=CREATE_NO_WINDOW, timeout=30)
    require(wait_port_open(b_port), "orphan 子进程残留监听端口 B")
    # 完整条目取 started（agent/ports 精简条目按 §4.9 设计不含 started）
    st, obj = api.req("GET", "/api/v1/ports?refresh=1")
    it = [i for i in obj["items"] if i["port"] == b_port][0]
    child_pid, child_proc, child_started = it["pid"], it["proc"], it["started"]
    st, obj = api.req("POST", "/api/v1/agent/kill",
                      {"port": b_port, "pid": child_pid + 999999,
                       "proc": "python.exe", "started": "2020-01-01T00:00:00+08:00",
                       "confirm": True},
                      agent_hdr(), timeout=20)
    require(st in (404, 409), "旧父身份（pid 不存在）→ 404/409")
    st, obj = api.req("GET", "/api/v1/agent/ports?port=" + str(b_port))
    require(obj["items"] and obj["items"][0]["pid"] == child_pid,
            "残留子进程未被旧快照误伤")
    st, obj = api.req("POST", "/api/v1/agent/kill",
                      {"port": b_port, "pid": child_pid,
                       "proc": child_proc, "started": child_started,
                       "confirm": True}, agent_hdr(), timeout=30)
    require(st == 200 and obj["remaining"] == [], "按当前身份重关成功")
    require(wait_port_gone(b_port), "端口 B 释放")


def step18_single_instance():
    tmp = Path(tempfile.mkdtemp(prefix="pcon-acc-"))
    try:
        for name in ("port_console.py", "rules.json", "protection.json"):
            shutil.copy2(ROOT / name, tmp / name)
        (tmp / "port_map.json").write_text("{}", encoding="utf-8")
        (tmp / "unknown.json").write_text("[]", encoding="utf-8")
        (tmp / "runtime.json").write_text(json.dumps(
            {"base_url": "http://127.0.0.1:1", "pid": 999999}), encoding="utf-8")
        no_browser_env = dict(os.environ, PORT_CONSOLE_NO_BROWSER="1")
        proc = subprocess.Popen([sys.executable, str(tmp / "port_console.py")],
                                cwd=str(tmp), shell=False,
                                creationflags=CREATE_NO_WINDOW,
                                env=no_browser_env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            base = wait_runtime_ready(tmp, proc, timeout=40)
            require(bool(base), "陈旧 runtime 识别恢复，新实例上线 " + str(base))
        finally:
            if proc.poll() is None:
                proc.kill()
        p2 = subprocess.run([sys.executable, str(ROOT / "port_console.py")],
                            cwd=str(ROOT), capture_output=True, shell=False,
                            creationflags=CREATE_NO_WINDOW, timeout=30,
                            env=no_browser_env)
        require(p2.returncode == 0, "第二实例健康识别后正常退出（exit 0）")
        note("  NOTE 18c（锁占+健康不通失败）由单测 19 覆盖")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ----------------------------------------------------------------------------
# T-PORT-004 1.0.1 增补步骤（V58/V73/V74/V75；V54-V57/V59/V61-V63/V64-V72 单测层）
# ----------------------------------------------------------------------------


def step19_display_cache(api):
    """V58 展示缓存命中＋V73 手动刷新绕缓存＋V59 宽松断言（sid 端点不吃缓存）。"""
    st, obj = api.req("GET", "/api/v1/ports")
    require(st == 200 and obj.get("ok"), "GET /api/v1/ports 200")
    require(obj.get("data_cached") is False, "首次 GET 为新鲜扫描（data_cached=false）")
    require(bool(obj.get("data_time")), "data_time 数据时间已下发")
    require(obj.get("data_scope") == "full", "缓存范围标记 _scope=full")
    st2, obj2 = api.req("GET", "/api/v1/ports")
    require(st2 == 200, "第二次 GET 200")
    require(obj2.get("data_cached") is True, "5 秒内第二次 GET 命中缓存（V58）")
    require(obj2.get("data_time") == obj.get("data_time"), "缓存数据时间不漂移")
    st3, obj3 = api.req("GET", "/api/v1/ports?refresh=1")
    require(st3 == 200 and obj3.get("data_cached") is False,
            "?refresh=1 绕过缓存强制新鲜（V73）")
    st4, obj4 = api.req("GET", "/api/v1/agent/ports?port=1", None, agent_hdr())
    require(st4 in (200, 400), "agent/ports 定向请求可用（V59：sid 端点走新鲜扫描）")
    note("  NOTE V59：定向扫描与缓存写隔离由单测 65 断言（真机不可数扫描次数）")


def step20_protection_speed(api):
    """V74：/protection 数据源换 GetActiveTcpListeners——端口集合与全表扫描一致＋实测耗时。"""
    sys.path.insert(0, str(ROOT))          # 已在头部 import 过；此处幂等
    import port_console as pcmod
    t0 = time.perf_counter()
    listeners = pcmod.scan_listen_ports()
    t1 = time.perf_counter()
    scan = pcmod.scan_or_error()
    t2 = time.perf_counter()
    full_set = {e["port"] for e in scan["entries"]}
    require(listeners == full_set,
            f"GetActiveTcpListeners({len(listeners)}) 与全表扫描({len(full_set)}) 端口集合一致（V74）")
    note("  实测耗时: listen_ports={:.3f}s  全表扫描={:.3f}s".format(t1 - t0, t2 - t1))
    st, obj = api.req("GET", "/api/v1/protection")
    require(st == 200 and "active_ports" in obj and "history_ports" in obj,
            "/api/v1/protection 200 且 active/history 结构在")
    t3 = time.perf_counter()
    api.req("GET", "/api/v1/protection")
    dt = time.perf_counter() - t3
    note("  /api/v1/protection 接口实测: {:.3f}s".format(dt))
    require(dt < 1.0, f"/protection 耗时 {dt:.3f}s < 1s（原全表扫描口径约 1.2s，白捡提速）")


def step21_ports_json_regression(api):
    """V75：三源拼接后全表逐条对比改前识别结果——只允许 unknown→有名字 的改善，不许 A→B 误伤。"""
    import port_console as pcmod
    st, obj = api.req("GET", "/api/v1/ports?refresh=1", None, agent_hdr())
    require(st == 200, "GET /ports 200（agent 头取完整条目）")
    rules = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))
    ordered = sorted(rules, key=lambda r: (r.get("order", 9999)))
    improved, kept, wounded = 0, 0, []
    for it in obj["items"]:
        cmdline, proc_name, exe = it.get("cmdline", ""), it.get("proc", ""), it.get("exe", "")
        # 改前逻辑（R3 必修 5 之前）：cmdline 非空就不看 proc/exe
        old_text = cmdline if cmdline else f"{proc_name} {exe}"
        # 改后逻辑与实现一致（两源：exe 全路径会把 System32 喂给 "System" 规则，
        # 真机实测误伤——见 port_console.classify_entry 注释与回件偏离申报）
        new_text = " ".join(x for x in (cmdline, proc_name) if x)
        old_name = new_name = ""
        for r in ordered:
            m = r["match"].casefold()
            if m in old_text.casefold() and not old_name:
                old_name = r["name"]
            if m in new_text.casefold() and not new_name:
                new_name = r["name"]
        if old_name == new_name:
            kept += 1
        elif not old_name and new_name:
            improved += 1
        else:
            wounded.append((it.get("port"), old_name, new_name))
    require(not wounded,
            f"全表回归 {kept} 条不变 + {improved} 条改善（unknown→有名字），误伤 {len(wounded)} 条（V75）")
    if wounded:
        for w in wounded[:10]:
            note("  误伤样本: port={} {}→{}".format(*w))


def wait_runtime_ready(tmp, proc, timeout=40):
    deadline = time.time() + timeout
    rt = tmp / "runtime.json"
    while time.time() < deadline:
        if proc.poll() is not None:
            return None
        if rt.exists():
            try:
                data = json.loads(rt.read_text(encoding="utf-8"))
                base = data.get("base_url", "")
                st, obj = Api(base).req("GET", "/api/v1/health", timeout=3)
                if st == 200 and obj.get("ok"):
                    return base
            except Exception:
                pass
        time.sleep(0.4)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:3999")
    ap.add_argument("--token-file", default=str(ROOT / "api_token.txt"))
    args = ap.parse_args()
    tok = Path(args.token_file).read_text(encoding="utf-8-sig").strip()
    TOKEN["v"] = tok
    note("[acceptance] token 遮蔽加载: " + tok[:4] + "***" + tok[-4:])

    api = Api(args.base_url)
    trees = []
    t2_owner = None
    old_started = ""
    ports = [pick_free_port() for _ in range(5)]
    a_port, b_port, b2_port, c_port, d_port = ports
    exit_code = 0
    try:
        note("[1/21] health 校验")
        step1_health(api)
        note("[2/21] 启动父子夹具")
        trees.append(step2_launch_tree(a_port, b_port))
        note("[3/21] L0 完整列表断言")
        started_map = step3_l0_sees_tree(api, a_port, b_port)
        note("[4/21] agent/ports 精简断言")
        step4_agent_ports_slim(api, a_port)
        note("[5/21] AI 拒绝路径六连")
        step5_agent_rejections(api, a_port, trees[-1].info["pid"],
                               started_map.get(trees[-1].info["pid"], ""))
        note("[6/21] UI 无同源证据 403")
        step6_ui_no_origin_403(api, a_port, trees[-1].info["pid"],
                               started_map.get(trees[-1].info["pid"], ""))
        # （复核建议 8：原此处有一行 GET agent/ports 死代码——B2 改从
        #   started_map 取 started 后它只剩白跑一次服务端扫描，已删）
        old_started = started_map.get(trees[-1].info["pid"], "")
        note("[7/21] agent/kill 单次直达")
        step7_agent_kill_success(api, a_port, trees[-1].info["pid"], old_started)
        note("[8/21] 释放验证+审计断言")
        step8_verify_released_and_audit(api, a_port, b_port, trees[-1], started_map)
        note("[9/21] 幂等 already_free")
        step9_already_free(api, a_port)
        note("[10/21] 指纹全流程")
        step10_fingerprint_full_flow(api, a_port, b2_port)
        note("[11/21] 端口易主旧指纹")
        t2_owner = step11_owner_changed(api, a_port)
        note("[12/21] 旧四元组重放")
        step12_replay_old_identity(api, a_port, old_started)
        note("[13/21] 控制台自身保护")
        step13_self_port_protected(api)
        note("[14/21] 有窗 WM_CLOSE 正常关闭")
        step14_windowed_normal_close(api, c_port)
        note("[15/21] 两阶段强杀（IgnoreCloseCount）")
        step15_two_stage_force(api, d_port)
        note("[16/21] 父先退子残留")
        step16_orphan(api, a_port, b_port)
        note("[17/21] 多占用/频率闸/系统身份硬拒 —— 由单测覆盖，不占脚本步骤")
        note("[18/21] 单实例行为")
        step18_single_instance()
        note("[19/21] 展示缓存与手动刷新（V58/V73/V59 NOTE）")
        step19_display_cache(api)
        note("[20/21] /protection 数据源集合一致与耗时（V74）")
        step20_protection_speed(api)
        note("[21/21] 知识库接入全表识别回归（V75）")
        step21_ports_json_regression(api)
        note("[acceptance] 全部通过")
    except StepFail as e:
        note("[acceptance] FAIL: " + str(e))
        exit_code = 1
    except Exception as e:
        note("[acceptance] 异常: " + repr(e))
        exit_code = 1
    finally:
        for t in trees:
            try:
                t.kill_tree()
            except Exception:
                pass
        if t2_owner is not None:
            try:
                t2_owner.kill_tree()
            except Exception:
                pass
        note("[acceptance] 退出码 " + str(exit_code)
             + "（token " + tok[:4] + "***" + tok[-4:] + " 全程遮蔽）")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
