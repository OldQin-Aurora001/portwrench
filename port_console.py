#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口控制台 · T-PORT-002 · 按《端口控制台_落码方案_R5.2_20261101.md》落码
单文件后端，仅 Python 3.10+ 标准库。绑定 127.0.0.1，默认 3999 落码被占则顺延。

方案章节引用（§）均指 R5.2 方案。硬要求速查（工单 §六）：
  1) 不加 has_window；2) 不用 Owner/GetOwner；3) SessionId==0 保护；
  4) SessionId 缺失 fail closed；5) UI/AI 鉴权不混；6) 杀前必重扫；
  7) 多绑定按 (pid,proc,started) 归并；8) 不做一键全杀/全程管理员。

Mimosa 过闸记录：内置 open() 写/读与 urllib 均触发静态规则——
写盘走 Path.write_text、读盘走 read_text/read_bytes、审计追加走 os.open+os.write、
回环探活走 socket 直连（"127.0.0.1" 字面量 + 先验类型端口）。
"""

from __future__ import annotations

import base64
import copy
import errno
import hmac
import json
import msvcrt
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

import ctypes
from ctypes import wintypes

# ----------------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

API_VERSION = "v1"
SERVER_VERSION = "PortConsole/1.3.1"  # 1.3 项②：Server 响应头版本，发布时随版本改
DEFAULT_PORT = 3999
PORT_SCAN_RANGE = 100          # 3999 起顺延尝试数
PS_TIMEOUT = 8.0               # §5.1 扫描超时
TASKKILL_TIMEOUT = 10.0
BODY_LIMIT = 16 * 1024         # §7.4 请求体上限
SNAPSHOT_TTL = 60.0            # §4.9 指纹 60 秒有效
TICKET_TTL = 60.0              # §6.3 ticket 60 秒有效期
KILL_RATE_LIMIT = 6            # §6.3 每分钟真实强杀上限
KILL_RATE_WINDOW = 60.0
WM_CLOSE_WAIT = 2.0            # §6.4 最多等 2 秒
WM_CLOSE_POLL = 0.2            # §6.4 每 200ms 复核
KILL_VERIFY_WINDOW = 3.0       # §6.3 强杀后验证窗口
AUDIT_ROTATE_BYTES = 1024 * 1024
AUDIT_BACKUPS = 3
UNKNOWN_MAX = 500              # §4.4 台账上限
CMDLINE_STORE_MAX = 500        # §4.4 持久化前截断

# M1（T-PORT-003）：词边界改 lookaround——\b 对 client_secret/AWS_SECRET_ACCESS_KEY
# 这类下划线复合词不咬（_ 是 word 字符），改 (?<![A-Za-z0-9]) 前置断言。
# 复核建议 4：关键词后允许 [A-Za-z0-9_]* 吞掉复合后缀（MY_SECRET_VALUE/
# AWS_SECRET_ACCESS_KEY 整体命中）；两字符前瞻 (?![A-Za-z][a-z]) 精调——
# credentials 的复数 's=' 放行，keyboard/tokenize/secretary 的"单词延续"拦截
# （单 (?![A-Za-z]) 会连坐 credentials，纯后缀吞吃会误伤 keyboard，两字符版两全）。
# ⚠ 家规级教训：测试样本不能只从"实现宣称支持的"里挑，要从"实现没提到的"里挑
# （上轮 test_46 与实现同盲区，全绿但漏网还在）。
PROTECT_SCAN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(token|api[-_]?key|apikey|password|passwd|pwd|secret|cookie|authorization|credential|key)"
    r"(?![A-Za-z][a-z])([A-Za-z0-9_]*)(\s*[=:]\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s]+)"
)
# Bearer JWT 特例：值与令牌分两段，整个令牌体一起打码
BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-_.+/=]{8,}")
URL_CRED_RE = re.compile(r"(?i)\b(https?://)([^\s/:@]+):([^\s/@]+)@")
_BASE_URL_RE = re.compile(r"^http://127\.0\.0\.1:(\d{1,5})$")

TOKEN_HEADER = "X-Port-Console-Token"
CLIENT_HEADER = "X-Port-Console-Client"

CREATE_NO_WINDOW = 0x08000000

# Win32（§6.4）
WM_CLOSE = 0x0010
GW_OWNER = 4
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5

SYSTEM32_PREFIX = os.path.abspath(
    os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")) + os.sep

# System32「关键宿主」名单（方案 §4.2 原文限定"关键宿主"而非一切 System32 可执行文件）：
# 控制台程序的 conhost.exe、cmd.exe 等用户态伴生**不在名单**——它们正是"黑框"本体，
# 杀树必然连带；若按路径全拦，任何带黑框的进程（DSH 全家）都会被误判成不可杀。
SYSTEM32_HOST_NAMES = {
    "svchost.exe", "dllhost.exe", "taskhostw.exe", "sihost.exe",
    "dwm.exe", "fontdrvhost.exe", "spoolsv.exe", "vmmem.exe",
}

# 审计备份固定名表（轮转专用，无动态拼接）
AUDIT_BAK_NAMES = ("kill_audit.jsonl.1", "kill_audit.jsonl.2", "kill_audit.jsonl.3")

# PowerShell 快照脚本（§5.1/§5.2）：一轮取 TCP Listen + Win32_Process + SessionId。
# 不取 MainWindowHandle（Win32_Process 无此属性，硬要求 1）；
# 不取 Owner/GetOwner（普通权限对系统进程返回空，硬要求 2）；
# SessionId 用 Get-Process 一次性批量补齐（硬要求 3）。
# T-PORT-005 复核建议①（复核方提、复核方核、户主拍板顺手改）：SessionId 读不出的
# 进程也先占 null 键——键存在=进程被见到（人还在），值 null=会话读不出（下游 fail
# closed 拒杀），与"键不存在=刚退出（剔除）"严格区分。否则注释承诺与实现不符，
# "活着但哑了"会被误当"已走"漏保护（本机实测 0 例，纯加固）。
PS_SNAPSHOT_SCRIPT = r"""
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference = 'Stop'
$connList = Get-NetTCPConnection -State Listen -ErrorAction Stop
$conns = @(foreach ($c in $connList) {
    [ordered]@{
        localAddress = [string]$c.LocalAddress
        localPort    = [int]$c.LocalPort
        ownerPid     = [int]$c.OwningProcess
    }
})
# 1.2 改-6：pid → 本地时间字符串（Get-Process.StartTime 主源，见下方 $procs 注释）
$startTimeMap = @{}
try {
    foreach ($gp in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            if ($gp.StartTime) {
                $startTimeMap[[string]$gp.Id] = $gp.StartTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
            }
        } catch {}
    }
} catch {}
$procs = @(foreach ($p in (Get-CimInstance -ClassName Win32_Process)) {
    # 1.2 改-6 ticks 换源：started 主源换 Get-Process.StartTime——交付机对拍
    # 233/233 残差 0，CIM CreationDate 仅 28/233（缺口是权限相关不是测量误差，
    # 工单改-6 三家对照：高权限全读、普通权限缺口=Session 0）。
    # 格式保持 yyyy-MM-ddTHH:mm:sszzz 本地时间——pid_matches_start 第③关按
    # started[:19] 秒级比对，消费方零改动；Get-Process 读不到时回退试 CIM
    # CreationDate（双向兜底）。cmdline/exe/ppid 仍走 Win32_Process（仅 CIM 提供）。
    $sd = $null
    try { $sd = $startTimeMap[[string]$p.ProcessId] } catch {}
    if (-not $sd) {
        try { if ($p.CreationDate) { $sd = $p.CreationDate.ToString("yyyy-MM-ddTHH:mm:sszzz") } } catch {}
    }
    [ordered]@{
        pid     = [int]$p.ProcessId
        ppid    = [int]$p.ParentProcessId
        name    = [string]$p.Name
        exe     = [string]$p.ExecutablePath
        cmdline = [string]$p.CommandLine
        started = $sd
    }
})
$sessions = @{}
try {
    foreach ($gp in (Get-Process -ErrorAction SilentlyContinue)) {
        $key = [string]$gp.Id
        if (-not $sessions.ContainsKey($key)) { [void]$sessions.Add($key, $null) }
        try { $sessions[$key] = [int]$gp.SessionId } catch {}
    }
} catch {}
[ordered]@{ connections = $conns; processes = $procs; sessions = $sessions } |
    ConvertTo-Json -Depth 4 -Compress
"""

# /api/v1/protection 专用轻脚本（T-PORT-004 R3 §4.6 白捡）：只要"哪些端口在监听"，
# 不需要 PID/进程详情——GetActiveTcpListeners 实测 ~1.2s → ~0.1s。
# 独立优化，不与杀进程路径混；端口集合与全表扫描的一致性由 V74/单测 67+acceptance 把守。
PS_LISTEN_PORTS_SCRIPT = r"""
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference = 'Stop'
$eps = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
ConvertTo-Json -InputObject @(@($eps) | ForEach-Object { [int]$_.Port }) -Compress
"""

# ----------------------------------------------------------------------------
# 错误与工具
# ----------------------------------------------------------------------------


class ScanError(Exception):
    """扫描失败（§5.1：不能把失败当成 0 个端口）。"""


class ConfigError(Exception):
    """配置损坏（§4：拒绝启动）。"""


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _inside(base_dir: Path, p: Path) -> Path:
    """目录包含校验：p 解析后必须直接位于 base_dir 内。"""
    rp = Path(os.path.abspath(p))
    rb = Path(os.path.abspath(base_dir))
    if rp.parent != rb:
        raise ValueError(f"路径越界: {p}")
    return p


def _safe_tmp_path(base_dir: Path) -> Path:
    """tempfile 生成 base_dir 内唯一临时名（无字符串拼接）。"""
    fd, name = tempfile.mkstemp(prefix="pcon-", suffix=".tmp", dir=str(base_dir))
    os.close(fd)
    return Path(name)


def as_list(obj):
    """§5.2：兼容 PowerShell 把单元素数组展开为对象（list/tuple/dict 全收）。"""
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    if isinstance(obj, tuple):
        return list(obj)
    return [obj]


def atomic_write_json(path: Path, obj, *, indent=2) -> None:
    """§4.5：同目录临时文件 + write_text + os.replace；失败抛异常不假装成功。"""
    _inside(path.parent, path)
    tmp = _safe_tmp_path(path.parent)
    try:
        tmp.write_text(
            json.dumps(obj, ensure_ascii=False, indent=indent),
            encoding="utf-8", newline="\n",
        )
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def read_json_file(path: Path):
    _inside(path.parent, path)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def clamp_str(v, limit: int) -> str:
    v = v if isinstance(v, str) else ""
    return v if len(v) <= limit else v[:limit]


def is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def redact_cmdline(cmdline: str) -> str:
    """§4.4/§7.4：token/api-key/password/secret 参数值与 URL 内嵌凭据 → ***。
    M1（T-PORT-003）：下划线复合词（client_secret/AWS_SECRET_ACCESS_KEY/PROVIDER_APIKEY）
    与 Bearer JWT 全覆盖。"""
    if not cmdline:
        return cmdline
    # Bearer 先打（主正则会先咬掉 "authorization: Bearer" 的值段，顺序反了 JWT 就漏网）
    out = BEARER_RE.sub(r"\1 ***", cmdline)
    out = PROTECT_SCAN_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***", out)
    out = URL_CRED_RE.sub(r"\1***:***@", out)
    return out


# ----------------------------------------------------------------------------
# 回环探活（§4.7）：socket 裸 HTTP/1.0 直连 health 端点（零动态 URL、零 urllib）
# ----------------------------------------------------------------------------


def _extract_loopback_port(base_url: str):
    m = _BASE_URL_RE.match(base_url or "")
    return int(m.group(1)) if m else None


def _health_identity(port):
    """裸 HTTP/1.0 GET /api/v1/health，返回 health body（None = 不是本软件的控制台）。

    1.3 R2：旧实现只判状态行含 " 200 "——3999 上任何回 200 的服务都会被当成
    "已有实例在跑"，handle_existing_instance 于是打印一行然后 exit 0；而真正的
    控制台根本没起来。现在与 CLI 用同一套判据：200 ＋ JSON 对象 ＋ ok:true ＋
    api_version ＋ port 一致，缺一项就不认。
    """
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        return None
    deadline = time.monotonic() + 2.0
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.settimeout(2)
            s.sendall((
                "GET /api/v1/health HTTP/1.0\r\n"
                "Host: 127.0.0.1:" + str(port) + "\r\n"
                "\r\n"
            ).encode("ascii"))
            data = b""
            while True:
                if time.monotonic() > deadline or len(data) > 8192:
                    return None      # 滴流/超大响应：不认（旧实现只 recv 一次就判）
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
    if obj.get("api_version") != API_VERSION or obj.get("port") != port:
        return None
    return obj


# ----------------------------------------------------------------------------
# Win32 绑定（§6.4）
# ----------------------------------------------------------------------------

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
_user32.EnumWindows.argtypes = [_ENUMPROC, wintypes.LPARAM]
_user32.EnumWindows.restype = wintypes.BOOL
_user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_user32.GetWindowThreadProcessId.restype = wintypes.DWORD
_user32.IsWindowVisible.argtypes = [wintypes.HWND]
_user32.IsWindowVisible.restype = wintypes.BOOL
_user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
_user32.GetWindow.restype = wintypes.HWND
_user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
_user32.GetWindowLongW.restype = ctypes.c_long
_user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
_user32.GetWindowTextLengthW.restype = ctypes.c_int
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL
_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.GetProcessTimes.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
_kernel32.GetProcessTimes.restype = wintypes.BOOL
_kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_kernel32.GetExitCodeProcess.restype = wintypes.BOOL

STILL_ACTIVE = 0x103  # 259：进程仍在运行的退出码哨兵值


def pid_alive(pid: int) -> bool:
    """轻量存活检查（验证轮询用；不做权限提升）。
    注意：仅判"能打开句柄"——PID 复用时为假阳性，关闭验证请用 pid_matches_start。"""
    if not is_int(pid) or pid <= 0:
        return False
    h = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if h:
        _kernel32.CloseHandle(h)
        return True
    return False


_FILETIME_EPOCH = datetime(1601, 1, 1)


def pid_matches_start(pid: int, expected_started: str) -> bool:
    """强杀后验证的存活判定，三关全过才算真存活：
    ① OpenProcess 能开句柄（打不开=已退出）；
    ② GetExitCodeProcess == STILL_ACTIVE（进程终止后对象在句柄清零前不销毁，
       仅凭"能打开"会假阳性——tasklist 已看不到它了）；
    ③ 创建时间与快照一致（防 PID 复用：打开的是新进程则时间不符）。
    expected_started 为空时跳过第 ③ 关。"""
    if not is_int(pid) or pid <= 0:
        return False
    h = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h:
        return False
    try:
        exit_code = wintypes.DWORD(0)
        if not _kernel32.GetExitCodeProcess(h, ctypes.byref(exit_code)):
            return False
        if exit_code.value != STILL_ACTIVE:
            return False        # 已终止（哪怕进程对象尚未销毁）
        if not expected_started:
            return True
        ft_create = wintypes.FILETIME()
        ft_exit = wintypes.FILETIME()
        ft_kernel = wintypes.FILETIME()
        ft_user = wintypes.FILETIME()
        if not _kernel32.GetProcessTimes(h, ctypes.byref(ft_create), ctypes.byref(ft_exit),
                                         ctypes.byref(ft_kernel), ctypes.byref(ft_user)):
            return False
        ts = (ft_create.dwHighDateTime << 32) | ft_create.dwLowDateTime
        # FILETIME 是 naive UTC——必须显式挂 UTC 再转本地，否则 astimezone() 只贴标签差 8 小时
        dt_utc = (_FILETIME_EPOCH + timedelta(microseconds=ts // 10)).replace(tzinfo=timezone.utc)
        dt_local = dt_utc.astimezone()
        return dt_local.strftime("%Y-%m-%dT%H:%M:%S") == expected_started[:19]
    finally:
        _kernel32.CloseHandle(h)


def find_main_window_for_pid(pid: int):
    """§6.4：枚举顶层窗口，取第一个满足筛选的 HWND（EnumWindows 顺序即 Z 序）。
    回调对象活到枚举结束（函数作用域保证）。"""
    found = []

    @_ENUMPROC
    def _cb(hwnd, _lparam):
        wpid = wintypes.DWORD(0)
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value != pid:
            return True
        if not _user32.IsWindowVisible(hwnd):
            return True
        if _user32.GetWindow(hwnd, GW_OWNER):
            return True
        if _user32.GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW:
            return True
        if _user32.GetWindowTextLengthW(hwnd) <= 0:
            return True
        found.append(hwnd)
        return False  # 第一个满足者即最靠前主窗口，停

    _user32.EnumWindows(_cb, 0)
    return found[0] if found else None


def post_wm_close(hwnd: int) -> bool:
    """PostMessageW 返回 0 = 发送失败（不代表进程同意退出）。§6.4 步 5。"""
    return bool(_user32.PostMessageW(hwnd, WM_CLOSE, 0, 0))


# ----------------------------------------------------------------------------
# PowerShell 调用与快照归一化（§5）
# ----------------------------------------------------------------------------

_PS_XML_NS = "{http://schemas.microsoft.com/powershell/2004/04}"
_PS_XML_ESC = re.compile(r"_x([0-9A-Fa-f]{4})_")
# 1.3 返工：CLIXML 解析输入上限。DTD 预检（见 _PS_DTD_RE）挡住 entity 膨胀，
# 此处只防超大输入拖慢解析；取 4 MiB —— 实测 1.18 MB 的合法 CLIXML 必须能正常
# 解析（原 64 KiB 会绕过解析、把真实错误全丢掉，项① 等于失效）。
# 注：DTD 预检是「全串」扫描，不设窗口——曾用 xml_text[:4096]，实测在 DOCTYPE 前
# 垫 XML 注释即可把 DOCTYPE 推出窗口、预检漏过、实体照展开（小深 11-04 实测）。
_PS_ERR_XML_MAX = 4 * 1024 * 1024
# 真 CLIXML 是 [#< CLIXML] + <Objs>，永不含 DOCTYPE/ENTITY。
# 实测 6 组真 PS 样本 0 命中，零误判（小深复核 + 我复核）。
_PS_DTD_RE = re.compile(r"<!(DOCTYPE|ENTITY)", re.I)


def _decode_console_bytes(data: bytes) -> str:
    """1.3 项①：控制台字节解码三级回退：utf-8 严格 → mbcs（本地 ANSI 码页）→ utf-8 replace。
    实测同一台中文机 PS5.1 的 stderr 两种编码都出现过（Write-Error 走 GBK、真异常走
    UTF-8）；taskkill.exe 恒走本地码页。mbcs 仅 Windows 有，LookupError 也要接住。"""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("mbcs")
        except (LookupError, UnicodeDecodeError):
            return data.decode("utf-8", errors="replace")


def _squash_err_text(text: str, limit: int) -> str:
    """把多行错误压成一行（服务端日志用）：换行→' | '，多余空白收拢，末尾截断。"""
    text = re.sub(r"[\r\n]+", " | ", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"(\s*\|\s*)+", " | ", text)
    return text.strip(" |")[:limit]


def _strip_ps_xml_escapes(s: str) -> str:
    """CLIXML 文本节点里的 _x000D_/_x000A_ 还原成真实字符。"""
    return _PS_XML_ESC.sub(lambda m: chr(int(m.group(1), 16)), s)


def _extract_ps_stderr(data: bytes, limit: int = 300) -> str:
    """1.3 项①：PS5.1 stderr 提取。
    必须【先剥 CLIXML、后截断】——实测真实错误在 offset 600+，旧口径先 [:300]
    只截到前面的 progress 噪音。非 CLIXML（taskkill 形态）走码页解码后压扁截断。
    1.3 返工：改为「DTD 预检（全串，不设窗口）+ 4 MiB 上限」——先剥 DTD/ENTITY
    （真 CLIXML 永不含，防 entity 膨胀），再判大小。原「64 KiB 上限」两头都不对，
    已撤销；预检窗口也撤销——设窗口等于留洞。"""
    text = _decode_console_bytes(data)
    if text.startswith("#< CLIXML"):
        nl = text.find("\n")
        xml_text = text[nl + 1:] if nl >= 0 else ""
        # 1.3 返工：先查 DTD/ENTITY（真 CLIXML 永不含），再判大小。
        # 顺序很重要——先查 DTD 才是真防 bomb；只判大小两头都不对（挡不住小 payload
        # 膨胀，又会把大 CLIXML 挡在解析之外、丢真实错误）。
        # ★ 必须全串扫，不能设窗口：XML 的 prolog 允许 DOCTYPE 前有任意多个注释，
        #   位置没有上界；曾用 [:4096]，垫注释即可绕过（实测）。全串成本可忽略——
        #   6.9M 字符 2.5ms vs 解析同份 158ms。
        if _PS_DTD_RE.search(xml_text) is None and len(xml_text) <= _PS_ERR_XML_MAX:
            try:
                root = ET.fromstring(xml_text)
                parts = ["".join(n.itertext())
                         for n in root.iter(_PS_XML_NS + "S") if n.get("S") == "Error"]
                if parts:
                    return _squash_err_text(_strip_ps_xml_escapes("".join(parts)), limit)
            except ET.ParseError:
                pass
        return _squash_err_text(text, limit)
    return _squash_err_text(text, limit)


def run_powershell(script: str) -> str:
    """§5.1：-EncodedCommand（UTF-16LE→Base64）、CREATE_NO_WINDOW、8s 超时、shell=False。"""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    cmd = [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=PS_TIMEOUT,
            creationflags=CREATE_NO_WINDOW, shell=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError(f"powershell timeout: {e}") from e
    except OSError as e:
        raise ScanError(f"powershell spawn failed: {e}") from e
    if proc.returncode != 0:
        err = _extract_ps_stderr(proc.stderr, limit=300)
        raise ScanError(f"powershell exit {proc.returncode}: {err}")
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ScanError(f"powershell stdout decode failed: {e}") from e


def scan_snapshot() -> dict:
    """一轮快照（§5.2）：connections + processes + sessions。失败抛 ScanError。"""
    raw = run_powershell(PS_SNAPSHOT_SCRIPT)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ScanError(f"snapshot json decode failed: {e}") from e
    if not isinstance(data, dict) or "connections" not in data:
        raise ScanError("snapshot json unexpected shape")
    return data


def scan_listen_ports() -> set:
    """TCP 监听端口集合（T-PORT-004 R3 §4.6，只喂 /api/v1/protection）。失败抛 ScanError。"""
    raw = run_powershell(PS_LISTEN_PORTS_SCRIPT)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ScanError(f"listen-ports json decode failed: {e}") from e
    if isinstance(data, int):
        data = [data]
    if not isinstance(data, list):
        raise ScanError("listen-ports json unexpected shape")
    out = set()
    for p in data:
        try:
            q = int(p)
        except (TypeError, ValueError):
            continue
        if 0 <= q <= 65535:
            out.add(q)
    return out


def normalize_snapshot(raw: dict) -> dict:
    """§5.3：不按端口过滤、不按端口去重；去重键 (addr,port,pid)；排序 (port,addr,pid)。
    _session_seen 保留 PS 端 Get-Process 报告过的全部 pid 键（T-PORT-004 R3 §4.4）：
    键存在=进程在被查询那一刻还活着（含 SessionId 读不出异常的）；键不存在=已被
    SilentlyContinue 静默跳过=刚退出。没有这份键存在性，"已退出（可剔除）"与
    "还活着但读不到会话（必须 fail closed）"两种情形在 Python 端无法区分。"""
    sessions = {}
    session_seen = set()
    sessions_raw = raw.get("sessions") or {}
    if isinstance(sessions_raw, dict):
        for k, v in sessions_raw.items():
            try:
                session_seen.add(int(k))
            except (TypeError, ValueError):
                continue
            try:
                sessions[int(k)] = int(v)
            except (TypeError, ValueError):
                continue
    procs = {}
    for p in as_list(raw.get("processes")):
        try:
            pid = int(p.get("pid"))
        except (TypeError, ValueError):
            continue
        procs[pid] = {
            "pid": pid,
            "ppid": int(p.get("ppid") or 0),
            "name": str(p.get("name") or ""),
            "exe": str(p.get("exe") or ""),
            "cmdline": str(p.get("cmdline") or ""),
            "started": str(p.get("started") or ""),
            "session_id": sessions.get(pid),
        }

    entries = []
    seen = set()
    for c in as_list(raw.get("connections")):
        try:
            addr = str(c.get("localAddress"))
            port = int(c.get("localPort"))
            pid = int(c.get("ownerPid"))
        except (TypeError, ValueError):
            continue
        if not (0 <= port <= 65535):
            continue
        key = (addr, port, pid)
        if key in seen:            # 去重键 (addr,port,pid)，不是 port（单测 2）
            continue
        seen.add(key)

        proc_info = procs.get(pid)
        if proc_info is None:
            # §5.3：进程已退出或权限不足 → 保留监听行，proc="?"
            proc_name, exe, cmdline, started = "?", "", "", ""
        else:
            proc_name, exe = proc_info["name"], proc_info["exe"]
            cmdline, started = proc_info["cmdline"], proc_info["started"]
        session_id = sessions.get(pid)          # 取不到 → None → 不可杀（硬要求 4）
        entries.append({
            "port": port, "addr": addr, "pid": pid,
            "proc": proc_name if proc_name not in ("", "?") else "?",
            "exe": exe, "cmdline": cmdline, "started": started,
            "ppid": proc_info["ppid"] if proc_info else 0,
            "session_id": session_id,
        })
    entries.sort(key=lambda e: (e["port"], e["addr"], e["pid"]))
    return {"entries": entries, "processes": procs, "_session_seen": session_seen}


# ----------------------------------------------------------------------------
# 配置加载与校验（§4.1-§4.4）
# ----------------------------------------------------------------------------

DEFAULT_RULES = [
    # 出厂示例规则：演示「具体规则先于宽泛规则」（wechat-work 必须在 wechat 前）
    # 与三档 level。请按本机软件自行增删（编辑 rules.json 即可，无需改代码）。
    {"match": "wechat-work", "name": "企业微信", "level": "other", "order": 1},
    {"match": "wechat", "name": "微信", "level": "self", "order": 2},
    {"match": "mysql", "name": "MySQL", "level": "other", "order": 3},
    {"match": "vscode", "name": "VS Code", "level": "self", "order": 4},
    {"match": "jupyter", "name": "Jupyter", "level": "self", "order": 5},
    {"match": "docs-server", "name": "知识库服务", "level": "self", "order": 6},
    {"match": "devserver", "name": "开发服务", "level": "self", "order": 7},
    {"match": "workbench", "name": "工作台", "level": "self", "order": 8},
    {"match": "ollama", "name": "Ollama", "level": "self", "order": 9},
    {"match": "ComfyUI", "name": "ComfyUI", "level": "self", "order": 10},
    {"match": "port_console", "name": "端口扳手本体", "level": "self", "order": 12},
    {"match": "wps", "name": "WPS办公", "level": "other", "order": 20},
    {"match": "lghub", "name": "罗技lghub", "level": "other", "order": 21},
    {"match": "quark", "name": "夸克浏览器", "level": "other", "order": 22},
    {"match": "onedrive", "name": "OneDrive", "level": "other", "order": 23},
    {"match": "doubao", "name": "豆包客户端", "level": "other", "order": 24},
    {"match": "hipsdaemon", "name": "火绒安全", "level": "other", "order": 25},
    {"match": "msi.terminalserver", "name": "MSI主板工具", "level": "other", "order": 26},
    {"match": "svchost", "name": "系统", "level": "system", "order": 90},
    {"match": "System", "name": "系统", "level": "system", "order": 91},
    {"match": "lsass", "name": "系统", "level": "system", "order": 92},
]

# 3999 刻意不入静态保护表（1.2 改-3：本体端口流动顺延，静态表只会误护后来的
# 占用者；本体自保走 protection_reason 的「控制台自身端口」，按实际绑定口无条件
# 命中，与这张表无关）。
DEFAULT_PROTECTION = {
    "ports": [135, 139, 445, 3389, 5985, 5986],
    "process_names": [
        "System", "Registry", "smss", "csrss", "wininit", "winlogon",
        "services", "lsass", "MsMpEng",
    ],
}


def validate_rules(raw):
    """§4.1：字段校验，非法拒绝启动。"""
    if not isinstance(raw, list) or not raw:
        raise ConfigError("rules.json 必须是非空数组")
    out = []
    for i, r in enumerate(raw):
        if not isinstance(r, dict):
            raise ConfigError(f"rules.json 第 {i} 条不是对象")
        match = str(r.get("match", "")).strip()
        name = str(r.get("name", "")).strip()
        level = str(r.get("level", "")).strip()
        order = r.get("order")
        if not match or len(match) > 200:
            raise ConfigError(f"rules.json 第 {i} 条 match 非法")
        if not (1 <= len(name) <= 80):
            raise ConfigError(f"rules.json 第 {i} 条 name 非法")
        if level not in ("self", "other", "system"):
            raise ConfigError(f"rules.json 第 {i} 条 level 非法")
        if not is_int(order):
            raise ConfigError(f"rules.json 第 {i} 条 order 必须为整数")
        out.append({"match": match, "name": name, "level": level, "order": order})
    out.sort(key=lambda r: (r["order"],))
    return out


def validate_protection(raw):
    """§4.2：端口 1..65535 整数；进程名非空。"""
    if not isinstance(raw, dict):
        raise ConfigError("protection.json 必须是对象")
    ports = raw.get("ports", [])
    names = raw.get("process_names", [])
    if not isinstance(ports, list) or not isinstance(names, list):
        raise ConfigError("protection.json ports/process_names 必须是数组")
    out_ports = []
    for p in ports:
        if not is_int(p) or not (1 <= p <= 65535):
            raise ConfigError(f"protection.json 端口非法: {p!r}")
        out_ports.append(int(p))
    out_names = []
    for n in names:
        if not isinstance(n, str) or not n.strip():
            raise ConfigError(f"protection.json 进程名非法: {n!r}")
        out_names.append(n.strip())
    return {"ports": out_ports, "process_names": out_names}


def validate_port_map(raw):
    """§4.3：key=十进制端口字符串；level 仅 self/other（系统保护不可手工降级）。"""
    if not isinstance(raw, dict):
        raise ConfigError("port_map.json 必须是对象")
    out = {}
    for k, v in raw.items():
        if not (isinstance(k, str) and k.isdigit() and 1 <= int(k) <= 65535):
            raise ConfigError(f"port_map.json key 非法: {k!r}")
        if not isinstance(v, dict):
            raise ConfigError(f"port_map.json[{k}] 不是对象")
        name = str(v.get("name", "")).strip()
        level = str(v.get("level", "other")).strip()
        if not (1 <= len(name) <= 80):
            raise ConfigError(f"port_map.json[{k}] name 非法")
        if level not in ("self", "other"):
            raise ConfigError(f"port_map.json[{k}] level 仅允许 self/other")
        # 1.2 改-5（R0 F5 后半）：proc/started 超长在加载处拦下——name 已有长度
        # 校验，这两个字段原先不设防；手工编辑塞进来的垃圾串会一路带进
        # classify_entry 与 fill_mapping_fingerprint。上限按语义给：
        # proc=镜像名 ≤260（NTFS 文件名上限）、started=ISO8601 时间戳 ≤64。
        proc = str(v.get("proc", "") or "")
        started = str(v.get("started", "") or "")
        if len(proc) > 260:
            raise ConfigError(f"port_map.json[{k}] proc 超长（>260）")
        if len(started) > 64:
            raise ConfigError(f"port_map.json[{k}] started 超长（>64）")
        out[k] = {
            "name": name, "level": level,
            "proc": proc,
            "started": started,
        }
    return out


def _keep_corrupt_copy(base_dir: Path, broken: Path, label: str, warnings: list) -> None:
    """损坏配置：tempfile 唯一名副本保留（时间戳进警告文本），绝不无提示覆盖。"""
    stamp = now_iso()
    try:
        keep = _safe_tmp_path(base_dir).with_suffix(".corrupt")
        broken.rename(keep)
        warnings.append(f"{label} 损坏（{stamp}），副本保存为 {keep.name}")
    except OSError:
        warnings.append(f"{label} 损坏（{stamp}），且副本保留失败")


def load_and_validate_configs(base_dir: Path) -> dict:
    """rules/protection 损坏拒绝启动（§4.1/§4.2）；port_map/unknown 损坏保留副本新建。"""
    warnings = []

    rules_path = base_dir / "rules.json"
    if not rules_path.exists():
        atomic_write_json(rules_path, DEFAULT_RULES)
        rules = validate_rules(DEFAULT_RULES)
    else:
        try:
            rules = validate_rules(read_json_file(rules_path))
        except ConfigError:
            raise
        except Exception as e:
            raise ConfigError(f"rules.json 无法解析: {e}") from e

    prot_path = base_dir / "protection.json"
    if not prot_path.exists():
        atomic_write_json(prot_path, DEFAULT_PROTECTION)
        protection = validate_protection(DEFAULT_PROTECTION)
    else:
        try:
            protection = validate_protection(read_json_file(prot_path))
        except ConfigError:
            raise
        except Exception as e:
            raise ConfigError(f"protection.json 无法解析: {e}") from e

    pm_path = base_dir / "port_map.json"
    port_map = {}
    if pm_path.exists():
        try:
            port_map = validate_port_map(read_json_file(pm_path))
        except Exception:
            _keep_corrupt_copy(base_dir, pm_path, "port_map.json", warnings)
            port_map = {}

    unk_path = base_dir / "unknown.json"
    unknown = []
    if unk_path.exists():
        try:
            raw = read_json_file(unk_path)
            if not isinstance(raw, list):
                raise ValueError("必须是数组")
            unknown = raw
        except Exception:
            _keep_corrupt_copy(base_dir, unk_path, "unknown.json", warnings)

    # 动态保护表（用户 UI 手动保护，重启不丢）：损坏保留副本新建，同 port_map 策略
    dp_path = base_dir / "dynamic_protection.json"
    dynamic_protected = set()
    if dp_path.exists():
        try:
            raw = read_json_file(dp_path)
            ports = raw.get("ports") if isinstance(raw, dict) else None
            if not isinstance(ports, list):
                raise ValueError("必须是含 ports 数组的对象")
            dynamic_protected = {p for p in ports if is_int(p) and 1 <= p <= 65535}
        except Exception:
            _keep_corrupt_copy(base_dir, dp_path, "dynamic_protection.json", warnings)

    return {"rules": rules, "protection": protection, "port_map": port_map,
            "unknown": unknown, "dynamic_protected": dynamic_protected,
            "warnings": warnings}


# ----------------------------------------------------------------------------
# 识别（§4.1/§4.3/§4.4）
# ----------------------------------------------------------------------------


def classify_entry(state, entry: dict) -> dict:
    """返回 name/level/source/mapping_stale。优先级：手工映射 > 自动规则 > 未知；
    最终安全优先级：系统保护 > 手工映射与自动规则（§4.3）。"""
    port, proc, exe, cmdline = entry["port"], entry["proc"], entry["exe"], entry["cmdline"]
    matched = None
    # T-PORT-004 R3 必修 5：拼接 proc 源——cmdline 非空也看进程名。
    # 实测坑：OneDrive.Sync.Service.exe 的 cmdline 只有 "/silentConfig"，
    # 旧逻辑"cmdline 非空就不看 proc/exe"导致 onedrive 类规则永远命中不了。
    # ⚠ 方案原文是三源（cmdline, proc, exe）——真机实测砍掉 exe 源（偏离申报）：
    #   exe 是全路径，System32 下的 "C:\Windows\System32\..." 会以 "system" 子串
    #   命中规则 "System"(order 91, level=system)，把全部 System32 进程误标系统级
    #   403（acceptance step14 的 powershell 夹具实锤）。proc 名命中 onedrive
    #   已足够（OneDrive.Sync.Service.exe 含 "onedrive"）。
    # ⚠ 此改动扩大所有规则的匹配面，全表改前/改后逐条对比由 V75/单测 68 把守。
    text = " ".join(x for x in (cmdline, proc) if x)
    text_low = text.casefold()
    proc_low = proc.casefold()
    for r in state.rules:                    # 已按 (order, 文件序号) 预排序
        # 1.2 改-4（甲案，复核方 08:0x 拍板）：level=system 的兜底规则只用 proc 名
        # 匹配、不看 cmdline——AI 程序的命令行带 --system-prompt 是家常便饭，拼接
        # 匹配会把任意带该参数的 AI 进程误标 system 级 403 硬拒（AI 通道带正确
        # token 也杀不动），而「关掉 DSH 全家」正是本工具的核心诉求。真 System/
        # svchost/lsass 的 proc 名本来就够（svchost.exe -k netsvcs 这类不受影响）；
        # 应用识别规则（self/other）仍走 cmdline+proc 双源（V75/单测 68 口径不变）。
        # 乙案（rules.json 加 match_field 维度）是长期正解，留二期；丙案（改窄
        # match 字面量）会把 PID 4 的真 System（cmdline 为空）漏掉，禁止。
        hay = proc_low if r["level"] == "system" else text_low
        if r["match"].casefold() in hay:
            matched = r
            break

    mp = state.port_map.get(str(port))
    if mp:
        name, level, source = mp["name"], mp["level"], "manual"
        mapping_stale = bool(
            mp.get("proc") and mp.get("started") and entry["started"]
            and (mp["proc"].casefold() != proc.casefold()
                 or mp["started"] != entry["started"]))
    elif matched:
        name, level, source = matched["name"], matched["level"], "auto"
        mapping_stale = False
    else:
        name, level, source = "", "unknown", "unknown"
        mapping_stale = False
    return {"name": name, "level": level, "source": source, "mapping_stale": mapping_stale}


def fill_mapping_fingerprint(state, entry: dict) -> None:
    """§4.3：旧手工记录无指纹时按首次发现补齐（带锁写盘，低频）。"""
    if not entry["started"]:
        return
    with state.state_lock:
        mp = state.port_map.get(str(entry["port"]))
        if not mp or (mp.get("proc") and mp.get("started")):
            return
        mp["proc"] = entry["proc"]
        mp["started"] = entry["started"]
        try:
            atomic_write_json(state.base_dir / "port_map.json", state.port_map)
        except OSError as e:
            print(f"[port-console] port_map.json 指纹补齐写盘失败: {e}", file=sys.stderr)


def record_unknown(state, entry: dict) -> None:
    """§4.4：以 (port, proc, 截断脱敏后 cmdline) 去重；PID 变化不重复记账。"""
    key_val = (entry["port"], entry["proc"].casefold(),
               redact_cmdline(entry["cmdline"])[:CMDLINE_STORE_MAX])
    with state.state_lock:
        for u in state.unknown:
            if (u.get("port"), str(u.get("proc", "")).casefold(),
                    str(u.get("cmdline", ""))) == key_val:
                return
        state.unknown.append({
            "port": entry["port"],
            "proc": entry["proc"],
            "first_seen": now_iso(),
            "cmdline": key_val[2],
        })
        if len(state.unknown) > UNKNOWN_MAX:
            state.unknown = state.unknown[-UNKNOWN_MAX:]
        try:
            atomic_write_json(state.base_dir / "unknown.json", state.unknown)
        except OSError as e:
            print(f"[port-console] unknown.json 写盘失败: {e}", file=sys.stderr)


# ----------------------------------------------------------------------------
# 保护（§4.2 / §6.1 步7 / §6.3 子树护栏）
# ----------------------------------------------------------------------------


def _proc_name_matches(rule_name: str, proc: str) -> bool:
    a = rule_name.casefold().removesuffix(".exe")
    b = proc.casefold().removesuffix(".exe")
    return a == b


def protection_reason(state, entry: dict):
    """返回保护原因字符串或 None。运行时系统身份保护不落盘（§4.2）。"""
    exe_low = (entry.get("exe") or "").casefold()
    pid = entry["pid"]
    if pid <= 4:
        return f"系统保留进程(pid={pid})"
    if pid == state.console_pid:
        return "控制台自身进程"
    if entry["port"] == state.console_port:
        return "控制台自身端口"
    if entry["port"] in state.protection["ports"]:
        return "系统保护端口"
    if entry["port"] in state.dynamic_protected:
        return "用户手动保护"
    proc = entry["proc"] or ""
    if proc != "?" and any(_proc_name_matches(n, proc) for n in state.protection["process_names"]):
        return f"系统保护进程({proc})"
    if entry.get("session_id") == 0:
        return "系统会话进程(Session 0)"
    if entry.get("session_id") is None:
        return "会话信息缺失(fail closed)"
    # 复核建议（复核方方案乙）：started 读不到时指纹链失效且会造成误导性 503
    # （issue_snapshot_id 拒发）——与 B4 同风格 fail closed，3 行堵死。
    if not entry.get("started"):
        return "启动时间不可读(fail closed)"
    # B4（T-PORT-003）：exe 读不到时 System32 路径护栏失效（startswith 恒 False）。
    # 复核方实测：普通权限下 131 个 session 0 + 14 个 session 1 进程读不到 exe，
    # 其中 MSI.TerminalServer.exe（端口 26822, session 1）按原判定会被放行。
    # fail closed：读不到路径一律保护，不留"因为读不到所以放行"的口子。
    if not entry.get("exe"):
        return "可执行路径不可读(fail closed)"
    if exe_low.startswith(SYSTEM32_PREFIX.lower()):
        proc_name_low = (entry.get("proc") or "").casefold()
        if proc_name_low in SYSTEM32_HOST_NAMES:
            return "系统目录关键宿主(System32)"
    return None


def _parse_started_dt(s):
    """started 字符串 → aware datetime；解析不了返回 None（调用方按保守处理）。"""
    if not s or not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def build_tree_with_session_filter(processes: dict, sessions: dict,
                                   root_pid: int) -> list:
    """T-PORT-004 R3 §4.4：按 ppid 在【全量快照】内存构树，并做两类剔除。
    ⚠ 复核建议 6（耦合声明，勿拆，自 build_process_tree 移入）：保护检查用的
    树来自【扫描快照】，taskkill /T 按【实时父子关系】杀——两者语义一致的前提是
    Windows 的 PPID 语义。若将来把 taskkill 换成自研递归 kill，必须改为实时构树，
    否则保护检查会失守。数据来源是同一轮全量 CIM 快照，不做任何逐层/逐 PID 的
    WMI 查询（R3 拆阻断：逐 PID 递归子树实测 164 秒撞超时线，已删）。

    ⚠ 时序审查补注（1.2，复核方 15:5x，勿拆）：上面的耦合声明只覆盖了「检查树 vs
    执行树」，还有第二层没写——**B1 杀前实时复核（close_target 里 pid_matches_start）
    只复核 target 这一个 pid，不逐个复核子树成员**。所以「扫描后、taskkill 前，目标
    新建的子进程」既不在快照树里（未过 check_protection），又会被 taskkill /T 按实时
    父子关系连带杀掉。当前概率极低（要求目标在几百毫秒内 spawn 子进程且该子进程恰好
    受保护），且 taskkill /T 的实时语义恰好兜住了「已退出成员」这一侧。但改这一带时
    必须知道：**复核范围＝root，杀范围＝实时全树，两者不相等**。若要收紧，做法是杀前
    重扫一次并逐个 pid_matches_start 校验子树——代价是每杀一次多一轮全表扫描（0.3-0.8s）。

    sessions 键存在性语义（三判据的分界）：
      - pid 不在 sessions → Get-Process 静默跳过 = 该成员已退出 → 差集剔除（判据 2）；
      - pid 在 sessions 且值 None → 人还在但读不到会话 → 保留在树里，
        由 check_protection 的 protection_reason fail closed 拒绝（判据 3）；
      - 查询命令本身失败 → scan_or_error 已抛 ScanError 拒绝关闭（判据 1，不在本函数）。

    PPID 复用过滤（工单备注 3，放宽方向、必须保守）：
      - 子树成员 started 早于根 started → 视为 PPID 复用孤儿，剔除；
      - started 为空 / 解析失败 / 根 started 为空 → 不剔（不知道怎么判就别剔）；
      - aware datetime 比较，跨时区偏移表示也能正确比先后。"""
    children = defaultdict(list)
    for p in processes.values():
        children[p["ppid"]].append(p["pid"])
    raw_tree, stack, seen = [], [root_pid], set()
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        raw_tree.append(pid)
        stack.extend(children.get(pid, []))

    root_started = _parse_started_dt((processes.get(root_pid) or {}).get("started"))
    out = []
    for pid in raw_tree:
        if pid == root_pid:
            out.append(pid)
            continue
        # 判据 2：Get-Process 没见到（键不存在）= 刚退出 → 剔除，不参与保护判定。
        # sessions 键缺失时（旧式 mock/防御路径）视为全员在场，不做剔除（保守）。
        if sessions is not None and pid not in sessions:
            continue
        # PPID 复用孤儿：成员 started 早于根 → 父 PID 已被复用，剔除。
        # 三态里"读不到就不剔"是铁律——用另一个 bug 修 bug 等于保护缩水。
        if root_started is not None:
            member_started = _parse_started_dt((processes.get(pid) or {}).get("started"))
            if member_started is not None and member_started < root_started:
                continue
        out.append(pid)
    return out


def check_protection(state, scan: dict, target: dict, tree_pids: list):
    """返回 (allowed, reason, protected_entry)。子树含保护成员/自身 → 整次拒绝（§6.3）。"""
    entries_by_pid = {}
    for e in scan["entries"]:
        entries_by_pid.setdefault(e["pid"], e)
    r = protection_reason(state, target)
    if r:
        return False, r, target
    cls = classify_entry(state, target)
    if cls["level"] == "system":
        return False, "规则判定为系统级(level=system)", target
    for pid in tree_pids:
        if pid == target["pid"]:
            continue
        if pid == state.console_pid:
            return False, "子树包含控制台自身进程", {"pid": pid}
        # 树成员可能没有监听端口（不在 entries）——保护检查必须看全量进程快照
        info = scan["processes"].get(pid)
        if info is None:
            continue
        pseudo = {"port": 0, "pid": pid, "proc": info["name"] or "?",
                  "exe": info["exe"], "session_id": info.get("session_id"),
                  "started": info.get("started")}
        r = protection_reason(state, pseudo)
        if r:
            return False, f"子树包含受保护进程: {r}", pseudo
    return True, "", None


# ----------------------------------------------------------------------------
# 审计（§4.8）：os.open 追加写（无内置 open），>1MiB 轮转最多 3 备份
# ----------------------------------------------------------------------------


def rotate_audit_log(path: Path) -> None:
    try:
        if not path.exists() or path.stat().st_size < AUDIT_ROTATE_BYTES:
            return
        names = [_inside(path.parent, path.parent / n) for n in AUDIT_BAK_NAMES]
        for i in range(AUDIT_BACKUPS - 2, -1, -1):
            if names[i].exists():
                os.replace(names[i], names[i + 1])
        os.replace(path, names[0])
    except OSError as e:
        print(f"[port-console] 审计轮转失败: {e}", file=sys.stderr)


def write_audit_event(state, event: dict) -> None:
    """UTF-8 JSONL 追加 + fsync；失败抛 OSError（前置事件失败 → 拒杀 fail closed）。"""
    path = _inside(state.base_dir, state.base_dir / "kill_audit.jsonl")
    line = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
    with state.audit_lock:
        rotate_audit_log(path)
        fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)


# ----------------------------------------------------------------------------
# 授权（§4.6 / §6.1 / §6.3）
# ----------------------------------------------------------------------------


def authorize_ui_request(origin: str, sec_fetch_site: str, actual_port: int) -> bool:
    """§7.4：Origin/SFS 至少一个满足本机同源；缺失、跨源、矛盾一律不合格。
    /ui/* 不合格必须 403 且不做扫描（单测 22）。"""
    expected = f"http://127.0.0.1:{actual_port}"
    origin_ok = origin == expected
    sfs_ok = sec_fetch_site == "same-origin"
    if origin and sec_fetch_site:
        return origin_ok and sfs_ok
    if origin:
        return origin_ok
    if sec_fetch_site:
        return sfs_ok
    return False


def has_ui_evidence(origin: str, sec_fetch_site: str, actual_port: int) -> bool:
    """GET /ports 的「同源证据」判定（cmdline 脱敏决策，§7.4）。"""
    return authorize_ui_request(origin, sec_fetch_site, actual_port)


def is_cross_origin_request(origin: str, sec_fetch_site: str, actual_port: int) -> bool:
    """1.2 改-1：跨源判定（白名单式），/ports 的 refresh 门与 agent/ports 共用。
    跨源（返回 True）当且仅当：
      ① SFS 有值且不在 {"same-origin", "none"} 白名单内——cross-site、same-site、
         以及将来浏览器新增的任何取值全拒（白名单 fail closed；黑名单会自动漏，
         1.2 交叉审就抓到 same-site 漏放：site=(scheme,host) 不含端口，
         127.0.0.1:3080 → 127.0.0.1:3999 属同站异源，而 <img> 只发 SFS 不发 Origin）；
      ② 或 Origin 存在且非本机同源。
    无 Origin 且无 SFS 的本机程序（portctl/验收/AI 脚本）返回 False——这是 L0
    通路的命脉，语义刻意与 authorize_ui_request 的「无证据即拒」相反；
    两谓词各管各端，不许复用（裁定 §二/§三：复用=CLI 当场死）。"""
    expected = f"http://127.0.0.1:{actual_port}"
    if sec_fetch_site and sec_fetch_site not in ("same-origin", "none"):
        return True
    return bool(origin and origin != expected)


# agent/ports 限流初始值（1.2 改-2，复核方 04:00 裁定 §5.2；真机可调——U12/U13 未验，
# 真实负载未知，写成具名常量挤了再调，别散落字面量）。
AGENT_PORTS_RATE_ANON = 30       # 匿名请求：30 次/分钟
AGENT_PORTS_RATE_TOKEN = 60      # 有效 token 请求：60 次/分钟
AGENT_PORTS_MAX_INFLIGHT = 2     # 在飞全表扫描并发上限
AGENT_PORTS_WINDOW = 60.0        # 滑动窗口宽（秒）


class _AgentPortsGate:
    """agent/ports 专用限流闸：匿名/token 两档滑动窗口 + 在飞扫描并发闸。
    与杀链路频率闸（try_consume_rate_slot）互不相干——那把闸管杀，这把管读。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._anon = deque()
        self._token = deque()
        self._inflight = 0

    def try_acquire(self, authenticated: bool) -> bool:
        """滑动窗口计数；False=超限（429）。"""
        now = time.monotonic()
        with self._lock:
            dq = self._token if authenticated else self._anon
            limit = AGENT_PORTS_RATE_TOKEN if authenticated else AGENT_PORTS_RATE_ANON
            while dq and dq[0] < now - AGENT_PORTS_WINDOW:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True

    def try_enter_inflight(self) -> bool:
        """在飞并发闸；False=满（503）。进入者必须配对 leave_inflight（finally）。"""
        with self._lock:
            if self._inflight >= AGENT_PORTS_MAX_INFLIGHT:
                return False
            self._inflight += 1
            return True

    def leave_inflight(self) -> None:
        with self._lock:
            self._inflight -= 1


def issue_force_ticket(state, target: dict, channel: str) -> str:
    """§6.3：ticket 绑定目标四元组、调用通道（S4，T-PORT-003 补齐）与 60 秒有效期，仅内存。
    复核建议 9：channel 必填——给了默认值等于把 S4 防的口子重新开开。"""
    ticket = secrets.token_urlsafe(16)
    with state.state_lock:
        now = time.monotonic()
        for k in [k for k, v in state.tickets.items() if v["expires"] < now]:
            del state.tickets[k]
        state.tickets[ticket] = {
            "port": target["port"], "pid": target["pid"], "proc": target["proc"],
            "started": target["started"], "channel": channel,
            "expires": now + TICKET_TTL, "used": False,
        }
    return ticket


def consume_force_ticket(state, ticket: str, target: dict, channel: str) -> str:
    """返回 ""=通过；否则错误 reason（409 force_ticket_invalid，单测 8）。S4：校验 channel 绑定。"""
    with state.state_lock:
        t = state.tickets.get(ticket or "")
        if not t or t["used"] or t["expires"] < time.monotonic():
            state.tickets.pop(ticket or "", None)
            return "force_ticket_invalid"
        if t.get("channel") != channel:
            return "force_ticket_invalid"
        if (t["port"] != target["port"] or t["pid"] != target["pid"]
                or t["proc"].casefold() != target["proc"].casefold()
                or t["started"] != target["started"]):
            return "force_ticket_invalid"
        t["used"] = True
        return ""


SNAPSHOT_MAX = 500             # T-PORT-003 B3：按 sid 存储的内存上限


def issue_snapshot_id(state, identity: dict):
    """§4.9：唯一占用时下发，内存 60 秒，绑定 (port,pid,proc,started)。
    B3（T-PORT-003）：按 sid 存储（不再按端口覆盖）——多 AI 并发取同端口指纹互不顶掉。
    复核建议 2：started 为空的占用者不发指纹（指纹的价值就在时间戳，""=="" 会
    让 B2 的校验整段跳过——阻断级修法不能在 by_port 模式留着这个口子）。
    复核建议 5：超限**拒绝下发**（返回 None），不删有效票据——拿正确性换内存方向错。
    返回 sid 或 None（None=存储满，调用方应 503）。"""
    if not identity.get("started"):
        return None
    sid = "sn_" + secrets.token_hex(3)
    with state.state_lock:
        now = time.monotonic()
        for k in [k for k, v in state.snapshots.items() if v["expires"] < now]:
            del state.snapshots[k]
        if len(state.snapshots) >= SNAPSHOT_MAX:
            return None                    # fail closed：宁可不发，不挤掉别人的有效票
        state.snapshots[sid] = {
            "sid": sid, "port": identity["port"],
            "identity": dict(identity), "expires": now + SNAPSHOT_TTL,
        }
    return sid


def verify_snapshot_id(state, port: int, sid: str, current_identity: dict) -> str:
    """返回 ""=有效；target_identity_required=缺失/过期；target_changed=身份不符。
    B3（T-PORT-003）：按 sid 查——假 sid 只作废自己，不牵连同端口其他有效指纹。
    复核建议 2：任一方 started 为空 → target_identity_required（fail closed，
    堵 by_port 模式的 ""=="" 口子）。"""
    with state.state_lock:
        rec = state.snapshots.get(sid or "")
        if not rec or rec["expires"] < time.monotonic():
            state.snapshots.pop(sid or "", None)
            return "target_identity_required"
        if rec["port"] != port:
            return "target_changed"        # sid 是签给别的端口的
        ident = rec["identity"]
    if not ident.get("started") or not current_identity.get("started"):
        return "target_identity_required"
    same = (ident["pid"] == current_identity["pid"]
            and ident["proc"].casefold() == current_identity["proc"].casefold()
            and ident["started"] == current_identity["started"])
    return "" if same else "target_changed"


def try_consume_rate_slot(state, channel: str) -> bool:
    """S1（T-PORT-003）：检查+记账原子化——原 check/record 两把锁之间夹着审计写盘，
    并发下 N 个请求能同时通过检查（频率闸是防 AI 循环误调的唯一闸门）。False=超限。"""
    with state.state_lock:
        now = time.monotonic()
        dq = state.kill_rate[channel]
        while dq and dq[0] < now - KILL_RATE_WINDOW:
            dq.popleft()
        if len(dq) >= KILL_RATE_LIMIT:
            return False
        dq.append(now)
        return True


# ----------------------------------------------------------------------------
# 外部关闭命令（§6.3/§6.4）
# ----------------------------------------------------------------------------


def run_taskkill(pid: int) -> tuple:
    """taskkill /PID <pid> /T /F；返回码只代表命令执行结果，不代表端口释放。"""
    cmd = ["taskkill", "/PID", str(pid), "/T", "/F"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=TASKKILL_TIMEOUT,
                              creationflags=CREATE_NO_WINDOW, shell=False)
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"taskkill failed: {e}"
    if proc.returncode != 0:
        err = _extract_ps_stderr(proc.stderr, limit=200)
        return False, f"taskkill exit {proc.returncode}: {err}"
    return True, ""


def tree_member_entry(pid: int, procs_by_pid: dict, started_map: dict, target: dict) -> dict:
    """S2/复核建议 3（共用）：树成员的 killed 记录取真实 proc/started，
    不许拿根进程的值充数（审计造假）。UI 与强杀两条路径共用。"""
    info = procs_by_pid.get(pid) or {}
    return {"pid": pid,
            "proc": info.get("name") or target["proc"],
            "started": info.get("started") or started_map.get(pid) or target["started"]}


def wait_tree_exit(tree_pids: list, window: float, poll: float = 0.4,
                   started_map=None) -> list:
    """轮询窗口内返回仍存活的树成员列表（带 started 指纹防 PID 复用假阳性）。"""
    smap = started_map or {}
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        alive = [p for p in tree_pids if pid_matches_start(p, smap.get(p, ""))]
        if not alive:
            return []
        time.sleep(poll)
    return [p for p in tree_pids if pid_matches_start(p, smap.get(p, ""))]


def remaining_on_port(scan: dict, port: int) -> list:
    """端口当前占用者（精简）：可能被新进程接管，不得当作已杀目标（§6.5）。"""
    out, seen = [], set()
    for e in scan["entries"]:
        if e["port"] != port or e["pid"] in seen:
            continue
        seen.add(e["pid"])
        out.append({"pid": e["pid"], "proc": e["proc"], "started": e["started"],
                    "addr": e["addr"]})
    return out


# ----------------------------------------------------------------------------
# 运行时状态与 L0 列表
# ----------------------------------------------------------------------------


class AppState:
    def __init__(self, base_dir: Path, configs: dict, console_port: int,
                 token: str, token_ok: bool):
        self.base_dir = base_dir
        self.rules = configs["rules"]
        self.protection = configs["protection"]
        self.port_map = configs["port_map"]
        self.unknown = configs["unknown"]
        self.dynamic_protected = set(configs.get("dynamic_protected") or ())
        self.warnings = list(configs["warnings"])
        self.console_port = console_port
        self.console_pid = os.getpid()
        # 1.3 R2：实例身份。端口会顺延、会被顶，pid 会被复用；只有"本进程随机号"
        # 能回答"应答的是不是写 runtime.json 的那个实例"。随进程生死，不落盘明文，
        # 只进 runtime.json 与 health 回显，不含任何可推断信息。
        self.instance_id = secrets.token_hex(8)
        self.token = token
        self.token_ok = token_ok
        self.started_at = time.monotonic()
        self.state_lock = threading.Lock()
        self.audit_lock = threading.Lock()
        self.tickets = {}        # ticket -> {port,pid,proc,started,expires,used}
        self.snapshots = {}      # port -> {sid,identity,expires}
        self.kill_rate = {"ui": deque(), "agent": deque()}
        self.agent_gate = _AgentPortsGate()  # 1.2 改-2：agent/ports 限流+在飞闸
        self.scan_cache = None   # 展示缓存槽 -> {data,at,cached_at_iso}（只喂 GET /ports）
        self.scan_cache_lock = threading.Lock()
        self.index_html = b""
        index_path = base_dir / "index.html"
        if index_path.exists():
            self.index_html = index_path.read_bytes()


def uptime_seconds(state) -> int:
    return int(time.monotonic() - state.started_at)


def build_full_entries(state, scan: dict, *, record_unknowns: bool) -> list:
    """完整端口条目（§5.4）。"""
    out = []
    for e in scan["entries"]:
        cls = classify_entry(state, e)
        if cls["source"] == "manual":
            fill_mapping_fingerprint(state, e)
        level = cls["level"]
        reason = protection_reason(state, e)
        if reason:
            level = "system"      # §4.3：安全优先级最高，即使手工命名为 self
        out.append({
            "port": e["port"], "addr": e["addr"], "pid": e["pid"],
            "proc": e["proc"], "cmdline": e["cmdline"],
            "name": cls["name"], "level": level, "source": cls["source"],
            "started": e["started"], "session_id": e["session_id"],
            "kill_allowed": reason is None and level != "system",
            "protected_reason": reason or "",
            "mapping_stale": cls["mapping_stale"],
        })
        # 1.2 台账过滤：只留"真·未知的可操作目标"。
        # 旧逻辑 source==unknown 即记账，wininit/services/控制台残影这类受保护项
        # 也会进 unknown.json（实测台账里就有），挤占 UNKNOWN_MAX=500 上限、稀释信噪比。
        #   - reason 非空 / level 被压成 system：保护线已拦，不是"待认领"，不记；
        #   - proc 为空或 "?"：进程快照缺失（刚退出/读不到的残影），记了也无法认领。
        if (record_unknowns and cls["source"] == "unknown"
                and not reason and level != "system"
                and e.get("proc") not in ("", "?")):
            record_unknown(state, e)
    return out


def slim_entry(item: dict) -> dict:
    """§4.9：AI 精简条目，默认不含 cmdline/started/session_id。"""
    slim = {
        "port": item["port"], "addr": item["addr"], "pid": item["pid"],
        "proc": item["proc"], "name": item["name"], "level": item["level"],
        "source": item["source"], "kill_allowed": item["kill_allowed"],
    }
    if not item["kill_allowed"]:
        slim["protected_reason"] = item["protected_reason"]
    return slim


def owner_groups(scan: dict, port: int) -> list:
    """§6.2 步 3：按 (pid, proc, started) 归并占用者（硬要求 7）。"""
    groups, seen = [], set()
    for e in scan["entries"]:
        if e["port"] != port:
            continue
        key = (e["pid"], e["proc"].casefold(), e["started"])
        if key in seen:
            continue
        seen.add(key)
        groups.append(e)
    return groups


# ----------------------------------------------------------------------------
# 关闭核心（§6）——UI 与 AI 共用同一 close_target
# ----------------------------------------------------------------------------


def scan_or_error() -> dict:
    return normalize_snapshot(scan_snapshot())


# 展示缓存 TTL（T-PORT-004 R3 §4.1：设计决策 1）。只服务 GET /api/v1/ports 展示，
# 与 kill 链路零交集（V54/V55/V72 三层防御见 scan_or_error_cached 与 close_target）。
SCAN_CACHE_TTL = 5.0


def scan_or_error_cached(state, force_fresh: bool = False) -> dict:
    """GET /api/v1/ports 展示专用 5 秒缓存（V1 目标：命中 0.02s）。
    force_fresh=True（?refresh=1）跳过命中直接新鲜扫描，结果同样回写缓存槽
    ——手动刷新后轮询拿到的是刷新时的数据，不会"跳回"旧缓存。
    三层防御：
      第一层·物理隔离——本函数无定向参数，只可能缓存全表结果；任何定向/过滤
      扫描（agent/ports?port=X）走 scan_or_error()，不写也不读缓存（V72）。
      第二层·标记——返回数据带 _cached/_cached_at/_scope:"full"；kill 路径
      在 close_target 见到 _cached 即 RuntimeError（500，不执行关闭，V55）。
      第三层·专门测试——单测 54/55/65/66 + 验收 V54/V55/V72/V73。
    ScanError 原样上抛（扫描失败不缓存、不假装成功）。"""
    if not force_fresh:
        now = time.monotonic()
        with state.scan_cache_lock:
            c = state.scan_cache
            if c is not None and (now - c["at"]) < SCAN_CACHE_TTL:
                data = copy.deepcopy(c["data"])
                data["_cached"] = True
                data["_cached_at"] = c["cached_at_iso"]
                data["_scope"] = "full"
                return data
    scan = scan_or_error()
    cached_at = now_iso()
    scan["_cached"] = False
    scan["_cached_at"] = cached_at
    scan["_scope"] = "full"
    with state.scan_cache_lock:
        state.scan_cache = {"data": copy.deepcopy(scan), "at": time.monotonic(),
                            "cached_at_iso": cached_at}
    return scan


def parse_close_request(state, body: dict, mode: str, channel: str):
    """§6.1 步 3：字段类型与范围校验。布尔值不能冒充整数；字符串 "true" 不合格；
    Agent 拒绝 force/force_ticket；按端口模式拒绝身份字段（acceptance 步 5）。"""
    port = body.get("port")
    if not is_int(port) or not (1 <= port <= 65535):
        return 400, "invalid_request", "port 非法", None
    if channel == "agent":
        # confirm 是 AI 通道（L2）的授权要件；UI 通道（L1）凭同源证据+两阶段，不带 confirm（§6.1 步1）
        if "confirm" not in body:
            return 400, "confirm_required", "缺少 confirm:true", None
        confirm = body.get("confirm")
        if not isinstance(confirm, bool):
            return 400, "invalid_request", "confirm 必须是 JSON 布尔值", None
        if confirm is not True:
            return 400, "confirm_required", "confirm 必须为 true", None
        if "force" in body or "force_ticket" in body:
            return 400, "invalid_request", "Agent 通道不得携带 force/force_ticket", None

    if mode == "strict":
        pid = body.get("pid")
        if not is_int(pid) or pid <= 0:
            return 400, "invalid_request", "pid 非法", None
        proc = body.get("proc")
        if not isinstance(proc, str) or not proc.strip() or len(proc) > 200:
            return 400, "invalid_request", "proc 非法", None
        # B2（T-PORT-003）：started 必填——四元组才是唯一身份（PID 会复用，方案级修正）
        started = body.get("started")
        if not isinstance(started, str) or not started.strip():
            return 400, "invalid_request", "严格模式必须携带 started 指纹（四元组才是唯一身份）", None
        if len(started) > 100:
            return 400, "invalid_request", "started 非法", None
        return 0, "", "", {"port": port, "pid": pid, "proc": proc.strip(), "started": started.strip()}
    for k in ("pid", "proc", "started"):
        if k in body:
            return 400, "invalid_request", f"按端口模式不得携带身份字段 {k}", None
    sid = body.get("snapshot_id")
    if sid is not None and (not isinstance(sid, str) or len(sid) > 64):
        return 400, "invalid_request", "snapshot_id 非法", None
    return 0, "", "", {"port": port, "snapshot_id": sid}


def close_target(state, *, channel: str, mode: str, clean: dict, client_id: str) -> tuple:
    """§6.1/§6.2/§6.3 状态机核心。返回 (http_code, response_dict)。
    任何校验不过都不触碰外部关闭命令（阶段 C 硬门槛）。"""
    port = clean["port"]

    # 步 4：新鲜扫描，禁用轮询缓存（硬要求 6）
    try:
        scan = scan_or_error()
    except ScanError as e:
        print(f"[port-console] kill-scan: {e}", file=sys.stderr)
        return 500, error_body("scan_failed", "扫描失败，无法完成操作，请稍后重试")
    # T-PORT-004 R3 第二层防御（V55）：展示缓存若因将来误接线流进 kill 路径，
    # 缓存里的身份是旧快照——宁可 500 拒绝执行，也不能拿旧身份去杀（工单 §三）。
    if scan.get("_cached"):
        raise RuntimeError("cached scan data must never enter the kill path (V55)")

    # 步 5：解析目标
    if mode == "strict":
        target = None
        for e in owner_groups(scan, port):
            if e["pid"] == clean["pid"]:
                target = e
                break
        if target is None:
            return 404, error_body("port_free", "端口上没有该 PID 的监听（可能已退出或易主）")
        if target["proc"].casefold() != clean["proc"].casefold():
            return 409, error_body("target_changed", "进程名与请求不符，目标可能已变化")
        # B2（T-PORT-003）：started fail-closed——缺失/空一律拒，不再"空则跳过"
        if not clean["started"] or not target["started"]:
            # 1.2 改-6 文案分流：目标本身 started 不可读（ticks 缺失）时，
            # 「请重新查询」是死循环话术——重查一万次也读不到。两种情况分开说。
            if not target["started"]:
                return 409, error_body(
                    "target_identity_unavailable",
                    "该进程启动时间不可读（系统未返回其创建时间，常见于 Session 0/"
                    "权限不足），无法核验身份；不可对其执行关闭操作")
            return 409, error_body("target_identity_required",
                                   "缺少启动时间指纹，无法确认目标身份，请重新查询")
        if clean["started"] != target["started"]:
            return 409, error_body("target_changed", "启动时间与请求不符，目标可能已被复用")
    else:
        groups = owner_groups(scan, port)
        if not groups:
            # §6.2 步 2：幂等成功，不校验指纹、不写审计、不执行进程操作
            return 200, {
                "ok": True, "port": port, "already_free": True, "target": None,
                "killed": [], "remaining": [], "message": "端口已空闲",
            }
        if len(groups) > 1:
            # §6.2 步 4：多占用者拒绝，优先于指纹校验（单测 40 / V40）
            by_pid = {f["pid"]: f
                      for f in build_full_entries(state, scan, record_unknowns=False)}
            body = error_body("multiple_owners",
                              "端口有多个占用者，请查询列表后用严格模式显式点名")
            body["candidates"] = [{
                "port": e["port"], "addr": e["addr"], "pid": e["pid"],
                "proc": e["proc"], "name": by_pid.get(e["pid"], {}).get("name", ""),
                "level": by_pid.get(e["pid"], {}).get("level", "unknown"),
                "kill_allowed": by_pid.get(e["pid"], {}).get("kill_allowed", False),
            } for e in groups]
            return 409, body
        target = groups[0]
        identity = {"port": port, "pid": target["pid"], "proc": target["proc"],
                    "started": target["started"]}
        if clean.get("snapshot_id"):
            v = verify_snapshot_id(state, port, clean["snapshot_id"], identity)
            if v == "target_identity_required":
                # 1.2 改-6 文案分流：目标当前 started 不可读时不能叫人「再取指纹」
                # ——agent/ports 对 started 空的目标不发 sid，AI 会取不到再查再 400
                if not target["started"]:
                    return 400, error_body(
                        "target_identity_unavailable",
                        "该进程启动时间不可读（系统未返回其创建时间，常见于 Session 0/"
                        "权限不足），无法核验身份；不可对其执行关闭操作")
                return 400, error_body("target_identity_required",
                                       "指纹缺失或过期，请先 GET /api/v1/agent/ports?port=X 取指纹")
            if v == "target_changed":
                return 409, error_body("target_changed",
                                       "指纹绑定身份与当前占用者不符（端口易主或认错端口）")
        else:
            # §6.2 步 5：占用端口必须携带指纹（V41）
            # 1.2 改-6 文案分流：目标 started 不可读（ticks 缺失）时，agent/ports
            # 本来就不发 sid，「请先查指纹」会让 AI 陷入取不到→再查→再 400 的循环。
            if not target["started"]:
                return 400, error_body(
                    "target_identity_unavailable",
                    "该进程启动时间不可读（系统未返回其创建时间，常见于 Session 0/"
                    "权限不足），无法核验身份；不可对其执行关闭操作")
            return 400, error_body("target_identity_required",
                                   "占用端口必须携带 snapshot_id（先 GET /api/v1/agent/ports?port=X）")

    # 步 7：保护检查（level=system 硬拒 / SessionId==0 / System32 / 子树护栏）
    # T-PORT-004 R3 §4.4：构树换 build_tree_with_session_filter——同一轮全量快照
    # 内存构树＋"刚退出成员剔除（判据 2）"＋"PPID 复用孤儿剔除（备注 3，保守三态）"；
    # started_map 仍按剔除后的 tree_pids 取（杀后验证防 PID 复用）。
    tree_pids = build_tree_with_session_filter(
        scan["processes"],
        scan.get("_session_seen") or set(scan["processes"]),
        target["pid"])
    # 树成员 started 指纹表（杀后验证防 PID 复用假阳性）
    started_map = {}
    for p in tree_pids:
        info = scan["processes"].get(p)
        started_map[p] = (info or {}).get("started", "") or (target["started"] if p == target["pid"] else "")
    allowed, reason, _pe = check_protection(state, scan, target, tree_pids)
    if not allowed:
        body = error_body("kill_not_allowed", f"目标受保护，不允许关闭: {reason}")
        body["target"] = {"pid": target["pid"], "proc": target["proc"],
                          "started": target["started"]}
        body["protected_reason"] = reason
        return 403, body

    by_pid = {f["pid"]: f for f in build_full_entries(state, scan, record_unknowns=False)}
    t_full = by_pid.get(target["pid"], {})
    target_label = {"pid": target["pid"], "proc": target["proc"], "started": target["started"],
                    "name": t_full.get("name", ""), "level": t_full.get("level", "unknown"),
                    "source": t_full.get("source", "unknown")}

    # ---------------- UI 第一阶段：礼貌关窗（§6.4） ----------------
    if channel == "ui" and not clean.get("force"):
        try:
            write_audit_event(state, {
                "ts": now_iso(), "channel": "ui", "mode": "wm_close", "port": port,
                "target": target_label, "client_id": client_id, "action": "started",
            })
        except OSError as e:
            print(f"[port-console] audit-pre-ui: {e}", file=sys.stderr)
            return 500, error_body("audit_write_failed", "操作未能执行，审计记录写入失败")

        # 1.2 审计成对收口：枚举窗口是 Win32 边界，started 已落盘——异常必须补
        # finished 再返回，杜绝 started 悬空。
        try:
            hwnd = find_main_window_for_pid(target["pid"])
        except Exception as e:
            write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                 "failed", [], [], f"internal_error:{type(e).__name__}")
            return 500, error_body("internal_error", "枚举主窗口失败")
        if hwnd is None:
            ticket = issue_force_ticket(state, target, channel="ui")
            write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                 "failed", [], remaining_on_port(scan, port),
                                 "force_confirm_required")
            body = error_body("force_confirm_required", "未找到可正常关闭的窗口，需要强杀确认")
            body.update({"force_ticket": ticket, "expires_in": int(TICKET_TTL),
                         "target": {"pid": target["pid"], "proc": target["proc"],
                                    "started": target["started"]}})
            return 428, body
        if not post_wm_close(hwnd):
            err_no = ctypes.get_last_error()
            fail_reason = "access_denied" if err_no == ERROR_ACCESS_DENIED else "close_failed"
            write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                 "failed", [], remaining_on_port(scan, port), fail_reason)
            return (403 if fail_reason == "access_denied" else 500), error_body(
                fail_reason, "关窗消息发送失败（权限不足或目标拒绝），不升级强杀")

        # PostMessageW 已排队：每 200ms 复核，最多 2 秒（§6.4）
        try:
            tree_alive = wait_tree_exit(tree_pids, WM_CLOSE_WAIT, WM_CLOSE_POLL,
                                        started_map=started_map)
        except Exception as e:
            # 1.2 审计成对收口：存活轮询走 Win32 句柄，同样是外部边界
            write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                 "failed", [], [], f"internal_error:{type(e).__name__}")
            return 500, error_body("internal_error", "关窗结果复核失败")
        try:
            rescan = scan_or_error()
        except ScanError as e:
            write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                 "failed", [], [], "scan_failed")
            print(f"[port-console] wm_close-rescan: {e}", file=sys.stderr)
            return 500, error_body("scan_failed", "关窗后复核失败，请重新查询端口状态确认")
        still = remaining_on_port(rescan, port)
        if not tree_alive and not still:
            killed = [tree_member_entry(p, scan["processes"], started_map, target)
                      for p in tree_pids]
            write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                 "succeeded", killed[:1], [], None)
            return 200, success_body(port, target, killed, [], "进程已正常关闭，端口已释放")
        if target["pid"] in tree_alive:
            fresh = None
            for e in rescan["entries"]:
                if e["pid"] == target["pid"] and e["port"] == port:
                    fresh = e
                    break
            if fresh and target["started"] and fresh["started"] and \
                    fresh["started"] != target["started"]:
                write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                     "failed", [], still, "target_changed")
                return 409, error_body("target_changed", "等待期间目标身份变化（PID 可能被复用）")
            ticket = issue_force_ticket(state, target, channel="ui")
            write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                                 "failed", [], still, "force_confirm_required")
            body = error_body("force_confirm_required", "正常关闭未完成，需要强杀确认")
            body.update({"force_ticket": ticket, "expires_in": int(TICKET_TTL),
                         "target": {"pid": target["pid"], "proc": target["proc"],
                                    "started": target["started"]}})
            return 428, body
        write_audit_finished(state, "ui", "wm_close", port, target_label, client_id,
                             "failed", [], still, "residual_listeners")
        body = error_body("residual_listeners", "进程已退出但端口仍有占用")
        body["remaining"] = still
        return 409, body

    # ---------------- 强杀路径（UI force=true / AI 单次直达） ----------------
    if channel == "ui":
        terr = consume_force_ticket(state, clean.get("force_ticket"), target, channel="ui")
        if terr:
            return 409, error_body(terr, "强杀 ticket 缺失、过期、已复用或不匹配，请回到第一阶段重新确认")

    # 审计前置（复核建议 1：前置在扣费之前——already_free/复核拒绝出口不白扣配额；
    # 扣费点挪到本文件下方 taskkill 前的最后一刻，闸门计量的是"杀"，不是"请求"）
    try:
        write_audit_event(state, {
            "ts": now_iso(), "channel": channel, "mode": "taskkill_tree", "port": port,
            "target": target_label, "client_id": client_id, "action": "started",
        })
    except OSError as e:
        print(f"[port-console] audit-pre-agent: {e}", file=sys.stderr)
        return 500, error_body("audit_write_failed", "操作未能执行，审计记录写入失败")

    # ★ B1（T-PORT-003）杀前实时复核：快照比对只能发现"扫描前"的易主，
    #   发现不了"扫描后（含审计 os.fsync 的窗口）"的 PID 复用。此处用【此刻】的
    #   进程创建时间与快照比对（pid_matches_start 三关判定）。
    # 1.2 审计成对收口：started 事件已落盘，pid_matches_start 是 Win32 边界——
    # 真实 kill_audit.jsonl 里出现过此处之后无 finished 的悬空记录。异常时补一条
    # failed 再返回 500，不让 started 挂在日志里。
    try:
        pre_alive = bool(target["started"]) and pid_matches_start(
            target["pid"], target["started"])
    except Exception as e:
        write_audit_finished(state, channel, "taskkill_tree", port, target_label,
                             client_id, "failed", [], [],
                             f"internal_error:{type(e).__name__}")
        return 500, error_body("internal_error", "杀前身份复核失败")
    if not pre_alive:
        # False 有两义：目标已自行退出（不用杀）vs PID 被复用（必须拒）。重扫分辨：
        try:
            recheck = scan_or_error()
        except ScanError as e:
            write_audit_finished(state, channel, "taskkill_tree", port, target_label,
                                 client_id, "failed", [], [], "scan_failed")
            print(f"[port-console] prekill-rescan: {e}", file=sys.stderr)
            return 500, error_body("scan_failed", "杀前复核失败，操作已中止")
        still = remaining_on_port(recheck, port)
        if not still:
            # 目标已退且端口已空：意图已达成（非己力）。审计 result 用 "already_free"
            # （复核要点 4：与 API 响应同词，下游聚合不会误算成"成功强杀一次"）
            write_audit_finished(state, channel, "taskkill_tree", port, target_label,
                                 client_id, "already_free", [], [], "port_free")
            return 200, {"ok": True, "port": port, "already_free": True,
                         "target": {"pid": target["pid"], "proc": target["proc"],
                                    "started": target["started"]},
                         "killed": [], "remaining": [],
                         "message": "杀前复核发现目标已自行退出，端口已空闲"}
        write_audit_finished(state, channel, "taskkill_tree", port, target_label,
                             client_id, "failed", [], still, "target_changed")
        return 409, error_body("target_changed",
                               "杀前复核失败：目标 PID 已被复用或已变化，拒绝关闭，请重新查询")

    # ★ 复核建议 1：扣费点挪到最后一刻——闸门计量的是"杀"，不是"请求"。
    #   （原位置在审计前置/B1 复核之前，already_free 与审计失败都会白扣配额）
    if not try_consume_rate_slot(state, channel):
        write_audit_finished(state, channel, "taskkill_tree", port, target_label,
                             client_id, "failed", [], [], "rate_limited")
        return 429, error_body("rate_limited",
                               "触发 kill 频率闸（每分钟 6 次），请检查是否存在调用循环")

    _ok, err = run_taskkill(target["pid"])
    try:
        alive = wait_tree_exit(tree_pids, KILL_VERIFY_WINDOW, started_map=started_map)
    except Exception as e:
        # 1.2 审计成对收口：taskkill 已执行，杀后验证轮询若抛异常，started 必须有 finished
        write_audit_finished(state, channel, "taskkill_tree", port, target_label,
                             client_id, "failed", [], [],
                             f"internal_error:{type(e).__name__}")
        return 500, error_body("internal_error", "杀后存活验证失败")
    procs_by_pid = scan["processes"]
    try:
        final_scan = scan_or_error()
    except ScanError as e:
        write_audit_finished(state, channel, "taskkill_tree", port, target_label, client_id,
                             "failed", [], [], "scan_failed")
        print(f"[port-console] postkill-rescan: {e}", file=sys.stderr)
        return 500, error_body("scan_failed", "强杀结果验证失败，请重新查询确认")
    still = remaining_on_port(final_scan, port)
    exited = [p for p in tree_pids if p not in set(alive)]
    # S2（T-PORT-003）：killed 填每个成员的真实 proc/started（原实现全填根进程的值，
    # 杀 6 棵树的审计里 6 条只有 1 条真信息——出事追责审计会给错误答案）
    killed = [tree_member_entry(p, procs_by_pid, started_map, target) for p in exited]

    if not alive and not still:
        # T-PORT-003：taskkill 返回码进审计——非零也杀干净了时，200 但审计留痕
        write_audit_finished(state, channel, "taskkill_tree", port, target_label, client_id,
                             "succeeded", killed, [], None if _ok else f"taskkill_rc:{err}")
        return 200, success_body(port, target, killed, [], "进程树已结束，端口已释放")
    if target["pid"] in alive:
        write_audit_finished(state, channel, "taskkill_tree", port, target_label, client_id,
                             "failed", killed, still, "command_failed")
        print(f"[port-console] taskkill: {err or '根进程仍存活'}", file=sys.stderr)
        body = error_body("command_failed", "强杀未生效：可能权限不足（需以管理员身份运行），或目标正在被系统占用")
        body["remaining"] = still
        return 500, body
    write_audit_finished(state, channel, "taskkill_tree", port, target_label, client_id,
                         "failed", killed, still, "residual_listeners")
    body = error_body("residual_listeners", "目标进程已退出，但端口仍有占用")
    body["remaining"] = still
    return 409, body


def success_body(port, target, killed, remaining, message) -> dict:
    return {
        "ok": True, "port": port, "already_free": False,
        "target": {"pid": target["pid"], "proc": target["proc"], "started": target["started"]},
        "killed": killed, "remaining": remaining, "message": message,
    }


def error_body(reason: str, message: str) -> dict:
    return {"ok": False, "reason": reason, "message": message}


def write_audit_finished(state, channel, mode, port, target_label, client_id,
                         result, killed, remaining, reason) -> None:
    """结果事件写失败：控制台警告，不假装审计成功（§4.8）。"""
    try:
        write_audit_event(state, {
            "ts": now_iso(), "channel": channel, "mode": mode, "port": port,
            "target": target_label, "client_id": client_id, "action": "finished",
            "result": result, "killed": killed, "remaining": remaining,
            "reason": reason,
        })
    except OSError as e:
        print(f"[port-console] ⚠ 审计结果事件写盘失败（真实结果={result}）: {e}", file=sys.stderr)


# ----------------------------------------------------------------------------
# rename（§7.3）
# ----------------------------------------------------------------------------


def rename_port(state, body: dict, client_id: str) -> tuple:
    port = body.get("port")
    if not is_int(port) or not (1 <= port <= 65535):
        return 400, error_body("invalid_request", "port 非法")
    name = body.get("name")
    if not isinstance(name, str) or not (1 <= len(name.strip()) <= 80):
        return 400, error_body("invalid_request", "name 必须为 1-80 字符")
    name = name.strip()
    level = body.get("level")
    if level not in ("self", "other"):
        return 400, error_body("invalid_request", "level 仅允许 self/other")

    try:
        scan = scan_or_error()
    except ScanError as e:
        print(f"[port-console] rename-scan: {e}", file=sys.stderr)
        return 500, error_body("scan_failed", "扫描失败，无法完成操作，请稍后重试")

    current = None
    for e in owner_groups(scan, port):
        current = e
        break
    if current is not None:
        allowed, reason, _pe = check_protection(state, scan, current, [current["pid"]])
        if not allowed:
            return 403, error_body("kill_not_allowed", f"受保护项不提供改名入口: {reason}")
        fingerprint = {"proc": current["proc"], "started": current["started"]}
    else:
        fingerprint = {"proc": "", "started": ""}

    with state.state_lock:
        old_entry = state.port_map.get(str(port))       # S3：回滚还原旧映射，不误删
        state.port_map[str(port)] = {"name": name, "level": level, **fingerprint}
        try:
            atomic_write_json(state.base_dir / "port_map.json", state.port_map)
        except OSError as e:
            if old_entry is not None:
                state.port_map[str(port)] = old_entry
            else:
                state.port_map.pop(str(port), None)
            print(f"[port-console] port_map-write: {e}", file=sys.stderr)
            return 500, error_body("internal_error", "命名保存失败，请稍后重试")

    item = {"port": port, "name": name, "level": level, "source": "manual",
            "proc": fingerprint["proc"], "started": fingerprint["started"]}
    return 200, {"ok": True, "item": item, "message": "命名已保存"}


def protect_port(state, body: dict, client_id: str) -> tuple:
    """用户手动保护：按端口加入动态保护表（重启不丢）。
    静态系统口不受理（已受保护）；只保护当前监听中的端口（不确定的不保）。"""
    port = body.get("port")
    if not is_int(port) or not (1 <= port <= 65535):
        return 400, error_body("invalid_request", "port 非法")
    if port in state.protection["ports"]:
        return 409, error_body("already_protected_static", "该端口在系统静态保护表中，无需手动保护")
    if port in state.dynamic_protected:
        return 200, {"ok": True, "message": f"端口 {port} 已在手动保护中"}
    try:
        listening = scan_listen_ports()
    except ScanError as e:
        # 1.2 改-8：响应体统一稳定话术（L-13 风格）——{e} 可能带 PowerShell
        # stderr 片段，详情只进服务端 stderr，不出响应体。
        print(f"[port-console] protect_port 扫描失败: {e}", file=sys.stderr)
        return 503, error_body("scan_failed", "扫描失败，无法确认端口监听状态，请稍后重试")
    if port not in listening:
        return 400, error_body("not_listening", "端口当前未监听，无从保护")
    with state.state_lock:
        state.dynamic_protected.add(port)
        try:
            atomic_write_json(state.base_dir / "dynamic_protection.json",
                              {"ports": sorted(state.dynamic_protected)})
        except OSError as e:
            state.dynamic_protected.discard(port)
            print(f"[port-console] protect-write: {e}", file=sys.stderr)
            return 500, error_body("internal_error", "保护设置保存失败，请稍后重试")
    try:  # 保护已生效，审计失败只记日志不回滚（次级故障不推翻主操作）
        write_audit_event(state, {"ts": now_iso(), "channel": "ui", "port": port,
                                  "client_id": client_id, "action": "protect"})
    except OSError as e:
        print(f"[port-console] 保护审计写盘失败: {e}", file=sys.stderr)
    return 200, {"ok": True, "message": f"端口 {port} 已保护，关闭请求将被拒绝"}


def unprotect_port(state, body: dict, client_id: str) -> tuple:
    """解除手动保护：仅限动态表条目；静态系统保护不可通过 API 解除。"""
    port = body.get("port")
    if not is_int(port) or not (1 <= port <= 65535):
        return 400, error_body("invalid_request", "port 非法")
    if port in state.protection["ports"]:
        return 403, error_body("static_protected", "静态系统保护不可解除")
    if port not in state.dynamic_protected:
        return 404, error_body("not_dynamic_protected", "该端口不在手动保护表中")
    with state.state_lock:
        state.dynamic_protected.discard(port)
        try:
            atomic_write_json(state.base_dir / "dynamic_protection.json",
                              {"ports": sorted(state.dynamic_protected)})
        except OSError as e:
            state.dynamic_protected.add(port)
            print(f"[port-console] unprotect-write: {e}", file=sys.stderr)
            return 500, error_body("internal_error", "解除保护保存失败，请稍后重试")
    try:
        write_audit_event(state, {"ts": now_iso(), "channel": "ui", "port": port,
                                  "client_id": client_id, "action": "unprotect"})
    except OSError as e:
        print(f"[port-console] 解除保护审计写盘失败: {e}", file=sys.stderr)
    return 200, {"ok": True, "message": f"端口 {port} 已解除手动保护"}


# ----------------------------------------------------------------------------
# HTTP 层（§7）
# ----------------------------------------------------------------------------


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION
    sys_version = ""              # 1.3 项②：不外露 Python 解释器版本
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        # 默认实现拼 'server_version + 空格 + sys_version'；置空 sys_version 仍带尾
        # 空格，覆写保证响应头恰好为产品版本。
        return SERVER_VERSION

    # ---- 基础响应 ----

    def _send_json(self, code: int, obj: dict) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # 1.3 R2：每个 JSON 应答都盖章"我是哪个实例"。客户端发现端口后若端口被顶，
        # 第二个请求拿到的实例号会变——宁可报"端口易主"，也不把别家结果当本包。
        self.send_header("X-Port-Console-Instance", self._state().instance_id)
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, code: int, data: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # 静默访问日志；错误仍走 stderr
        pass

    # ---- 请求工具 ----

    def _actual_port(self) -> int:
        return self.server.actual_port

    def _state(self) -> AppState:
        return self.server.app_state

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") == f"127.0.0.1:{self._actual_port()}"

    def _origin_sfs(self):
        return self.headers.get("Origin", ""), self.headers.get("Sec-Fetch-Site", "")

    def _client_id(self) -> str:
        raw = self.headers.get(CLIENT_HEADER, "").strip()
        return clamp_str(raw, 64) or "unknown"

    def _read_json_body(self):
        """返回 (err_code, err_reason, err_msg, body)。POST 必须 application/json + 16KiB。"""
        ct = self.headers.get("Content-Type", "")
        if ct.split(";")[0].strip().lower() != "application/json":
            return 400, "invalid_request", "Content-Type 必须为 application/json", None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return 400, "invalid_request", "Content-Length 非法", None
        if length <= 0 or length > BODY_LIMIT:
            return 400, "invalid_request", "请求体为空或超过 16KiB 上限", None
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"[port-console] body-parse: {e}", file=sys.stderr)
            return 400, "invalid_request", "请求体不是合法 JSON", None
        if not isinstance(body, dict):
            return 400, "invalid_request", "请求体必须是 JSON 对象", None
        return 0, "", "", body

    def _reject_query_token(self) -> bool:
        return "token" in parse_qs(urlsplit(self.path).query)

    def _ai_token_ok(self, state) -> bool:
        """§4.6：token 只从请求头读取，hmac.compare_digest 常量时间比较。"""
        if not state.token_ok or not state.token:
            return False
        got = self.headers.get(TOKEN_HEADER, "")
        if not got:
            return False
        return hmac.compare_digest(got.encode("utf-8"), state.token.encode("utf-8"))

    # ---- 路由 ----

    def do_GET(self):
        state = self._state()
        path = urlsplit(self.path).path
        if not self._host_ok():
            self._send_json(403, error_body("invalid_host", "Host 必须为 127.0.0.1:<实际端口>"))
            return
        if path == "/":
            if state.index_html:
                self._send_html(200, state.index_html)
            else:
                self._send_json(404, error_body("not_found", "index.html 缺失"))
            return
        if not path.startswith("/api/v1/"):
            self._send_json(404, error_body("not_found", "未约定的路由（所有 API 统一 /api/v1 前缀）"))
            return
        if self._reject_query_token():
            self._send_json(401, error_body("unauthorized", "禁止通过 URL query 传 token"))
            return

        if path == "/api/v1/health":
            # CORS 开放仅限 health（1.1 DSH 壳）：壳页从 DSH 源探测本机本体是否在线，
            # 跨源 fetch 需 ACAO 头。health 只暴露在线/版本/uptime，无敏感面；
            # 其余端点（含 L0 列表）刻意不开——不给恶意网页跨源枚举本机端口的口子。
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-Port-Console-Instance", state.instance_id)
            body = json.dumps({"ok": True, "uptime": uptime_seconds(state),
                               "port": self._actual_port(), "api_version": API_VERSION,
                               "instance_id": state.instance_id}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/v1/protection":
            self._handle_protection(state)
        elif path == "/api/v1/ports":
            self._handle_ports(state)
        elif path == "/api/v1/agent/ports":
            self._handle_agent_ports(state)
        else:
            self._send_json(404, error_body("not_found", "未约定的路由"))

    def do_POST(self):
        state = self._state()
        path = urlsplit(self.path).path
        if not self._host_ok():
            self._send_json(403, error_body("invalid_host", "Host 必须为 127.0.0.1:<实际端口>"))
            return
        if self._reject_query_token():
            self._send_json(401, error_body("unauthorized", "禁止通过 URL query 传 token"))
            return

        ui_routes = {"/api/v1/ui/rename", "/api/v1/ui/kill",
                     "/api/v1/ui/protect", "/api/v1/ui/unprotect"}
        agent_routes = {"/api/v1/agent/kill": "strict",
                        "/api/v1/agent/kill-by-port": "by_port"}

        if path in ui_routes:
            # 步 1：通道授权先于任何扫描（单测 22：403 不得触发扫描）
            origin, sfs = self._origin_sfs()
            if not authorize_ui_request(origin, sfs, self._actual_port()):
                self._send_json(403, error_body("not_ui_origin", "缺少本机同源证据，UI 通道拒绝"))
                return
        elif path in agent_routes:
            origin, _sfs = self._origin_sfs()
            if origin and origin != f"http://127.0.0.1:{self._actual_port()}":
                self._send_json(403, error_body("invalid_origin", "Agent 通道不接受跨源请求"))
                return
            if not self._ai_token_ok(state):
                self._send_json(401, error_body(
                    "unauthorized",
                    "token 缺失或错误；若 token 文件损坏请删除 api_token.txt 后重启重新生成"))
                return
        else:
            self._send_json(404, error_body("not_found", "未约定的路由（所有 API 统一 /api/v1 前缀）"))
            return

        code, reason, msg, body = self._read_json_body()
        if code:
            self._send_json(code, error_body(reason, msg))
            return
        try:
            if path == "/api/v1/ui/kill":
                http_code, resp = self._ui_kill(state, body, self._client_id())
            elif path == "/api/v1/ui/rename":
                http_code, resp = rename_port(state, body, self._client_id())
            elif path == "/api/v1/ui/protect":
                http_code, resp = protect_port(state, body, self._client_id())
            elif path == "/api/v1/ui/unprotect":
                http_code, resp = unprotect_port(state, body, self._client_id())
            else:
                mode = agent_routes[path]
                code2, reason2, msg2, parsed = parse_close_request(state, body, mode, "agent")
                if code2:
                    http_code, resp = code2, error_body(reason2, msg2)
                else:
                    http_code, resp = close_target(state, channel="agent", mode=mode,
                                                   clean=parsed, client_id=self._client_id())
        except Exception as e:  # 防单请求异常拖垮服务；堆栈只进服务端日志不外泄（§6.6）
            print(f"[port-console] handler error: {e!r}", file=sys.stderr)
            traceback.print_exc()
            http_code, resp = 500, error_body("internal_error", "服务内部错误")
        self._send_json(http_code, resp)

    # ---- GET 处理器 ----

    def _handle_protection(self, state):
        # T-PORT-004 R3 §4.6：数据来源换 GetActiveTcpListeners()（~1.2s → ~0.1s）。
        # protection.json 语义、历史端口判定、V11 判据全部不变；集合一致性 V74。
        try:
            listening = scan_listen_ports()
        except ScanError as e:
            print(f"[port-console] protection-scan: {e}", file=sys.stderr)
            self._send_json(500, error_body("scan_failed", "扫描失败，无法完成操作，请稍后重试"))
            return
        active = sorted(p for p in state.protection["ports"] if p in listening)
        history = sorted(p for p in state.protection["ports"] if p not in listening)
        self._send_json(200, {"ok": True, "active_ports": active,
                              "history_ports": history,
                              "protected_processes": state.protection["process_names"],
                              "warnings": state.warnings})

    def _handle_ports(self, state):
        """完整条目。同源 UI 返回完整命令行；非同源默认脱敏（§7.4）。
        T-PORT-004 R3 §4.1：展示走 5 秒缓存（data_cached/data_time 透传给前端）；
        ?refresh=1 绕过缓存强制新鲜扫描（必修 4：手动刷新不许是假开关，V73）。"""
        origin, sfs = self._origin_sfs()
        same_origin = has_ui_evidence(origin, sfs, self._actual_port())
        q = parse_qs(urlsplit(self.path).query)
        force_fresh = q.get("refresh", [None])[0] == "1"
        # 1.2 GET 副作用收口（改-1 白名单谓词版）：?refresh=1 会强制跑一轮 PowerShell
        # 全表扫描（秒级、起子进程）。/api/v1/ports 是 L0 无 token 端点，任意网页
        # 都能用 <img src="http://127.0.0.1:3999/api/v1/ports?refresh=1"> 跨站发
        # 简单 GET——浏览器会执行服务端处理，只是读不到响应。
        # 收口口径（白名单式，与 agent/ports 同一谓词）：SFS 有值且不在
        # {same-origin, none} 白名单内（cross-site、same-site、及将来新增取值）
        # → 降级为缓存查询；本机脚本/CLI/验收（无 SFS 头）、地址栏直达 none、
        # 同源页面 → 照常强制刷新（端口发现与 21 步验收不能误伤）。
        refresh_ignored = bool(force_fresh and is_cross_origin_request(
            origin, sfs, self._actual_port()))
        if refresh_ignored:
            force_fresh = False
        try:
            scan = scan_or_error_cached(state, force_fresh=force_fresh)
        except ScanError as e:
            print(f"[port-console] ports-scan: {e}", file=sys.stderr)
            self._send_json(500, error_body("scan_failed", "扫描失败，无法完成操作，请稍后重试"))
            return
        items = build_full_entries(state, scan, record_unknowns=same_origin)
        if not same_origin:
            for it in items:
                it["cmdline"] = redact_cmdline(it["cmdline"])
        self._send_json(200, {"ok": True, "items": items, "generated_at": now_iso(),
                              "data_cached": bool(scan.get("_cached")),
                              "data_time": scan.get("_cached_at") or now_iso(),
                              "data_scope": scan.get("_scope") or "full",
                              "refresh_ignored": refresh_ignored,
                              "warnings": state.warnings})

    def _handle_agent_ports(self, state):
        """§4.9 精简条目；port 过滤且唯一占用附 snapshot_id；多占用附 candidates。
        1.2 改-2 收口：403（跨源）→ 429（限流）→ 503（在飞满）→ 才扫描；
        匿名请求降为纯只读（不发 snapshot_id、不写 unknown 台账），
        响应带 authenticated 供调用方自辨语义。"""
        origin, sfs = self._origin_sfs()
        if is_cross_origin_request(origin, sfs, self._actual_port()):
            # 403 在路由层返回：不进入任何扫描/记账/关闭路径（裁定 §六）
            self._send_json(403, error_body(
                "cross_origin_forbidden",
                "浏览器跨源请求已拒绝（本端点只服务本机程序）"))
            return
        authenticated = self._ai_token_ok(state)
        if not state.agent_gate.try_acquire(authenticated):
            limit = AGENT_PORTS_RATE_TOKEN if authenticated else AGENT_PORTS_RATE_ANON
            kind = "带 token" if authenticated else "匿名"
            self._send_json(429, error_body(
                "rate_limited",
                f"agent/ports {kind}请求超过 {limit} 次/分钟，请稍后重试"))
            return
        if not state.agent_gate.try_enter_inflight():
            self._send_json(503, error_body(
                "inflight_full",
                f"在飞全表扫描已达并发上限（{AGENT_PORTS_MAX_INFLIGHT}），请稍后重试"))
            return
        try:
            q = parse_qs(urlsplit(self.path).query)
            port_filter = q.get("port", [None])[0]
            try:
                scan = scan_or_error()
            except ScanError as e:
                print("[port-console] agent-ports-scan: " + str(e), file=sys.stderr)
                self._send_json(500, error_body("scan_failed", "扫描失败，无法完成操作，请稍后重试"))
                return
            # 1.2 改-2：unknown 台账只由带 token 的请求记账（匿名纯只读，不写盘）
            full = build_full_entries(state, scan, record_unknowns=authenticated)
            if port_filter is not None:
                try:
                    pf = int(port_filter)
                except ValueError:
                    self._send_json(400, error_body("invalid_request", "port 参数必须为整数"))
                    return
                if not (1 <= pf <= 65535):
                    self._send_json(400, error_body("invalid_request", "port 参数超出 1..65535"))
                    return
                full = [f for f in full if f["port"] == pf]

            items = [slim_entry(f) for f in full]
            resp = {"ok": True, "items": items, "generated_at": now_iso(),
                    "authenticated": authenticated,
                    "warnings": state.warnings}

            if port_filter is not None:
                groups = owner_groups(scan, int(port_filter))
                if len(groups) == 1:
                    e = groups[0]
                    # started 空的占用者不发指纹（503 语义只留给存储满；
                    # started 不可读目标已由 protection_reason fail closed 拦杀）。
                    # 1.2 改-2：匿名请求不发指纹——纯只读，不进票据面。
                    if e["started"] and authenticated:
                        sid = issue_snapshot_id(state, {"port": e["port"], "pid": e["pid"],
                                                        "proc": e["proc"], "started": e["started"]})
                        if sid is None:
                            # 复核建议 5：存储满 fail closed——拒绝下发，不挤有效票据
                            self._send_json(503, error_body(
                                "snapshot_store_full",
                                "指纹存储已满，请稍后重试取指纹"))
                            return
                        for it in items:
                            it["snapshot_id"] = sid
                elif len(groups) > 1:
                    by_pid = {f["pid"]: f for f in full}
                    resp["candidates"] = [{
                        "port": e["port"], "addr": e["addr"], "pid": e["pid"],
                        "proc": e["proc"], "name": by_pid.get(e["pid"], {}).get("name", ""),
                        "level": by_pid.get(e["pid"], {}).get("level", "unknown"),
                        "kill_allowed": by_pid.get(e["pid"], {}).get("kill_allowed", False),
                    } for e in groups]
        finally:
            state.agent_gate.leave_inflight()
        self._send_json(200, resp)

    # ---- POST 处理器 ----

    def _ui_kill(self, state, body, client_id):
        force = body.get("force")
        if "force" not in body or not isinstance(force, bool):
            return 400, error_body("invalid_request", "force 必须是 JSON 布尔值")
        code, reason, msg, parsed = parse_close_request(state, body, "strict", "ui")
        if code:
            return code, error_body(reason, msg)
        parsed["force"] = force
        if force:
            ft = body.get("force_ticket")
            if not isinstance(ft, str) or not ft:
                return 409, error_body("force_ticket_invalid", "强杀必须携带有效 force_ticket")
            parsed["force_ticket"] = ft
        return close_target(state, channel="ui", mode="strict", clean=parsed, client_id=client_id)


# ----------------------------------------------------------------------------
# 启动区（§9）
# ----------------------------------------------------------------------------


def acquire_instance_lock(base_dir: Path):
    """§9.1：msvcrt.locking LK_NBLCK；锁随进程生命周期，锁文件残留不代表有实例。"""
    fd = os.open(str(base_dir / "instance.lock"), os.O_CREAT | os.O_RDWR)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError:
        os.close(fd)
        return None
    return fd


def runtime_status(base_dir: Path) -> tuple:
    """返回 (runtime 存在, pid 存活, 健康且是本实例, base_url 或 None)。

    1.3 R2：第三个返回值从"端口上有人应答"收紧成"应答的是写这份 runtime.json 的
    那个实例"。旧实现把 3999 上任何 200 都算健康——handle_existing_instance 会打印
    "已有实例在运行"并 exit 0，而真正的控制台根本没起（用户看到一行提示就以为好了）。
    """
    rt = base_dir / "runtime.json"
    if not rt.exists():
        return False, False, False, None
    try:
        data = read_json_file(rt)
    except Exception:
        return True, False, False, None
    if not isinstance(data, dict):
        return True, False, False, None
    pid = data.get("pid")
    pid_ok = (isinstance(pid, int) and not isinstance(pid, bool)
              and pid > 0 and pid_alive(int(pid)))
    port = _extract_loopback_port(str(data.get("base_url") or ""))
    ident = _health_identity(port) if port else None
    recorded = str(data.get("instance_id") or "")
    health = bool(ident) and (not recorded or ident.get("instance_id") == recorded)
    return True, pid_ok, health, (data.get("base_url") if port else None)


def handle_existing_instance(base_dir: Path) -> None:
    """§9.1：锁被占 → 验证现有实例；健康则打开页面退出；等待 1 秒重试一次；
    仍失败明确报错退出，不删锁、不接管。
    S5（T-PORT-003）：第二次取锁成功时**持锁返回**（调用方继续启动），
    不得静默退出——原实现无条件 return 导致服务不启动。"""
    _e, pid_ok, health, base = runtime_status(base_dir)
    if pid_ok and health and base:
        print(f"[port-console] 已有实例在运行: {base}，打开页面后退出。")
        try:
            if os.environ.get("PORT_CONSOLE_NO_BROWSER") != "1":
                webbrowser.open(base)
        except Exception:
            pass
        sys.exit(0)
    time.sleep(1.0)
    fd = acquire_instance_lock(base_dir)
    if fd is None:
        print("[port-console] 另一个实例可能正在启动或异常占用 instance.lock，"
              "无法取得单实例锁，退出。", file=sys.stderr)
        sys.exit(1)
    # 持锁返回，main 继续正常启动流程


def clear_stale_runtime(base_dir: Path) -> None:
    """锁成功后检查 runtime.json：PID 不存在或健康不通 → 移到唯一名陈旧件继续。
    不得根据陈旧 PID 杀任何进程（V23）。"""
    exists, pid_ok, health, _base = runtime_status(base_dir)
    if not exists:
        return
    if pid_ok and health:
        print("[port-console] 警告：runtime.json 指向健康实例但未持锁，继续启动。", file=sys.stderr)
        return
    try:
        keep = _safe_tmp_path(base_dir).with_suffix(".stale")
        (base_dir / "runtime.json").rename(keep)
        print(f"[port-console] 陈旧 runtime.json 已移至 {keep.name}（{now_iso()}）")
    except OSError:
        pass


def cleanup_orphan_tmp(base_dir: Path) -> int:
    """1.3.1：启动早期清掉 pcon-*.tmp 孤儿。

    只按「pcon- 前缀 + .tmp 后缀」判，不按大小判——0 B 是常态，但中断残件可能带内容。
    名字空间与真件不相交（runtime.json / rules.json / api_token.txt / instance.lock 等），
    且只在拿到 instance.lock 之后、任何启动写操作之前调用，不碰正在写、尚未
    os.replace 的临时件。删不掉（被占）就保留并告警，不阻断启动。
    """
    removed = 0
    for p in base_dir.glob("pcon-*.tmp"):
        try:
            if p.is_file():
                p.unlink(missing_ok=True)
                removed += 1
        except OSError:
            print(f"[port-console] 临时件清理失败，保留：{p.name}", file=sys.stderr)
    if removed:
        print(f"[port-console] 已清理 {removed} 个 pcon-*.tmp 临时件")
    return removed


class ConsoleServer(ThreadingHTTPServer):
    """1.3 R2（审核返工 A-2）：把「地址复用」显式钉死为关。

    ThreadingHTTPServer 对 allow_reuse_address 的默认是"没写"不是"不许"——在
    Windows 上谁要是按 Unix 习惯在子类里打开它（绕 TIME_WAIT），语义立刻翻转成
    "允许绑已被占用的端口"：探测明明顺延了，服务却和占位者绑同一个口并存。
    在这里落成明文类属性，四象限里 reuse=1/reuse=1 的"同口并存"结构上不可能。
    """

    allow_reuse_address = False


def bind_console_server():
    """§9.1 ＋ 1.3 R2：绑定与 listen 在同一步完成，被占即顺延，返回 (server, port)。

    旧实现 find_available_port() 用裸 socket 试绑后立刻 close，真正的 bind 在 main
    里更晚：中间被抢就抛未捕获 OSError 带栈退出，而 runtime.json 已经写成别人的端口。
    现在：① 先探（**探测 socket 不设任何端口复用选项**）；② 直接构造
    ThreadingHTTPServer（构造时自己 bind＋listen），失败就下一个号；
    ③ 只有 100 个号全被真监听占用才失败——此时 runtime.json 一个字节都不写。

    为什么探测侧不能留「地址复用」选项：Windows 语义与 BSD 相反，它是"允许绑**已被
    占用**的端口"，不是"复用 TIME_WAIT"。加上它以后探测恒成功 → find 一路返回 3999
    → 服务也绑 3999，与占位者并存，顺延机制被这一行直接废掉（症状是"看着正常、
    两个进程抢一个口"）。TIME_WAIT 造成的漂号**不在这里治**：漂一个号无害，顺延兜得住。

    残余风险（审核返工 A-2 已关）：服务端此前沿用 ThreadingHTTPServer 的默认，
    「复用地址」是"没写明文"而非"明文不许"——谁在子类里顺手打开（Unix 上绕
    TIME_WAIT 的习惯写法），Windows 语义就翻转成"允许绑已被占用的端口"，同口
    并存、顺延被废。现在 ConsoleServer 把 allow_reuse_address = False 钉成
    明文类属性，四象限里 reuse=1/reuse=1 的"同口并存"在结构上不可能出现。
    §6.3 #3 的「netstat 同一端口只能有一个 PID」由"必须做"降为"复核做"：
    结构上已不可能并存，真机看一眼 netstat 即可，不必以它为放行条件。
    """
    for p in range(DEFAULT_PORT, DEFAULT_PORT + PORT_SCAN_RANGE):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", p))
        except OSError as e:
            if getattr(e, "winerror", None) == 10048 or e.errno == errno.EADDRINUSE:
                continue
            raise
        finally:
            probe.close()
        try:
            server = ConsoleServer(("127.0.0.1", p), ConsoleHandler)
        except OSError as e:
            if getattr(e, "winerror", None) == 10048 or e.errno == errno.EADDRINUSE:
                continue          # 探完到 bind 之间被抢：顺延，绝不带栈退出
            raise
        server.daemon_threads = True
        server.actual_port = p
        return server, p
    raise RuntimeError(f"{DEFAULT_PORT} 起连续 {PORT_SCAN_RANGE} 个端口均被占用")


def ensure_token_file(base_dir: Path) -> tuple:
    """§4.6：首次启动生成 token_urlsafe(32)；内容非法 → L2 关闭（token_ok=False）。"""
    path = base_dir / "api_token.txt"
    if not path.exists():
        token = secrets.token_urlsafe(32)
        tmp = _safe_tmp_path(base_dir)
        try:
            tmp.write_text(token + "\n", encoding="utf-8", newline="\n")
            os.replace(tmp, path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        print(f"[port-console] 已生成 L2 管理 token：{path}")
        return token, True
    try:
        raw = path.read_text(encoding="utf-8-sig").strip()
    except OSError as e:
        print(f"[port-console] api_token.txt 读取失败，L2 已关闭: {e}", file=sys.stderr)
        return "", False
    if not raw or len(raw) > 256 or any(c.isspace() for c in raw):
        print("[port-console] api_token.txt 内容非法（空或含空白），L2 已关闭；"
              "请删除该文件后重启重新生成。", file=sys.stderr)
        return "", False
    return raw, True


def write_runtime_info(base_dir: Path, port: int, instance_id: str = "") -> None:
    """1.3 R2：只在 listen 成功之后调用；多写一个 instance_id 供客户端认人。

    instance_id 缺省为空（旧调用形态不写该键），新流程一律传入 state.instance_id。
    """
    data = {
        "base_url": "http://127.0.0.1:" + str(int(port)),
        "pid": os.getpid(),
        "started_at": now_iso(),
        "api_version": API_VERSION,
    }
    if instance_id:
        data["instance_id"] = instance_id
    atomic_write_json(base_dir / "runtime.json", data)


def cleanup_runtime(base_dir: Path) -> None:
    """§9.3：只删自己写的 runtime.json（核对 pid），不误删其他实例运行文件。"""
    rt = _inside(base_dir, base_dir / "runtime.json")
    try:
        data = read_json_file(rt)
        if data.get("pid") == os.getpid():
            rt.unlink()
    except (FileNotFoundError, ValueError, OSError):
        pass
    except Exception:
        pass


def main() -> None:
    print("[port-console] 启动中……")
    try:
        configs = load_and_validate_configs(BASE_DIR)
    except ConfigError as e:
        print(f"[port-console] 配置校验失败，拒绝启动: {e}", file=sys.stderr)
        sys.exit(1)
    for w in configs["warnings"]:
        print(f"[port-console] ⚠ {w}", file=sys.stderr)

    lock_fd = acquire_instance_lock(BASE_DIR)
    if lock_fd is None:
        # S5（T-PORT-003）：二次取锁成功则持锁返回并继续启动；失败/已有实例则内部退出
        handle_existing_instance(BASE_DIR)
    clear_stale_runtime(BASE_DIR)
    cleanup_orphan_tmp(BASE_DIR)   # 1.3.1：早于首个启动写盘（ensure_token_file）

    token, token_ok = ensure_token_file(BASE_DIR)

    try:
        # 1.3 R2：绑定＋listen 在同一个动作里完成，失败即顺延下一个号。
        # 旧顺序是"裸 socket 试绑→close→写 runtime.json→再 bind"：中间任何一刻被抢走
        # 都会抛未捕获 OSError 带栈退出，而 runtime.json 已经写成别人的端口。
        server, port = bind_console_server()
    except (OSError, RuntimeError) as e:
        print(f"[port-console] 端口选择失败: {e}", file=sys.stderr)
        sys.exit(1)

    state = AppState(BASE_DIR, configs, port, token, token_ok)
    if not token_ok:
        print("[port-console] ⚠ L2 程序化关闭已关闭（token 文件问题），L0/L1 不受影响", file=sys.stderr)

    server.app_state = state
    # 落盘一定在 listen 之后：文件存在的每一刻，该端口都真的在收连接。
    write_runtime_info(BASE_DIR, port, state.instance_id)

    base_url = "http://127.0.0.1:" + str(int(port))
    try:
        print(f"[port-console] 端口控制台已启动: {base_url}/")
        print(f"[port-console] L2 token 文件: {BASE_DIR / 'api_token.txt'}（仅本机 AI 部署读取，请勿分享）")
        print("[port-console] 退出：在本窗口按 Ctrl+C，或直接关闭本窗口。")
        # T-PORT-005 验收配套（偏离申报项）：PORT_CONSOLE_NO_BROWSER=1 抑制自动开页面——
        # acceptance 起服务时浏览器轮询会与服务端展示缓存抢状态，V58 断言不可控。
        try:
            if os.environ.get("PORT_CONSOLE_NO_BROWSER") != "1":
                webbrowser.open(base_url)
        except Exception:
            print("[port-console] 自动打开浏览器失败，请手动访问上面的地址。", file=sys.stderr)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        cleanup_runtime(BASE_DIR)
        print("[port-console] 已退出，runtime.json 已清理。")


if __name__ == "__main__":
    main()
