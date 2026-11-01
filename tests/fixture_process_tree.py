# -*- coding: utf-8 -*-
"""进程树测试夹具（fixture_process_tree.py）。
- --listen PORT            ：仅监听模式（子进程用）
- --port A --child-port B  ：父监听 A，启动子监听 B，READY 后打印 JSON（含父/子 PID）
- --orphan                 ：父启动子后立即退出（父先退、子残留场景）
夹具无窗口、只监听 127.0.0.1、不写文件、不联网（仅回环 accept）。"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time

CREATE_NO_WINDOW = 0x08000000


def listen_forever(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(5)
    try:
        while True:
            try:
                c, _ = s.accept()
                c.close()
            except OSError:
                break
    finally:
        s.close()


def wait_port_open(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            c.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, help="仅监听模式")
    ap.add_argument("--port", type=int, help="父监听端口")
    ap.add_argument("--child-port", type=int, default=None, help="子进程监听端口")
    ap.add_argument("--orphan", action="store_true", help="父启动子后立即退出")
    args = ap.parse_args()

    if args.listen is not None:
        listen_forever(args.listen)
        return

    if args.port is None:
        print("需要 --listen 或 --port", file=sys.stderr)
        sys.exit(2)

    child = None
    if args.child_port:
        child = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__),
             "--listen", str(args.child_port)],
            creationflags=CREATE_NO_WINDOW)
        if not wait_port_open(args.child_port):
            print("child failed to listen", file=sys.stderr)
            sys.exit(3)

    if args.orphan:
        # 父先退：子进程独立存活（Windows 无进程组绑定），端口 B 残留
        return

    print(json.dumps({"pid": os.getpid(),
                      "child_pid": child.pid if child else None}), flush=True)
    listen_forever(args.port)


if __name__ == "__main__":
    main()
