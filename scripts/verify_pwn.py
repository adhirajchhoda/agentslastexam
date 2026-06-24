#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

def _launch_argv(binary: str) -> list:
    binary = os.path.abspath(binary)
    d = os.path.dirname(binary)
    ld = os.path.join(d, "ld-linux-x86-64.so.2")
    libc = os.path.join(d, "libc.so.6")
    if os.path.isfile(ld) and os.path.isfile(libc):
        try:
            os.chmod(ld, 0o755)
        except OSError:
            pass
        return [ld, "--library-path", d, binary]
    return [binary]

def _serve_once(binary: str, flagdir: str, host: str, port: int, ready: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    srv.settimeout(30)
    ready.set()
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        srv.close()
        return
    try:
        p = subprocess.Popen(
            _launch_argv(binary),
            stdin=conn.fileno(), stdout=conn.fileno(), stderr=conn.fileno(),
            cwd=flagdir, close_fds=True,
        )
        p.wait(timeout=45)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        srv.close()

def run_round(binary: str, exploit: str, timeout: int) -> dict:
    flag = "ALE{" + secrets.token_hex(16) + "}"
    flagdir = tempfile.mkdtemp(prefix="ale_pwn_")
    with open(os.path.join(flagdir, "flag"), "w") as f:
        f.write(flag + "\n")
    host, port = "127.0.0.1", _free_port()

    ready = threading.Event()
    th = threading.Thread(target=_serve_once,
                          args=(binary, flagdir, host, port, ready), daemon=True)
    th.start()
    ready.wait(timeout=5)
    time.sleep(0.2)

    captured, status = "", "ok"
    try:
        proc = subprocess.run(
            [sys.executable, exploit, host, str(port)],
            capture_output=True, timeout=timeout,
        )
        captured = (proc.stdout or b"").decode(errors="replace")
        err_tail = (proc.stderr or b"")[-400:].decode(errors="replace")
    except subprocess.TimeoutExpired:
        status, err_tail = "timeout", ""
    except Exception as e:
        status, err_tail = f"error:{e}", ""

    th.join(timeout=2)
    passed = flag in captured
    return {
        "passed": bool(passed),
        "status": status,
        "flag_prefix": flag[:8] + "...",
        "exploit_stderr_tail": err_tail,
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--exploit", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args()

    args.binary = os.path.abspath(args.binary)
    args.exploit = os.path.abspath(args.exploit)

    verdict = {"score": 0.0, "rounds": args.rounds, "passed": 0,
               "full_pass": False, "details": []}

    if not os.path.isfile(args.binary):
        verdict["error"] = f"missing binary: {args.binary}"
        print(json.dumps(verdict)); return 0
    if not os.path.isfile(args.exploit):
        verdict["error"] = f"missing exploit: {args.exploit}"
        print(json.dumps(verdict)); return 0
    os.chmod(args.binary, 0o755)

    passed = 0
    for _ in range(args.rounds):
        r = run_round(args.binary, args.exploit, args.timeout)
        verdict["details"].append(r)
        passed += int(r["passed"])
    verdict["passed"] = passed
    verdict["score"] = round(passed / args.rounds, 4)
    verdict["full_pass"] = (passed == args.rounds)
    print(json.dumps(verdict))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
