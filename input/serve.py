#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import sys

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, help="path to vuln binary")
    ap.add_argument("--flagdir", required=True, help="cwd holding the `flag` file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--once", action="store_true", help="serve a single connection then exit")
    ap.add_argument("--portfile", default="", help="write the bound port here")
    args = ap.parse_args()

    binary = os.path.abspath(args.binary)
    flagdir = os.path.abspath(args.flagdir)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(16)
    bound_port = srv.getsockname()[1]
    if args.portfile:
        with open(args.portfile, "w") as f:
            f.write(str(bound_port))
    print(f"[serve] listening on {args.host}:{bound_port} binary={binary} cwd={flagdir}",
          file=sys.stderr, flush=True)

    while True:
        conn, addr = srv.accept()
        try:
            p = subprocess.Popen(
                [binary],
                stdin=conn.fileno(),
                stdout=conn.fileno(),
                stderr=conn.fileno(),
                cwd=flagdir,
                close_fds=True,
            )
            p.wait(timeout=60)
        except Exception as e:
            print(f"[serve] conn error: {e}", file=sys.stderr, flush=True)
        try:
            conn.close()
        except OSError:
            pass
        if args.once:
            break
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
