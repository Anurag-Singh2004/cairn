"""Network reachability and egress probe running inside containers for C3 matrix."""

from __future__ import annotations

import argparse
import json
import socket
import sys


def probe_tcp(host: str, port: int, timeout_s: float = 1.0) -> bool:
    """Attempt TCP connection to host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def probe_external_egress(timeout_s: float = 1.0) -> bool:
    """Check for external egress to common public DNS IPs."""
    return any(probe_tcp(ip, 53, timeout_s) for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cairn.netprobe")
    parser.add_argument("--targets", nargs="*", default=[], help="Targets as host:port")
    parser.add_argument("--check-egress", action="store_true")
    args = parser.parse_args(argv)

    edges: list[dict[str, object]] = []
    for target in args.targets:
        if ":" in target:
            host, port_str = target.split(":", 1)
            port = int(port_str)
            reachable = probe_tcp(host, port)
            edges.append({"target": host, "port": port, "reachable": reachable})

    egress = False
    if args.check_egress:
        egress = probe_external_egress()

    report = {
        "hostname": socket.gethostname(),
        "edges": edges,
        "egress": egress,
    }
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
