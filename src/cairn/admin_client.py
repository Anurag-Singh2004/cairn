"""Admin client running inside Switchboard container communicating via UDS.

Implements context.md §5 (DEC-3):
Reached from host via:
docker compose exec -T switchboard python -m cairn.admin_client <command> [args]
"""

from __future__ import annotations

import argparse
import json
import sys

import httpx

ADMIN_UDS_PATH = "/run/cairn/admin.sock"


def get_client() -> httpx.Client:
    transport = httpx.HTTPTransport(uds=ADMIN_UDS_PATH)
    return httpx.Client(transport=transport, base_url="http://admin")


def cmd_configure(args: argparse.Namespace) -> int:
    with open(args.config, encoding="utf-8") as f:
        tier_cfg = json.load(f)

    payload = {
        "run_id": args.run,
        "pubkey_b64": args.pubkey,
        "tier_config": tier_cfg,
        "secret_flag": args.secret_flag or "",
        "secret_flag_hex": args.secret_flag_hex or "",
        "canaries": args.canaries or [],
    }
    with get_client() as client:
        resp = client.post("/admin/run/configure", json=payload)
        print(resp.text)
        return 0 if resp.status_code == 200 else 1


def cmd_state(args: argparse.Namespace) -> int:
    with get_client() as client:
        resp = client.post("/admin/run/state", json={"state": args.state})
        print(resp.text)
        return 0 if resp.status_code == 200 else 1


def cmd_health(args: argparse.Namespace) -> int:
    with get_client() as client:
        resp = client.get("/admin/health")
        print(resp.text)
        return 0 if resp.status_code == 200 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cairn.admin_client")
    subparsers = parser.add_subparsers(dest="subcommand")

    # configure
    p_conf = subparsers.add_parser("configure")
    p_conf.add_argument("--run", required=True)
    p_conf.add_argument("--pubkey", required=True)
    p_conf.add_argument("--config", required=True, help="Path to tier config JSON")
    p_conf.add_argument("--secret-flag", default="")
    p_conf.add_argument("--secret-flag_hex", default="")
    p_conf.add_argument("--canaries", nargs="*", default=[])
    p_conf.set_defaults(func=cmd_configure)

    # state
    p_state = subparsers.add_parser("state")
    p_state.add_argument("--state", required=True)
    p_state.set_defaults(func=cmd_state)

    # health
    p_health = subparsers.add_parser("health")
    p_health.set_defaults(func=cmd_health)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
