"""Command-line interface for CAIRN per context.md §14.

Uses stdlib argparse exclusively per DEC-18.
Exit codes per context.md §13:
  0: success / valid
  1: verification failed / invariant check failed
  2: usage / configuration error
  3: environment / preflight error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cairn.common.errors import CairnError
from cairn.crypto.keys import generate_keypair, load_public_key, save_keypair
from cairn.referee.verify import verify_receipt_data


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate Ed25519 referee keypair."""
    key_dir = Path(args.dir)
    priv, _pub = generate_keypair()
    priv_path, pub_path = save_keypair(priv, key_dir, args.name)
    print(f"Generated Ed25519 keypair in {key_dir}:")
    print(f"  Private key (0600): {priv_path}")
    print(f"  Public key:         {pub_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify an offline receipt file."""
    receipt_path = Path(args.receipt)
    if not receipt_path.is_file():
        print(f"Error: Receipt file not found: {receipt_path}", file=sys.stderr)
        return 2

    try:
        with open(receipt_path, encoding="utf-8") as f:
            receipt = json.load(f)
    except Exception as e:
        print(f"Error reading receipt JSON: {e}", file=sys.stderr)
        return 2

    pubkey = None
    if args.pubkey:
        pubkey_path = Path(args.pubkey)
        if not pubkey_path.is_file():
            print(f"Error: Public key file not found: {pubkey_path}", file=sys.stderr)
            return 2
        try:
            pubkey = load_public_key(pubkey_path)
        except Exception as e:
            print(f"Error loading public key: {e}", file=sys.stderr)
            return 2

    ok, message = verify_receipt_data(receipt, pubkey)
    if ok:
        print(f"VALID: {message}")
        return 0
    else:
        print(f"FAILED: {message}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cairn",
        description="CAIRN — Measured, Signed Isolation for Adversarial AI Safety Testing",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # keygen
    parser_keygen = subparsers.add_parser("keygen", help="Generate Ed25519 referee keypair")
    parser_keygen.add_argument(
        "--dir",
        default="keys",
        help="Directory to store keypair (default: keys/)",
    )
    parser_keygen.add_argument(
        "--name",
        default="ref_ed25519",
        help="Key filename base (default: ref_ed25519)",
    )
    parser_keygen.set_defaults(func=cmd_keygen)

    # verify
    parser_verify = subparsers.add_parser("verify", help="Verify offline receipt JSON")
    parser_verify.add_argument("receipt", help="Path to receipt JSON file")
    parser_verify.add_argument(
        "--pubkey",
        default=None,
        help="Path to referee public key (optional if embedded in receipt)",
    )
    parser_verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 2

    try:
        return args.func(args)
    except CairnError as e:
        print(f"Error: {e}", file=sys.stderr)
        return e.exit_code
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
