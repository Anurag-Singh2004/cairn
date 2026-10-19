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


def cmd_certify(args: argparse.Namespace) -> int:
    """Evaluate validity certificates and generate receipts for a run."""
    from cairn.crypto.keys import public_key_to_b64
    from cairn.referee.evidence import EvidenceStore
    from cairn.referee.receipts import generate_all_receipts_for_run

    run_dir = Path("runs") / args.run if not Path(args.run).is_dir() else Path(args.run)
    db_path = run_dir / "evidence.db"
    if not db_path.is_file():
        print(f"Error: Evidence database not found: {db_path}", file=sys.stderr)
        return 2

    store = EvidenceStore(db_path)
    latest_cp = store.get_latest_checkpoint()
    if not latest_cp:
        print(f"Error: No signed checkpoint found for run {args.run}", file=sys.stderr)
        return 2

    manifest = {}
    commitments = {}
    for ev in store.get_events():
        if ev.kind == "manifest.frozen":
            manifest = ev.body
        elif ev.kind == "reveal.verification":
            commitments = ev.body

    import os

    key_dir_env = os.environ.get("CAIRN_KEY_DIR")
    pubkey_arg = getattr(args, "pubkey", None)
    pubkey_path = None
    if pubkey_arg:
        pubkey_path = Path(pubkey_arg)
    elif key_dir_env:
        pubkey_path = Path(key_dir_env) / "ref_ed25519.pub"
    else:
        candidate = Path("keys") / "ref_ed25519.pub"
        if (
            not candidate.is_file()
            and (run_dir.parent.parent / "keys" / "ref_ed25519.pub").is_file()
        ):
            candidate = run_dir.parent.parent / "keys" / "ref_ed25519.pub"
        pubkey_path = candidate

    pubkey_b64 = ""
    if pubkey_path and pubkey_path.is_file():
        pk = load_public_key(pubkey_path)
        pubkey_b64 = public_key_to_b64(pk)

    out_receipts_dir = run_dir / "receipts"
    receipts = generate_all_receipts_for_run(
        store=store,
        checkpoint=latest_cp.checkpoint,
        signature=latest_cp.signature,
        public_key_b64=pubkey_b64,
        manifest=manifest,
        commitments=commitments,
        out_dir=out_receipts_dir,
    )

    print("\n" + "=" * 78)
    print(f"CAIRN RUN VALIDITY CERTIFICATES: {args.run}")
    print("=" * 78)
    cols = ["I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "I9"]
    col_hdr = " ".join(f"{c:<3}" for c in cols)
    header = f"{'Finding':<10} {'Status':<22} {col_hdr} {'Sim':<5}"
    print(header)
    print("-" * 78)

    def _mark(inv_name: str, invs_dict: dict) -> str:
        res = invs_dict.get(inv_name, {}).get("result", "?")
        if res == "pass":
            return "P"
        if res == "fail":
            return "F"
        return "W" if res == "warn" else "M"

    all_valid = True
    certs_data = {}
    for finding, r in sorted(receipts.items()):
        c = r.certificate
        status = c["status"]
        if status in ("QUARANTINED", "INCOMPLETE"):
            all_valid = False
        invs = c.get("invariants", {})
        marks = " ".join(f"{_mark(col, invs):<3}" for col in cols)
        row = f"{finding:<10} {status:<22} {marks} {'YES' if c.get('simulated') else 'NO':<5}"
        print(row)
        certs_data[finding] = c

    print("-" * 78)
    certs_file = run_dir / "certificates.json"
    certs_file.write_text(json.dumps(certs_data, indent=2), encoding="utf-8")
    print(f"Generated {len(receipts)} receipts in: {out_receipts_dir}")
    print(f"Saved certificates summary to: {certs_file}")
    print("=" * 78 + "\n")

    return 0 if all_valid else 1


def cmd_verify_run(args: argparse.Namespace) -> int:
    """Verify all offline receipts for a run."""
    run_dir = Path("runs") / args.run if not Path(args.run).is_dir() else Path(args.run)
    receipts_dir = run_dir / "receipts"
    if not receipts_dir.is_dir():
        print(f"Error: Receipts directory not found: {receipts_dir}", file=sys.stderr)
        return 2

    receipt_files = sorted(receipts_dir.glob("receipt_*.json"))
    if not receipt_files:
        print(f"Error: No receipts found in {receipts_dir}", file=sys.stderr)
        return 2

    print(f"\nVerifying {len(receipt_files)} receipts for run: {args.run}")
    print("-" * 65)

    all_passed = True
    for rf in receipt_files:
        with open(rf, encoding="utf-8") as f:
            receipt = json.load(f)
        ok, msg = verify_receipt_data(receipt)
        status_tag = "VALID" if ok else "FAILED"
        print(f"[{status_tag}] {rf.name:<30} {msg}")
        if not ok:
            all_passed = False

    print("-" * 65)
    if all_passed:
        print("All receipts verified successfully (Exit code: 0)\n")
        return 0
    else:
        print("One or more receipts failed verification (Exit code: 1)\n", file=sys.stderr)
        return 1


def cmd_doctor(args: argparse.Namespace) -> int:
    """Execute preflight doctor diagnostics."""
    from cairn.referee.doctor import print_doctor_report, run_doctor

    ok, report = run_doctor(tier=args.tier, live_check=args.live)
    print_doctor_report(report)
    return 0 if ok else 3


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

    # doctor
    parser_doctor = subparsers.add_parser("doctor", help="Preflight environment and tier doctor")
    parser_doctor.add_argument(
        "--tier",
        default="t1",
        choices=["t0", "t1"],
        help="Target tier to inspect (default: t1)",
    )
    parser_doctor.add_argument(
        "--live",
        action="store_true",
        help="Perform live container network and security audit (requires running containers)",
    )
    parser_doctor.set_defaults(func=cmd_doctor)

    # certify
    parser_certify = subparsers.add_parser(
        "certify", help="Evaluate certificates and generate receipts for a run"
    )
    parser_certify.add_argument("--run", required=True, help="Run ID or path to run directory")
    parser_certify.add_argument("--pubkey", default=None, help="Path to referee public key")
    parser_certify.set_defaults(func=cmd_certify)

    # verify-run
    parser_verify_run = subparsers.add_parser(
        "verify-run", help="Verify all offline receipts for a run"
    )
    parser_verify_run.add_argument("--run", required=True, help="Run ID or path to run directory")
    parser_verify_run.set_defaults(func=cmd_verify_run)

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
