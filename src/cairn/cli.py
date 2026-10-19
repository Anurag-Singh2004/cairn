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
    elif (run_dir.parent.parent / "keys" / "ref_ed25519.pub").is_file():
        pubkey_path = run_dir.parent.parent / "keys" / "ref_ed25519.pub"
    elif (run_dir.parent / "keys" / "ref_ed25519.pub").is_file():
        pubkey_path = run_dir.parent / "keys" / "ref_ed25519.pub"
    else:
        pubkey_path = Path("keys") / "ref_ed25519.pub"

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


def cmd_report(args: argparse.Namespace) -> int:
    """Generate offline HTML assurance report."""
    from cairn.referee.evidence import EvidenceStore
    from cairn.referee.report import generate_html_report

    run_dir = Path("runs") / args.run if not Path(args.run).is_dir() else Path(args.run)
    db_path = run_dir / "evidence.db"
    if not db_path.is_file():
        print(f"Error: Evidence database not found: {db_path}", file=sys.stderr)
        return 2

    store = EvidenceStore(db_path)
    out_file = Path(args.out) if args.out else run_dir / "report.html"
    report_path = generate_html_report(run_id=args.run, store=store, out_path=out_file)
    print(f"Generated offline HTML report: {report_path}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Execute a benchmark run."""
    from cairn.referee.runner import run_benchmark

    run_dir = run_benchmark(
        tier=args.tier,
        pack_path=args.pack,
        policy_path=args.policy,
        fault_specs=args.inject_fault,
        burn_cpu=args.burn,
        run_id=args.run,
    )
    print(f"\n[BENCHMARK COMPLETE] Tier: {args.tier.upper()} · Run Directory: {run_dir}")
    print(f"  Receipts: {run_dir / 'receipts'}")
    print(f"  Report:   {run_dir / 'report.html'}")
    print(f"  Results:  {run_dir / 'results.json'}\n")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Execute full end-to-end demo workflow per context.md §14 and flow.md §5 M6."""
    import copy

    from cairn.referee.results_doc import generate_results_markdown
    from cairn.referee.runner import run_benchmark

    print("=" * 70)
    print("CAIRN DEMO — STARTING AUTOMATED END-TO-END ASSURANCE WORKFLOW")
    print("=" * 70)

    pack_path = Path("data/attack_packs/demo.json")
    policy_path = Path("data/policies/demo_blue.json")

    # 1. Run T0 (leaky baseline positive control)
    print("\n[Step 1/6] Running T0 Leaky Baseline Positive Control...")
    t0_dir = run_benchmark("t0", pack_path, policy_path, run_id="r_demo_t0")
    print(f"  T0 run completed: {t0_dir}")

    # 2. Run T1 (hardened tier)
    print("\n[Step 2/6] Running T1 Hardened Isolation Tier...")
    t1_dir = run_benchmark("t1", pack_path, policy_path, run_id="r_demo_t1")
    print(f"  T1 run completed: {t1_dir}")

    # 3. Run Fault Injection Run (environmental interference)
    print("\n[Step 3/6] Running Environmental Fault Injection Run (blue_timeout@f_005)...")
    fault_dir = run_benchmark(
        "t1",
        pack_path,
        policy_path,
        fault_specs=["blue_timeout@f_005"],
        burn_cpu=True,
        run_id="r_demo_fault",
    )
    print(f"  Fault injection run completed: {fault_dir}")

    # 4. Verify Untouched T1 Receipt
    print("\n[Step 4/6] Verifying Untouched T1 Finding Receipt...")
    receipt_files = sorted(list((t1_dir / "receipts").glob("receipt_*.json")))
    if not receipt_files:
        print("Error: No receipts generated for T1", file=sys.stderr)
        return 1
    sample_receipt = receipt_files[0]
    with open(sample_receipt, encoding="utf-8") as f:
        receipt_data = json.load(f)
    ok, msg = verify_receipt_data(receipt_data)
    if not ok:
        print(f"Failed to verify untouched receipt: {msg}", file=sys.stderr)
        return 1
    print(f"  PASS: Untouched receipt {sample_receipt.name} verified successfully: {msg}")

    # 5. Tamper Demo: mutate 1 byte in copy and verify fails
    print("\n[Step 5/6] Executing Tamper Demo (C8 Byte Mutation)...")
    tampered_copy = copy.deepcopy(receipt_data)
    tampered_copy["events"][0]["body"]["tampered"] = True
    ok_tamper, msg_tamper = verify_receipt_data(tampered_copy)
    if ok_tamper:
        print("ERROR: Tampered receipt unexpectedly passed verification!", file=sys.stderr)
        return 1
    print(f"  PASS: Tampered receipt was successfully rejected: {msg_tamper}")

    # 6. Offline Witness Checkpoint Hash & Results Generation
    print("\n[Step 6/6] Reading Offline Witness Checkpoint Hashes & Writing docs/RESULTS.md...")
    t1_results = json.loads((t1_dir / "results.json").read_text(encoding="utf-8"))
    t0_results = json.loads((t0_dir / "results.json").read_text(encoding="utf-8"))
    fault_results = json.loads((fault_dir / "results.json").read_text(encoding="utf-8"))

    t1_cp = t1_results["final_checkpoint"]
    print(f"  T1 Signed Checkpoint Root: {t1_cp['root']}")
    print(f"  T1 Checkpoint Run ID:      {t1_cp['run']}")
    print(f"  T1 Checkpoint Tree Size:   {t1_cp['tree_size']}")

    results_path = generate_results_markdown(
        t0_results, t1_results, fault_results, Path("docs/RESULTS.md")
    )
    print(f"  Wrote comprehensive comparison to: {results_path}")

    print("\n" + "=" * 70)
    print("CAIRN DEMO COMPLETED SUCCESSFULLY — ALL SECURITY CONTROLS VERIFIED")
    print("=" * 70 + "\n")
    return 0


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

    # report
    parser_report = subparsers.add_parser("report", help="Generate offline HTML assurance report")
    parser_report.add_argument("--run", required=True, help="Run ID or path to run directory")
    parser_report.add_argument(
        "--out", default=None, help="Output HTML file path (default: runs/<id>/report.html)"
    )
    parser_report.set_defaults(func=cmd_report)

    # run
    parser_run = subparsers.add_parser("run", help="Execute an assurance benchmark run")
    parser_run.add_argument(
        "--tier", default="t1", choices=["t0", "t1"], help="Target tier (t0 or t1)"
    )
    parser_run.add_argument(
        "--pack", default="data/attack_packs/demo.json", help="Path to attack pack JSON"
    )
    parser_run.add_argument(
        "--policy", default="data/policies/demo_blue.json", help="Path to blue policy JSON"
    )
    parser_run.add_argument(
        "--inject-fault", action="append", default=None, help="Inject fault: <fault>@<finding>"
    )
    parser_run.add_argument(
        "--burn", action="store_true", default=False, help="Burn CPU cycles during run"
    )
    parser_run.add_argument("--run", dest="run", default=None, help="Explicit run ID")
    parser_run.set_defaults(func=cmd_run)

    # demo
    parser_demo = subparsers.add_parser(
        "demo", help="Execute automated full end-to-end assurance demo"
    )
    parser_demo.set_defaults(func=cmd_demo)

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
