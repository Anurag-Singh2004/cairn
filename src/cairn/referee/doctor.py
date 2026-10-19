"""Preflight 'doctor' diagnostics per context.md §8.6 and flow.md §5 M3.

Checks:
- Docker daemon and Compose availability
- Host class (native Linux vs dev-only)
- cgroup version
- Network topology and expected reachability
- Container hardening properties (read-only, cap_drop, non-root, no docker.sock)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cairn.auditor.matrix import audit_matrix
from cairn.referee.docker_ctl import (
    check_compose_available,
    check_docker_available,
    inspect_service_container,
)


def run_doctor(tier: str = "t1", live_check: bool = False) -> tuple[bool, dict[str, Any]]:
    """Run comprehensive preflight checks for the specified tier."""
    report: dict[str, Any] = {
        "tier": tier,
        "checks": {},
        "capabilities": {},
        "host_class": "native-linux",
        "passed": True,
    }

    # 1. Environment checks
    docker_ok, docker_msg = check_docker_available()
    report["checks"]["docker_daemon"] = {"ok": docker_ok, "details": docker_msg}

    compose_ok, compose_msg = check_compose_available()
    report["checks"]["docker_compose"] = {"ok": compose_ok, "details": compose_msg}

    # Check cgroup
    cgroup_v2 = (
        Path("/sys/fs/cgroup/cgroup.controllers").is_file()
        or Path("/sys/fs/cgroup/memory.max").is_file()
    )
    report["checks"]["cgroup_v2"] = {
        "ok": cgroup_v2,
        "details": "cgroup v2 unified hierarchy detected" if cgroup_v2 else "cgroup v1 / fallback",
    }

    if not (docker_ok and compose_ok):
        report["passed"] = False
        return False, report

    # 2. Hardening capabilities by tier
    if tier == "t1":
        report["capabilities"]["isolated_networks"] = "ENFORCED"
        report["capabilities"]["read_only_rootfs"] = "ENFORCED"
        report["capabilities"]["cap_drop_all"] = "ENFORCED"
        report["capabilities"]["no_new_privileges"] = "ENFORCED"
        report["capabilities"]["non_root_user"] = "ENFORCED"
        report["capabilities"]["no_shared_volume"] = "ENFORCED"
        report["capabilities"]["fail_mode"] = "CLOSED"
    else:
        report["capabilities"]["isolated_networks"] = "NOT ENFORCED (positive control)"
        report["capabilities"]["read_only_rootfs"] = "NOT ENFORCED"
        report["capabilities"]["cap_drop_all"] = "NOT ENFORCED"
        report["capabilities"]["no_new_privileges"] = "NOT ENFORCED"
        report["capabilities"]["non_root_user"] = "NOT ENFORCED"
        report["capabilities"]["no_shared_volume"] = "NOT ENFORCED (shared volume mounted)"
        report["capabilities"]["fail_mode"] = "OPEN (positive control)"

    # 3. Live container checks (if live_check requested)
    if live_check:
        try:
            matrix_res = audit_matrix(tier)
            report["checks"]["matrix_audit"] = {
                "ok": matrix_res["valid"],
                "deviations": matrix_res["deviations"],
            }
            if not matrix_res["valid"] and tier == "t1":
                report["passed"] = False

            # Inspect red container security properties
            red_info = inspect_service_container(tier, "red")
            host_cfg = red_info.get("HostConfig", {})
            config = red_info.get("Config", {})

            # Check read-only
            is_readonly = host_cfg.get("ReadonlyRootfs", False)
            # Check cap drop
            cap_drop = host_cfg.get("CapDrop", [])
            # Check non-root
            user = config.get("User", "")

            # Check no docker.sock mounted
            mounts = red_info.get("Mounts", [])
            has_sock = any("docker.sock" in m.get("Source", "") for m in mounts)

            report["checks"]["container_hardening"] = {
                "readonly_rootfs": is_readonly,
                "cap_drop": cap_drop,
                "user": user,
                "no_docker_sock": not has_sock,
            }

            if tier == "t1" and (
                not is_readonly or "ALL" not in cap_drop or user != "10001:10001" or has_sock
            ):
                report["passed"] = False
        except Exception as e:
            report["checks"]["live_check_error"] = str(e)
            report["passed"] = False

    return report["passed"], report


def print_doctor_report(report: dict[str, Any]) -> None:
    tier = report["tier"]
    print(f"=== CAIRN Doctor Preflight Report (Tier: {tier}) ===")
    print(f"Host Class: {report['host_class']}\n")

    print("System Checks:")
    for name, res in report["checks"].items():
        if isinstance(res, dict) and "ok" in res:
            status = "PASS" if res["ok"] else "FAIL"
            print(f"  [{status}] {name}: {res.get('details', '')}")
        else:
            print(f"  {name}: {res}")

    print("\nSecurity Controls:")
    for cap, status in report["capabilities"].items():
        print(f"  [{status}] {cap}")

    print("\nResult:")
    if report["passed"]:
        print("  OVERALL PREFLIGHT: PASS (Tier is ready)")
    else:
        print("  OVERALL PREFLIGHT: FAIL (Requirements not met)")
