"""Run curated detection / alert-accuracy regression scripts."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(ROOT, "scripts")

# Curated detection-layer suite — state machine, probes, pause, config, restart.
DETECTION_REGRESSION_SCRIPTS = (
    "verify_bugs_34.py",
    "round_b_state_machine.py",
    "verify_bugs_30.py",
    "verify_bugs_128.py",
    "verify_bugs_17_18.py",
    "verify_bugs_130.py",
    "verify_bugs_104.py",
    "verify_bugs_160.py",
    "verify_bugs_87.py",
    "verify_bugs_63.py",
    "verify_detection_restart_state.py",
    "verify_dns_monitor_probe.py",
    "round_d_config_edit.py",
    "round_f_alert_boundary.py",
    "round_e_thread_safety.py",
    "verify_bugs_141.py",
    "verify_icmp_diag_net_unreachable.py",
    "verify_web_alert_history_tid.py",
)


def main():
    failed = []
    for name in DETECTION_REGRESSION_SCRIPTS:
        path = os.path.join(SCRIPTS_DIR, name)
        if not os.path.isfile(path):
            print(f"SKIP missing {name}")
            failed.append(name)
            continue
        print(f"--- {name} ---")
        r = subprocess.run(
            [sys.executable, path],
            cwd=ROOT,
            check=False,
        )
        if r.returncode != 0:
            failed.append(name)
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print(f"All {len(DETECTION_REGRESSION_SCRIPTS)} detection regressions passed.")


if __name__ == "__main__":
    main()
