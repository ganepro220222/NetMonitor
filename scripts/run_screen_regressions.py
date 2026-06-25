"""Run screen / bigscreen dashboard regression scripts."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = (
    "verify_screen_dashboard.py",
    "verify_web_alert_history_tid.py",
)


def main():
    failed = []
    for name in SCRIPTS:
        path = os.path.join(ROOT, "scripts", name)
        print(f"--- {name} ---")
        r = subprocess.run([sys.executable, path], cwd=ROOT, check=False)
        if r.returncode != 0:
            failed.append(name)
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print(f"All {len(SCRIPTS)} screen regressions passed.")


if __name__ == "__main__":
    main()
