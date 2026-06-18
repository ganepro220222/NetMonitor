"""Run webhook/outbox reliability regression scripts."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(ROOT, "scripts")

# Keep verify_webhook_url_boundaries early — hostname allowlist guardrail.
WEBHOOK_REGRESSION_SCRIPTS = (
    "verify_webhook_url_boundaries.py",
    "verify_webhook_error_matrix.py",
    "verify_webhook_recovery_after_url_fix.py",
    "verify_webhook_multi_target_isolation.py",
    "verify_webhook_observability_fields.py",
    "verify_webhook_fail_panel.py",
    "verify_webhook_fail_pill_visibility.py",
    "verify_webhook_api_exception_stability.py",
    "verify_webhook_retention_policy.py",
    "verify_webhook_identity_change.py",
    "verify_bugs_185.py",
    "verify_bugs_186.py",
    "verify_bugs_145.py",
    "verify_bugs_161.py",
    "verify_bugs_163.py",
    "verify_bugs_165.py",
    "verify_bugs_166.py",
    "verify_bugs_169.py",
    "verify_bugs_171.py",
    "verify_bugs_172.py",
    "verify_bugs_174.py",
    "verify_bugs_175.py",
    "verify_bugs_176.py",
    "verify_bugs_182.py",
    "verify_bugs_183.py",
    "verify_bugs_184.py",
)


def main():
    failed = []
    for name in WEBHOOK_REGRESSION_SCRIPTS:
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
    print(f"All {len(WEBHOOK_REGRESSION_SCRIPTS)} webhook regressions passed.")


if __name__ == "__main__":
    main()
