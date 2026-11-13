"""Command line entry point.

  python -m secretscan scan PATH [--baseline FILE] [--update-baseline] [--sarif FILE] [--requirements FILE]
  python -m secretscan demo

`scan` exits 1 when there are new findings, so it can gate a CI job.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from .deps import check_requirements, load_advisories
from .report import Baseline, to_sarif
from .secrets import scan_path

ADVISORIES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "advisories.json")


def run_scan(args) -> int:
    findings = scan_path(args.path, args.entropy)
    baseline = Baseline.load(args.baseline) if args.baseline else Baseline()
    if args.update_baseline:
        baseline.save(args.baseline, findings)
        print(f"baseline written: {len({f.fingerprint for f in findings})} accepted finding(s)")
        return 0
    new = baseline.new(findings)
    for f in new:
        print(f"{f.severity.upper():<6} {f.location():<34} {f.rule:<30} {f.preview}")
    print(f"secrets: {len(new)} new, {len(findings) - len(new)} in baseline")
    hits, unpinned = [], []
    if args.requirements:
        with open(args.requirements, encoding="utf-8") as fh:
            hits, unpinned = check_requirements(fh.read(), load_advisories(args.advisories))
        for h in hits:
            print(f"VULN   {h['package']}=={h['installed']:<10} {h['id']}  fixed in {h['fixed_in']}: {h['summary']}")
        for line in unpinned:
            print(f"UNPIN  {line}")
        print(f"dependencies: {len(hits)} vulnerable, {len(unpinned)} unpinned")
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(new), fh, indent=2)
    return 1 if new or hits else 0


def demo() -> int:
    """Scan a small throwaway project. The 'secrets' are assembled here at run time
    and are random-looking fakes, so this repository never contains a key-shaped string."""
    fake_aws = "AKIA" + "Q7ZP2M4XK9WJ5TLD"
    fake_gh = "ghp_" + "a8Kq2LmZ9xVb4TnR7cYw1DfH6sJp3GuE5oQi"
    fake_generic = "f9K2" + "mQ7xLp4ZtR8vWc1N"
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "app"))
        os.makedirs(os.path.join(root, "node_modules", "lib"))
        files = {
            "app/config.py": f'AWS_KEY = "{fake_aws}"\nDB_URL = "postgres://app:{fake_generic}@db.internal/prod"\nDEBUG = False\n',
            "app/client.py": f'api_token = "{fake_generic}"\npassword = "changeme"\nlegacy_token = "{fake_gh}"  # secretscan:ignore\n',
            "deploy.sh": f"export GH_TOKEN={fake_gh}\n",
            "README.md": 'Set `password = "your_password_here"` in the config.\n',
            "node_modules/lib/index.js": f'var k = "{fake_aws}";\n',
            "requirements.txt": "requests==2.25.1\nPyYAML==5.3.1\nurllib3==1.26.18\nflask>=2.0\n",
        }
        for name, body in files.items():
            with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        common = dict(path=root, entropy=3.5, advisories=ADVISORIES, sarif=None)
        baseline = os.path.join(root, ".secretscan-baseline.json")

        print("1. First scan of the project")
        code = run_scan(argparse.Namespace(baseline=None, update_baseline=False, requirements=os.path.join(root, "requirements.txt"), **common))
        print(f"   exit code {code}\n")

        print("2. Accept what exists today as the baseline")
        run_scan(argparse.Namespace(baseline=baseline, update_baseline=True, requirements=None, **common))
        print()

        print("3. Someone commits a new key; only the new one is reported")
        with open(os.path.join(root, "app", "payments.py"), "w", encoding="utf-8") as fh:
            fh.write('STRIPE = "' + "sk_live_" + "Zx81QmLp04TrVb7NcKd2WyHs" + '"\n')
        code = run_scan(argparse.Namespace(baseline=baseline, update_baseline=False, requirements=None, **common))
        print(f"   exit code {code}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="secretscan")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("path")
    scan.add_argument("--baseline")
    scan.add_argument("--update-baseline", action="store_true")
    scan.add_argument("--sarif")
    scan.add_argument("--requirements")
    scan.add_argument("--advisories", default=ADVISORIES)
    scan.add_argument("--entropy", type=float, default=3.5)
    sub.add_parser("demo")
    args = parser.parse_args(argv)
    if args.command == "scan" and args.update_baseline and not args.baseline:
        parser.error("--update-baseline needs --baseline FILE")
    return demo() if args.command == "demo" else run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
