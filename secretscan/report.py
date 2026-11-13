from __future__ import annotations

import json

from .secrets import Finding


class Baseline:
    """Known findings that have been reviewed and accepted.

    Turning a scanner on in an old repository produces a wall of findings. A
    baseline records the ones that exist today so CI fails only on new ones,
    and the old ones can be worked down over time. Entries are fingerprints, so
    the baseline file itself contains no secrets.
    """

    def __init__(self, fingerprints: set[str] | None = None) -> None:
        self.fingerprints = set(fingerprints or ())

    @classmethod
    def load(cls, path: str) -> "Baseline":
        try:
            with open(path, encoding="utf-8") as f:
                return cls(set(json.load(f)["fingerprints"]))
        except FileNotFoundError:
            return cls()

    def save(self, path: str, findings: list[Finding]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "fingerprints": sorted({x.fingerprint for x in findings})}, f, indent=2)

    def new(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.fingerprint not in self.fingerprints]


def to_sarif(findings: list[Finding]) -> dict:
    """SARIF 2.1.0, the format GitHub code scanning ingests to show findings on pull requests."""
    rules = sorted({f.rule for f in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "secretscan", "rules": [{"id": r, "shortDescription": {"text": r.replace("-", " ")}} for r in rules]}},
            "results": [{
                "ruleId": f.rule, "level": "error" if f.severity == "high" else "warning",
                "message": {"text": f"Possible {f.rule.replace('-', ' ')}: {f.preview}"},
                "partialFingerprints": {"secretscan/v1": f.fingerprint},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": f.line}}}],
            } for f in findings],
        }],
    }
