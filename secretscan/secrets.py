from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str        # "high" or "medium"
    path: str
    line: int
    preview: str         # the match with its middle masked: enough to recognise, not enough to use
    fingerprint: str     # stable id for baselines: hash of rule + path + the secret itself

    def location(self) -> str:
        return f"{self.path}:{self.line}"


# (rule id, severity, pattern). Group 1, when present, is the secret itself.
RULES: list[tuple[str, str, re.Pattern]] = [
    ("aws-access-key-id", "high", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("github-token", "high", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("slack-token", "high", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("stripe-live-key", "high", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b")),
    ("google-api-key", "high", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("private-key-block", "high", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)")),
    ("jwt", "medium", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b")),
    ("url-with-password", "high", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{4,})@[^\s/]+", re.I)),
]
# Generic: an assignment to something named like a credential. Confirmed by entropy, see below.
ASSIGNMENT = re.compile(r"""(?ix)\b([a-z0-9_.-]*(?:passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[a-z0-9_.-]*)
                            \s*[:=]\s*["']([^"'\s]{8,})["']""")
PLACEHOLDER = re.compile(r"(?i)^(?:x{4,}|\*{4,}|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|changeme|change[_-]me|example|placeholder|your[_-].*|todo|none|null|dummy|test(?:ing)?|password|secret)$")
TEMPLATE = re.compile(r"[${}<>%]")
IGNORE_MARK = "secretscan:ignore"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".lock", ".min.js", ".map"}


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character. Random keys score high; words and repeated characters score low."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def mask(secret: str) -> str:
    """Show the ends, hide the middle, so reports and logs do not become a second leak."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * min(len(secret) - 6, 12)}{secret[-2:]}"


def _finding(rule: str, severity: str, path: str, line: int, secret: str) -> Finding:
    fingerprint = hashlib.sha256(f"{rule}\0{path}\0{secret}".encode()).hexdigest()[:16]
    return Finding(rule, severity, path, line, mask(secret), fingerprint)


def scan_text(text: str, path: str = "<text>", entropy_threshold: float = 3.5) -> list[Finding]:
    """Find secrets in one file's contents.

    Two detectors run on every line:
      1. Known formats (provider-specific key shapes), which are precise.
      2. Assignments to credential-like names, kept only when the value looks
         random (high entropy) and is not an obvious placeholder. Without the
         entropy check this rule fires on every `password = "changeme"` in a README.
    A line containing "secretscan:ignore" is skipped, for reviewed false positives.
    """
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARK in line or len(line) > 2000:      # very long lines are minified or generated code
            continue
        for rule, severity, pattern in RULES:
            for match in pattern.finditer(line):
                secret = match.group(1)
                if rule == "url-with-password" and (PLACEHOLDER.match(secret) or TEMPLATE.search(secret)):
                    continue                             # postgres://user:${DB_PASSWORD}@host is a reference, not a leak
                if (number, secret) not in seen:
                    seen.add((number, secret))
                    findings.append(_finding(rule, severity, path, number, secret))
        for match in ASSIGNMENT.finditer(line):
            value = match.group(2)
            if (number, value) in seen or PLACEHOLDER.match(value) or TEMPLATE.search(value):
                continue
            if shannon_entropy(value) >= entropy_threshold and len(value) >= 12:
                seen.add((number, value))
                findings.append(_finding("generic-credential-assignment", "medium", path, number, value))
    return findings


def scan_path(root: str, entropy_threshold: float = 3.5) -> list[Finding]:
    """Scan a file or walk a directory, skipping binaries, dependencies and build output."""
    paths = []
    if os.path.isfile(root):
        paths.append(root)
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if not any(name.endswith(ext) for ext in SKIP_EXT):
                paths.append(os.path.join(directory, name))
    findings: list[Finding] = []
    for path in paths:
        try:
            with open(path, "rb") as f:
                raw = f.read(2_000_000)
        except OSError:
            continue
        if b"\0" in raw[:4096]:              # binary file
            continue
        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        findings.extend(scan_text(raw.decode("utf-8", errors="replace"), rel.replace(os.sep, "/"), entropy_threshold))
    return findings
