"""Check pinned Python dependencies against a list of security advisories."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Advisory:
    id: str
    package: str
    introduced: str      # first affected version
    fixed: str           # first safe version
    summary: str


def _version(text: str) -> tuple:
    """Turn '2.10.1' into (2, 10, 1) so versions compare numerically ('2.10' > '2.9')."""
    parts = []
    for piece in re.split(r"[.\-+]", text.strip()):
        number = re.match(r"\d+", piece)
        if number is None:
            break                    # stop at a pre-release tag such as 'rc1'
        parts.append(int(number.group()))
    return tuple(parts)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()      # PyPI treats Foo_Bar, foo-bar and foo.bar as one package


def parse_requirements(text: str) -> tuple[dict[str, str], list[str]]:
    """Return ({package: pinned version}, [lines that are not pinned with ==]).

    An unpinned dependency cannot be checked, and it means two installs of the
    same commit can get different code, so those lines are reported too.
    """
    pinned: dict[str, str] = {}
    unpinned: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        line = line.split(";", 1)[0].strip()                     # drop environment markers
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.+!-]+)$", line)
        if match:
            pinned[_normalise(match.group(1))] = match.group(2)
        else:
            unpinned.append(line)
    return pinned, unpinned


def load_advisories(path: str) -> list[Advisory]:
    with open(path, encoding="utf-8") as f:
        return [Advisory(**item) for item in json.load(f)]


def check_requirements(text: str, advisories: list[Advisory]) -> tuple[list[dict], list[str]]:
    pinned, unpinned = parse_requirements(text)
    hits = []
    for advisory in advisories:
        version = pinned.get(_normalise(advisory.package))
        if version is not None and _version(advisory.introduced) <= _version(version) < _version(advisory.fixed):
            hits.append({"id": advisory.id, "package": advisory.package, "installed": version, "fixed_in": advisory.fixed, "summary": advisory.summary})
    return hits, unpinned
