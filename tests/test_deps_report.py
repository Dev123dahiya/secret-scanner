import json

from secretscan import Advisory, Baseline, check_requirements, parse_requirements, scan_text, to_sarif
from secretscan.__main__ import ADVISORIES, main
from secretscan.deps import _version, load_advisories

AWS = "AKIA" + "Q7ZP2M4XK9WJ5TLD"
ADV = [Advisory("TEST-1", "Foo_Bar", "1.0", "2.10", "example")]


def test_versions_compare_numerically_not_as_text():
    assert _version("2.10.0") > _version("2.9.9")
    assert _version("1.26.5") == (1, 26, 5)
    assert _version("3.0rc1") == (3, 0)


def test_requirements_parsing():
    pinned, unpinned = parse_requirements("""
        # comment
        requests==2.25.1   # inline
        Foo_Bar[extra]==1.5 ; python_version < "3.11"
        flask>=2.0
        numpy
        -r other.txt
    """)
    assert pinned == {"requests": "2.25.1", "foo-bar": "1.5"}
    assert unpinned == ["flask>=2.0", "numpy"]


def test_affected_range_is_introduced_inclusive_fixed_exclusive():
    def hit(v):
        return bool(check_requirements(f"foo.bar=={v}", ADV)[0])
    assert not hit("0.9") and hit("1.0") and hit("2.9") and not hit("2.10") and not hit("3.0")


def test_bundled_advisories_flag_old_pins_and_pass_fixed_ones():
    advisories = load_advisories(ADVISORIES)
    hits, unpinned = check_requirements("requests==2.25.1\nPyYAML==5.3.1\nurllib3==1.26.18\nflask>=2.0\n", advisories)
    assert sorted(h["id"] for h in hits) == ["CVE-2020-14343", "CVE-2023-32681"]
    assert unpinned == ["flask>=2.0"]
    assert check_requirements("requests==2.31.0\nPyYAML==6.0.1\n", advisories) == ([], [])


def test_baseline_hides_accepted_findings_and_stores_no_secrets(tmp_path):
    path = str(tmp_path / "baseline.json")
    old = scan_text(f'k = "{AWS}"', "old.py")
    Baseline().save(path, old)
    assert AWS not in open(path).read()
    new = scan_text(f'k = "{AWS}"', "new.py")
    assert Baseline.load(path).new(old + new) == new
    assert Baseline.load(str(tmp_path / "missing.json")).new(old) == old


def test_sarif_shape():
    doc = to_sarif(scan_text(f'k = "{AWS}"', "cfg.py"))
    result = doc["runs"][0]["results"][0]
    assert doc["version"] == "2.1.0" and result["ruleId"] == "aws-access-key-id" and result["level"] == "error"
    assert result["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "cfg.py"}, "region": {"startLine": 1}}
    assert AWS not in json.dumps(doc)


def test_cli_exit_codes_gate_ci(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert main(["scan", str(tmp_path)]) == 0
    (tmp_path / "leak.py").write_text(f'k = "{AWS}"\n')
    assert main(["scan", str(tmp_path)]) == 1
    baseline = str(tmp_path / "b.json")
    assert main(["scan", str(tmp_path), "--baseline", baseline, "--update-baseline"]) == 0
    sarif = str(tmp_path / "out.sarif")
    assert main(["scan", str(tmp_path), "--baseline", baseline, "--sarif", sarif]) == 0     # accepted, so CI passes
    assert json.load(open(sarif))["runs"][0]["results"] == []
    assert AWS not in capsys.readouterr().out
