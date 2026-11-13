"""Fake credentials are assembled from pieces so no key-shaped string is stored in this repository."""
import os

from secretscan import scan_path, scan_text, shannon_entropy
from secretscan.secrets import mask

AWS = "AKIA" + "Q7ZP2M4XK9WJ5TLD"
GH = "ghp_" + "a8Kq2LmZ9xVb4TnR7cYw1DfH6sJp3GuE5oQi"
RANDOM = "f9K2" + "mQ7xLp4ZtR8vWc1N"


def rules(text):
    return [f.rule for f in scan_text(text)]


def test_known_provider_formats_are_detected():
    assert rules(f'key = "{AWS}"') == ["aws-access-key-id"]
    assert rules(f"export GH_TOKEN={GH}") == ["github-token"]
    assert rules("xoxb-" + "123456789012-abcdefghij") == ["slack-token"]
    assert rules("-----BEGIN RSA " + "PRIVATE KEY-----") == ["private-key-block"]
    assert rules("sk_live_" + "Zx81QmLp04TrVb7NcKd2WyHs") == ["stripe-live-key"]


def test_password_inside_a_connection_url():
    found = scan_text(f"DB=postgres://app:{RANDOM}@db.internal:5432/prod")
    assert [f.rule for f in found] == ["url-with-password"]
    assert rules("see https://example.com/docs and http://localhost:8000/") == []
    assert rules("DB=postgres://app:${DB_PASSWORD}@db/prod") == []         # a variable reference, not a password
    assert rules('url = f"postgres://app:{password}@db/prod"') == []


def test_generic_assignment_needs_a_random_looking_value():
    assert rules(f'api_token = "{RANDOM}"') == ["generic-credential-assignment"]
    assert rules('password = "changeme"') == []                    # placeholder
    assert rules('password = "your_password_here"') == []
    assert rules('secret = "aaaaaaaaaaaaaaaaaaaa"') == []          # long but zero entropy
    assert rules('token_type = "Bearer"') == []                    # too short to be a key
    assert rules(f'username = "{RANDOM}"') == []                   # name is not credential-like


def test_similar_looking_strings_are_not_flagged():
    assert rules("AKIA1234") == []                                 # too short for an access key id
    assert rules("commit 9f8e7d6c5b4a39281706f5e4d3c2b1a098765432") == []
    assert rules("ghp_short") == []


def test_ignore_marker_suppresses_one_line_only():
    text = f'a = "{AWS}"  # secretscan:ignore\nb = "{AWS}"\n'
    found = scan_text(text)
    assert [(f.line, f.rule) for f in found] == [(2, "aws-access-key-id")]


def test_report_never_contains_the_full_secret():
    finding = scan_text(f'key = "{AWS}"', "cfg.py")[0]
    assert AWS not in finding.preview and AWS not in finding.fingerprint
    assert finding.preview.startswith("AKIA") and "*" in finding.preview
    assert mask("short") == "*****"


def test_fingerprint_is_stable_across_line_moves_but_differs_by_file():
    a = scan_text(f'key = "{AWS}"', "a.py")[0]
    moved = scan_text(f'\n\n\nkey = "{AWS}"', "a.py")[0]
    other = scan_text(f'key = "{AWS}"', "b.py")[0]
    assert a.fingerprint == moved.fingerprint and a.line != moved.line
    assert a.fingerprint != other.fingerprint


def test_entropy_orders_random_above_words():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abababab") == 1.0
    assert shannon_entropy(RANDOM) > shannon_entropy("passwordpassword")


def test_directory_walk_skips_dependencies_and_binaries(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "src" / "app.py").write_text(f'k = "{AWS}"\n')
    (tmp_path / "node_modules" / "x.js").write_text(f'k = "{AWS}"\n')
    (tmp_path / "blob.bin").write_bytes(b"\0\1\2" + AWS.encode())
    (tmp_path / "logo.png").write_text(AWS)
    found = scan_path(str(tmp_path))
    assert [(f.path, f.line) for f in found] == [("src/app.py", 1)]
    assert [f.path for f in scan_path(os.path.join(str(tmp_path), "src", "app.py"))] == ["app.py"]


def test_this_repository_scans_clean():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert scan_path(root) == []
