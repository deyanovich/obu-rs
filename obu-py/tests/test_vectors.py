"""Conformance of the obu Python bindings against the canonical test
vectors.

The vectors live in the shared ``oboron-test-vectors`` repo, checked
out as the ``tests/vectors`` submodule under the obu *core* crate
(``obu/tests/vectors/``). These tests run the same vectors as the Rust
``obu_vectors.rs`` / ``legacy_test_vectors.rs`` suites, but *through the
PyO3 boundary* — so they catch any binding-layer corruption that a
round-trip-only smoke test would miss (the obtext must be byte-for-byte
canonical, not merely self-consistent).

This file lives outside ``python-source`` and is NOT shipped in the
wheel; it runs from the source tree (``pytest obu-py/tests``).
"""

import base64
import json
from pathlib import Path

import pytest

import obu

# obu-py/tests/test_vectors.py -> parents[2] is the obu-rs repo root.
VECTORS_DIR = Path(__file__).resolve().parents[2] / "obu" / "tests" / "vectors"


def _load(name):
    path = VECTORS_DIR / name
    if not path.exists():
        pytest.skip(
            f"vectors not checked out: {path} "
            f"(run `git submodule update --init` in the obu crate)"
        )
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_obu_positive_vectors():
    """Every obu vector must round-trip; zdcbc (deterministic) must also
    reproduce the canonical obtext byte-for-byte. Uses the hardcoded
    keyless secret the vectors were generated under."""
    vectors = _load("obu-test-vectors.jsonl")
    assert vectors, "no obu vectors loaded"
    om = obu.Omnibu(keyless=True)

    deterministic = probabilistic = 0
    for v in vectors:
        fmt, pt, ot = v["format"], v["plaintext"], v["obtext"]

        # dec must recover the plaintext for every vector, both schemes.
        assert om.dec(ot, fmt) == pt, f"dec mismatch for {fmt} plaintext={pt!r}"

        if fmt.split(".")[0] == "zdcbc":
            # deterministic: enc must reproduce the obtext exactly.
            assert om.enc(pt, fmt) == ot, (
                f"enc mismatch for {fmt} plaintext={pt!r}\n"
                f"  expected {ot}\n  got      {om.enc(pt, fmt)}"
            )
            deterministic += 1
        else:
            # upcbc: random IV per call, so round-trip rather than match.
            assert om.dec(om.enc(pt, fmt), fmt) == pt, f"roundtrip mismatch for {fmt}"
            probabilistic += 1

    assert deterministic > 0 and probabilistic > 0, (
        "expected both deterministic (zdcbc) and probabilistic (upcbc) vectors"
    )
    print(
        f"obu vectors: {deterministic} deterministic (exact enc) + "
        f"{probabilistic} probabilistic (roundtrip) = {len(vectors)} total"
    )


def _load_negatives():
    # Prefer the split-out obu negatives; fall back to the combined file
    # (older submodule pins carry the obu negatives there). Mirrors the
    # Rust loader.
    for name in ("obu-negative-test-vectors.jsonl", "negative-test-vectors.jsonl"):
        path = VECTORS_DIR / name
        if path.exists():
            return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    pytest.skip("no negative vectors checked out (tests/vectors submodule)")


def test_obu_negative_vectors():
    """Every obu negative vector must be REJECTED. Only obu formats
    (upcbc / zdcbc) are exercised — core (dsiv, …) and legacy entries in
    the shared file are filtered out, exactly as the Rust test skips any
    format that fails ``Format::from_str``."""
    om = obu.Omnibu(keyless=True)

    tested = 0
    for v in _load_negatives():
        fmt = v["format"]
        if fmt.split(".")[0] not in ("upcbc", "zdcbc"):
            continue
        op = v["op"]
        assert op in ("dec", "enc"), f"unknown negative-vector op: {op}"
        with pytest.raises(obu.ObuError):
            if op == "dec":
                om.dec(v["input"], fmt)
            else:
                om.enc(v["input"], fmt)
        tested += 1

    assert tested > 0, "expected at least one obu negative vector to exercise"
    print(f"obu negative vectors: {tested} rejected as expected")


@pytest.mark.skipif(
    obu.Legacy is None,
    reason="Legacy codec not built (the off-by-default `legacy` feature is "
    "not in the published wheel)",
)
def test_legacy_vectors():
    """The deprecated standalone Legacy codec must reproduce the
    canonical pre-1.0 legacy obtext exactly (it is deterministic). Runs
    only when obu-py is built with `--features legacy`."""
    vectors = _load("legacy-test-vectors.jsonl")
    assert vectors and vectors[0].get("type") == "meta", "legacy meta line missing"

    # The meta secret is base64url; obu.Legacy takes a hex secret.
    b64 = vectors[0]["secret"]
    raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    assert len(raw) == 32, "legacy meta secret must be 32 bytes"
    lg = obu.Legacy(secret=raw.hex())

    tested = 0
    for v in vectors[1:]:
        if v.get("type") == "meta":
            continue
        pt, ot = v["plaintext"], v["obtext"]
        assert lg.dec(ot) == pt, f"legacy dec mismatch plaintext={pt!r}"
        assert lg.enc(pt) == ot, f"legacy enc mismatch plaintext={pt!r}"  # deterministic
        tested += 1

    assert tested > 0, "expected at least one legacy vector"
    print(f"legacy vectors: {tested} exact round-trips")
