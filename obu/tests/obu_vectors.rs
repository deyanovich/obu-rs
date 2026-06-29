//! Conformance against the canonical obu test vectors.
//!
//! The vectors live in the shared `oboron-test-vectors` repo, checked
//! out here as the `tests/vectors` submodule. They use the hardcoded
//! obu secret, so `new_keyless()` reproduces them.
//!
//! - `zdcbc` is deterministic: `enc` must reproduce the obtext exactly.
//! - `upcbc` is probabilistic (random IV): `enc` differs each time, so
//!   we round-trip instead. `dec` must recover the plaintext for both.

#![cfg(all(feature = "upcbc", feature = "zdcbc", feature = "keyless"))]

use obu::{Format, Omnibu};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct TestVector {
    format: String,
    plaintext: String,
    obtext: String,
}

fn load_vectors() -> Vec<TestVector> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/obu-test-vectors.jsonl");
    let data = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read {:?}: {e} — is the tests/vectors submodule checked out?",
            path
        )
    });
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("failed to parse test vector"))
        .collect()
}

#[test]
fn obu_test_vectors() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "no test vectors loaded");

    let omb = Omnibu::new_keyless().expect("keyless Omnibu");

    let (mut deterministic, mut probabilistic) = (0usize, 0usize);
    for v in &vectors {
        let format = Format::from_str(&v.format)
            .unwrap_or_else(|e| panic!("invalid format {:?}: {:?}", v.format, e));

        // dec must recover the plaintext for every vector, both schemes.
        let pt = omb
            .dec(&v.obtext, &v.format)
            .unwrap_or_else(|e| panic!("dec {:?} ({}): {:?}", v.obtext, v.format, e));
        assert_eq!(pt, v.plaintext, "dec mismatch for {}", v.format);

        if format.scheme().is_deterministic() {
            // zdcbc: enc must reproduce the obtext byte-for-byte.
            let ot = omb
                .enc(&v.plaintext, &v.format)
                .unwrap_or_else(|e| panic!("enc {:?} ({}): {:?}", v.plaintext, v.format, e));
            assert_eq!(
                ot, v.obtext,
                "enc mismatch for {} plaintext={:?}\n  expected {}\n  got      {}",
                v.format, v.plaintext, v.obtext, ot
            );
            deterministic += 1;
        } else {
            // upcbc: random IV, so round-trip rather than match the obtext.
            let ot = omb.enc(&v.plaintext, &v.format).expect("enc");
            let rt = omb.dec(&ot, &v.format).expect("dec roundtrip");
            assert_eq!(rt, v.plaintext, "roundtrip mismatch for {}", v.format);
            probabilistic += 1;
        }
    }

    println!(
        "obu vectors: {deterministic} deterministic (exact enc) + {probabilistic} probabilistic (roundtrip) = {} total",
        vectors.len()
    );
    assert!(
        deterministic > 0 && probabilistic > 0,
        "expected both deterministic and probabilistic vectors"
    );
}

/// A canonical negative vector: an `op` (`dec` or `enc`) on `input`
/// under `format` that MUST be rejected.
#[derive(Debug, Deserialize)]
struct NegativeVector {
    op: String,
    format: String,
    input: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

/// Load the obu negative vectors. Prefers the split-out
/// `obu-negative-test-vectors.jsonl`; falls back to the combined
/// `negative-test-vectors.jsonl` (older submodule pins carried the obu
/// negatives there). Non-obu formats are filtered out at the call site.
fn load_negative_vectors() -> Vec<NegativeVector> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    for name in ["obu-negative-test-vectors.jsonl", "negative-test-vectors.jsonl"] {
        let path = dir.join(name);
        if path.exists() {
            let data = fs::read_to_string(&path).expect("read negative vectors");
            return data
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).expect("parse negative vector"))
                .collect();
        }
    }
    panic!("no obu negative vectors found — is the tests/vectors submodule checked out?");
}

/// Every obu negative vector must be REJECTED. Only obu-core formats
/// (`upcbc` / `zdcbc`) are exercised — any core (`dsiv`, …) or retired
/// `legacy` entries carried by the shared file fail `Format::from_str`
/// and are skipped.
#[test]
fn obu_negative_vectors() {
    let omb = Omnibu::new_keyless().expect("keyless Omnibu");

    let mut tested = 0usize;
    for v in load_negative_vectors() {
        if Format::from_str(&v.format).is_err() {
            continue; // not an obu format (core scheme or legacy)
        }
        let result = match v.op.as_str() {
            "dec" => omb.dec(&v.input, &v.format).map(|_| ()),
            "enc" => omb.enc(&v.input, &v.format).map(|_| ()),
            other => panic!("unknown negative-vector op: {other}"),
        };
        assert!(
            result.is_err(),
            "obu negative vector should have been REJECTED: op={} format={} input={:?} reason={:?}",
            v.op, v.format, v.input, v.reason
        );
        tested += 1;
    }

    assert!(tested > 0, "expected at least one obu negative vector to exercise");
    println!("obu negative vectors: {tested} rejected as expected");
}
