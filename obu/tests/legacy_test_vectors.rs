//! Conformance of the deprecated `obu::Legacy` codec against the frozen
//! canonical `legacy-test-vectors.jsonl`. The vectors carry their secret
//! (base64url, a pre-1.0 artifact) in a `meta` first line.
#![cfg(feature = "legacy")]

use data_encoding::BASE64URL_NOPAD;
use obu::Legacy;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct MetaEntry {
    #[serde(rename = "type")]
    entry_type: String,
    secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    #[allow(dead_code)]
    format: String,
    plaintext: String,
    obtext: String,
}

fn load() -> (String, Vec<TestVector>) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/legacy-test-vectors.jsonl");
    let data = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {:?}: {e} — is the tests/vectors submodule checked out?",
            path
        )
    });
    let mut lines = data.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next().expect("empty vector file");
    let meta: MetaEntry =
        serde_json::from_str(first).expect("first line must be the meta entry carrying the secret");
    assert_eq!(meta.entry_type, "meta", "expected a meta first line");
    let secret = meta.secret.expect("meta must carry the secret");
    let vectors = lines
        .map(|l| serde_json::from_str(l).expect("parse vector"))
        .collect();
    (secret, vectors)
}

#[test]
fn legacy_vectors() {
    let (secret_b64, vectors) = load();
    assert!(!vectors.is_empty(), "no legacy vectors loaded");

    // The frozen vectors carry a base64url secret; obu is hex-only now,
    // so decode it to bytes for the (bytes-in) Legacy constructor.
    let secret_bytes: [u8; 32] = BASE64URL_NOPAD
        .decode(secret_b64.as_bytes())
        .expect("decode base64url secret")
        .try_into()
        .expect("legacy secret must be 32 bytes");
    let legacy = Legacy::from_bytes(&secret_bytes).expect("build Legacy from the secret");

    for v in &vectors {
        // legacy is deterministic: enc reproduces the obtext exactly.
        let ot = legacy
            .enc(&v.plaintext)
            .unwrap_or_else(|e| panic!("enc {:?}: {:?}", v.plaintext, e));
        assert_eq!(
            ot, v.obtext,
            "enc mismatch for plaintext {:?}\n  expected {}\n  got      {}",
            v.plaintext, v.obtext, ot
        );

        // and dec recovers the plaintext.
        let pt = legacy
            .dec(&v.obtext)
            .unwrap_or_else(|e| panic!("dec {:?}: {:?}", v.obtext, e));
        assert_eq!(pt, v.plaintext, "dec mismatch for obtext {:?}", v.obtext);
    }

    println!("legacy vectors: {} reproduced (enc + dec)", vectors.len());
}
