//! Unit tests for the deprecated standalone `obu::Legacy` codec.
#![cfg(all(feature = "legacy", feature = "keyless"))]

use obu::Legacy;

#[test]
fn legacy_roundtrip() {
    let ob = Legacy::new_keyless().unwrap();
    let long = "x".repeat(1000);
    for pt in ["a", "hello world", "UTF-8: こんにちは 🚀", long.as_str()] {
        let ot = ob.enc(pt).unwrap();
        assert_eq!(ob.dec(&ot).unwrap(), pt, "roundtrip failed for {pt:?}");
    }
}

#[test]
fn legacy_is_deterministic() {
    let ob = Legacy::new_keyless().unwrap();
    assert_eq!(ob.enc("same").unwrap(), ob.enc("same").unwrap());
}

#[test]
fn legacy_rejects_empty_plaintext() {
    let ob = Legacy::new_keyless().unwrap();
    assert!(ob.enc("").is_err());
}

#[test]
fn legacy_obtext_is_lowercase_rfc_base32() {
    let ob = Legacy::new_keyless().unwrap();
    let ot = ob.enc("hello").unwrap();
    // Lowercase RFC 4648 base32 alphabet: a-z plus digits 2-7.
    assert!(
        ot.bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
        "unexpected character in legacy obtext: {ot:?}"
    );
}

#[test]
fn legacy_secret_roundtrips_hex_and_bytes() {
    let secret = obu::generate_secret();
    let ob = Legacy::new(&secret).unwrap();
    assert_eq!(ob.secret(), secret);

    let ob2 = Legacy::from_bytes(ob.secret_bytes()).unwrap();
    assert_eq!(ob2.secret(), secret);
}

#[test]
fn legacy_different_secrets_produce_different_obtext() {
    let a = Legacy::new(&obu::generate_secret()).unwrap();
    let b = Legacy::new(&obu::generate_secret()).unwrap();
    assert_ne!(a.enc("collision?").unwrap(), b.enc("collision?").unwrap());
}
