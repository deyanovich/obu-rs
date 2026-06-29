//! Basic round-trip tests for the z-tier codecs.

#![cfg(all(feature = "zdcbc", feature = "keyless"))]

use obu::ZdcbcC32;

#[test]
fn test_zdcbc_basic() {
    let original = "hello world";
    let ob = ZdcbcC32::new_keyless().unwrap();
    let ot = ob.enc(original).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(original, pt2);
    assert!(!ot.is_empty());
}

#[test]
fn test_empty_string() {
    let ob = ZdcbcC32::new_keyless().unwrap();
    assert!(ob.enc("").is_err());
}

#[test]
fn test_dec_rejects_empty_payload() {
    // OBU §2.2: dec MUST reject anything that decrypts to empty. An
    // empty obtext decodes to a zero-length zdcbc payload.
    let ob = ZdcbcC32::new_keyless().unwrap();
    assert!(ob.dec("").is_err());
}

#[test]
fn test_zdcbc_all_printable_ascii() {
    let original = (32..127).map(|c| c as u8 as char).collect::<String>();
    let ob = ZdcbcC32::new_keyless().unwrap();
    let ot = ob.enc(&original).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(original, pt2);
}
