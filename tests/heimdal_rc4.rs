//! `rc4-hmac` (enctype 23) against Heimdal, in both directions.
//!
//! The fixture is produced by `scripts/heimdal-rc4-vectors.sh`, which compiles a small partner
//! against Debian's packaged Heimdal 7.7 and runs three steps: Heimdal derives a key and encrypts a
//! known plaintext; this crate encrypts the same plaintext with a fixed confounder; Heimdal decrypts
//! *our* ciphertext and must return the plaintext, or the script refuses to write the file.
//!
//! So each case pins three things at once — that our key derivation is Heimdal's, that our envelope
//! is Heimdal's, and that Heimdal's is ours — and a change to any of them fails here rather than in a
//! realm where a machine account has an RC4 key.

use rrl_crypto::{Cipher, Enctype, Key, OwnCipher};
use serde_json::Value;

fn fixture() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/heimdal_rc4.json"
    ))
    .expect("the fixture is committed");
    serde_json::from_str(&text).expect("the fixture is JSON")
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("the fixture holds hex")
}

/// The password is text to both sides: Heimdal takes UTF-8 `char *`, and this crate's
/// `string_to_key` encodes it as UTF-16LE itself.
fn key_of(fixture: &Value) -> Key {
    let cases = fixture["cases"].as_array().expect("cases");
    Key::new(Enctype::Rc4Hmac, unhex(cases[0]["key"].as_str().unwrap())).expect("a key")
}

/// Our string-to-key has to produce the key Heimdal produces, for ASCII and for text outside it: the
/// UTF-16LE encoding of the password is where a hand-rolled implementation goes wrong.
#[test]
fn the_string_to_key_is_heimdals() {
    let fixture = fixture();
    for entry in fixture["keys"].as_array().expect("keys") {
        let password = unhex(entry["password"].as_str().unwrap());
        let salt = unhex(entry["salt"].as_str().unwrap());
        let expected = entry["key"].as_str().unwrap();
        let label =
            String::from_utf8(password.clone()).unwrap_or_else(|_| "a non-UTF-8 password".into());
        let got = OwnCipher
            .s2k(Enctype::Rc4Hmac, &password, &salt, None)
            .unwrap_or_else(|e| panic!("s2k failed: {e}"));
        assert_eq!(
            hex::encode(got.bytes()),
            expected,
            "the key for {label:?} must be Heimdal's"
        );
    }
}

/// Heimdal's ciphertext opens with our key and usage — including usage 3, which both sides key as
/// usage 8.
#[test]
fn heimdals_ciphertexts_open() {
    let fixture = fixture();
    let key = key_of(&fixture);
    for case in fixture["cases"].as_array().expect("cases") {
        let usage = case["usage"].as_u64().unwrap() as u32;
        let ciphertext = unhex(case["heimdal"].as_str().unwrap());
        let expected = unhex(case["plaintext"].as_str().unwrap());
        let plaintext = OwnCipher
            .decrypt(&key, usage, &ciphertext)
            .unwrap_or_else(|e| panic!("usage {usage}: {e}"));
        assert_eq!(plaintext, expected, "usage {usage}");
    }
}

/// Our envelope is the one Heimdal read back: the exact octets are pinned, so a reordering of the tag
/// and the confounder fails here even though it would still round-trip inside this crate.
#[test]
fn our_ciphertext_is_the_one_heimdal_read() {
    let fixture = fixture();
    let key = key_of(&fixture);
    for case in fixture["cases"].as_array().expect("cases") {
        let usage = case["usage"].as_u64().unwrap() as u32;
        let plaintext = unhex(case["plaintext"].as_str().unwrap());
        let confounder = unhex(case["ours_confounder"].as_str().unwrap());
        let ours = OwnCipher
            .encrypt_with_confounder(&key, usage, &plaintext, &confounder)
            .expect("a ciphertext");
        assert_eq!(
            hex::encode(&ours),
            case["ours"].as_str().unwrap(),
            "usage {usage}: the envelope changed"
        );
        // The provenance: Heimdal decrypted exactly these octets to exactly this plaintext.
        assert_eq!(
            case["heimdal_read_ours_as"].as_str().unwrap(),
            case["plaintext"].as_str().unwrap(),
            "usage {usage}: the fixture records what Heimdal read back"
        );
        // And it round-trips here too, of course.
        assert_eq!(
            OwnCipher
                .decrypt(&key, usage, &ours)
                .expect("the plaintext"),
            plaintext
        );
    }
}

/// The usage mapping is what makes a Windows AS-REP readable: usage 3 keys as 8. A ciphertext sealed
/// under one must open under the other, and two unmapped usages must not be confused.
#[test]
fn the_usage_mapping_is_heimdals() {
    let key = Key::new(Enctype::Rc4Hmac, [0x5au8; 16]).expect("a key");
    let sealed = OwnCipher
        .encrypt_with_confounder(&key, 3, b"an AS-REP", &[0u8; 8])
        .expect("a ciphertext");
    assert_eq!(
        OwnCipher.decrypt(&key, 8, &sealed).expect("the plaintext"),
        b"an AS-REP"
    );
    assert!(OwnCipher.decrypt(&key, 1, &sealed).is_err());
}

/// A realm that lists `rc4-hmac` gets it; the default list does not, so nothing issues it by accident.
#[test]
fn the_enctype_is_available_and_not_a_default() {
    assert_eq!(Enctype::Rc4Hmac.id(), 23);
    assert_eq!(Enctype::Rc4Hmac.name(), "rc4-hmac");
    assert!(!Enctype::ALL.contains(&Enctype::Rc4Hmac));
    assert_eq!(
        Enctype::parse_list(&["rc4-hmac"]).expect("a listed enctype"),
        vec![Enctype::Rc4Hmac]
    );
    assert_eq!(Enctype::Rc4Hmac.checksum_type(), -138);
    assert_eq!(Enctype::Rc4Hmac.confounder_len(), 8);
}
