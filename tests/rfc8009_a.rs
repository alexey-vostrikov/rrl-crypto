//! RFC 8009 Appendix A: full encryptions with the confounder the document fixes.
//!
//! These are the only vectors that pin the *encrypt* direction of the profile against a third
//! party. MIT's `crypto_tests` (in `vectors.rs`) mostly pin the decrypt direction, and a round
//! trip pins nothing: both sides of it are this crate.
//!
//! The encryption is called with an explicit confounder for the same reason — `encrypt` draws one
//! from the OS, and a vector that does not fix the confounder cannot be compared to anything.
//! `encrypt_with_confounder` is public precisely so this is possible; a caller outside a test
//! must never pass a predictable one (RFC 8009 §8: the confounder is the only source of IV
//! unpredictability, and a repeated one leaks that two messages agree on a prefix).

use rrl_crypto::{Enctype, profile};

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("a hex vector")
}

struct Case {
    enctype: Enctype,
    ke: &'static str,
    ki: &'static str,
}

const E19: Case = Case {
    enctype: Enctype::Aes128Sha256,
    ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
    ki: "9fda0e56ab2d85e1569a688696c26a6c",
};

const E20: Case = Case {
    enctype: Enctype::Aes256Sha384,
    ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
    ki: "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
};

/// Encrypts with the document's confounder and compares the whole token, then decrypts it back.
///
/// The length is asserted too: an overhead that is right for 17/18 and wrong for 19/20 is the
/// kind of difference that only shows up as a rejected ticket.
fn check(case: &Case, confounder: &str, plaintext: &str, ciphertext: &str) {
    let ke = unhex(case.ke);
    let ki = unhex(case.ki);
    let conf = unhex(confounder);
    let plain = unhex(plaintext);

    let got = profile::encrypt_with_confounder(case.enctype, &ke, &ki, &conf, &plain)
        .expect("the profile encrypts");
    assert_eq!(
        hex::encode(&got),
        ciphertext,
        "{:?}: ciphertext",
        case.enctype
    );
    assert_eq!(
        got.len(),
        plain.len() + case.enctype.overhead(),
        "{:?}: overhead",
        case.enctype
    );

    let back = profile::decrypt(case.enctype, &ke, &ki, &got).expect("the profile decrypts");
    assert_eq!(hex::encode(&back), plaintext, "{:?}: decrypt", case.enctype);
}

#[test]
fn rfc8009_a_aes128_sha256_empty_plaintext() {
    check(
        &E19,
        "7e5895eaf2672435bad817f545a37148",
        "",
        "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718",
    );
}

#[test]
fn rfc8009_a_aes128_sha256_less_than_block() {
    check(
        &E19,
        "7bca285e2fd4130fb55b1a5c83bc5b24",
        "000102030405",
        "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c",
    );
}

#[test]
fn rfc8009_a_aes128_sha256_equals_block() {
    // 32 octets of CTS input: CS3 exchanges the final two blocks even when nothing is ragged.
    check(
        &E19,
        "56ab21713ff62c0a1457200f6fa9948f",
        "000102030405060708090a0b0c0d0e0f",
        "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3",
    );
}

#[test]
fn rfc8009_a_aes128_sha256_greater_than_block() {
    check(
        &E19,
        "a7a4e29a4728ce10664fb64e49ad3fac",
        "000102030405060708090a0b0c0d0e0f1011121314",
        "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc",
    );
}

#[test]
fn rfc8009_a_aes256_sha384_empty_plaintext() {
    check(
        &E20,
        "f764e9fa15c276478b2c7d0c4e5f58e4",
        "",
        "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c",
    );
}

#[test]
fn rfc8009_a_aes256_sha384_less_than_block() {
    check(
        &E20,
        "b80d3251c1f6471494256ffe712d0b9a",
        "000102030405",
        "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
    );
}

#[test]
fn rfc8009_a_aes256_sha384_equals_block() {
    check(
        &E20,
        "53bf8a0d105265d4e276428624ce5e63",
        "000102030405060708090a0b0c0d0e0f",
        "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266",
    );
}

#[test]
fn rfc8009_a_aes256_sha384_greater_than_block() {
    check(
        &E20,
        "763e65367e864f02f55153c7e3b58af1",
        "000102030405060708090a0b0c0d0e0f1011121314",
        "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
    );
}

/// The IV prefix is load-bearing for 19/20, and a self-round-trip cannot show it: both sides would
/// drop it together. Against the published tag it is visible.
#[test]
fn the_rfc8009_mac_needs_the_iv_prefix() {
    let case = &E19;
    let ke = unhex(case.ke);
    let ki = unhex(case.ki);
    let conf = unhex("7e5895eaf2672435bad817f545a37148");
    let sealed =
        profile::encrypt_with_confounder(case.enctype, &ke, &ki, &conf, b"").expect("encrypt");
    let (cipher, tag) = sealed.split_at(sealed.len() - 16);

    // What the tag would be without the IV in the MAC input, computed the same way the profile
    // does but skipping the prefix: it must differ from the published one.
    use hmac::{Hmac, KeyInit, Mac};
    let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&ki).expect("hmac key");
    m.update(cipher);
    let without = m.finalize().into_bytes();
    assert_ne!(
        &without[..16],
        tag,
        "the MAC must cover IV | C; without the IV it is a different value"
    );
}
