//! What must be *refused*, not what must come out.
//!
//! The known-answer tests (`vectors.rs`, `rfc8009_a.rs`) pin the decrypt direction against
//! published octets: they catch a cipher that computes the wrong thing. They cannot catch a cipher
//! that computes the right thing and then does not check it, because a tag that is never verified
//! still produces the correct plaintext for every vector in the tree.
//!
//! This file is the other half, and it is the half OpenSSL's own `evp_test` recipes spend most of
//! their lines on: every octet of a ciphertext is damaged in turn and must be refused, a key of the
//! wrong size is refused, and a ciphertext made under one usage does not open under another. An
//! implementation that passes `vectors.rs` and this file is one that both computes and checks.

use rrl_crypto::{Cipher, Enctype, Key, OwnCipher};

/// Every enctype this crate implements.
const ENCTYPES: [Enctype; 4] = [
    Enctype::Aes128Sha1,
    Enctype::Aes256Sha1,
    Enctype::Aes128Sha256,
    Enctype::Aes256Sha384,
];

/// A key of the right length for `enctype`, drawn from a counter so a failure is reproducible.
fn key_for(enctype: Enctype) -> Key {
    Key::new(enctype, vec![0x5au8; enctype.key_len()]).expect("a key of the enctype's length")
}

/// The usage numbers the profiles distinguish; a handful is enough to catch a key that ignores it.
const USAGES: [u32; 4] = [
    rrl_crypto::usage::AS_REQ_PA_ENC_TS,
    rrl_crypto::usage::TGS_REQ_AD_SESSKEY,
    rrl_crypto::usage::KDC_REP_TICKET,
    rrl_crypto::usage::TGS_REP_ENCPART_SUBKEY,
];

/// Damaging any single octet of a ciphertext must make it refuse to open.
///
/// Every octet, not a sample: the tag sits at the end, the confounder at the front, and a check
/// that covers only part of the buffer is exactly the bug this looks for. For a 32-octet plaintext
/// that is 48–80 decryptions per enctype, which is cheap enough to do exhaustively.
#[test]
fn every_octet_of_a_ciphertext_is_covered_by_the_check() {
    let cipher = OwnCipher;
    let plaintext = b"the quick brown fox jumps over";

    for enctype in ENCTYPES {
        let key = key_for(enctype);
        for usage in USAGES {
            let ciphertext = cipher
                .encrypt(&key, usage, plaintext)
                .unwrap_or_else(|err| panic!("{enctype:?} usage {usage}: encrypt: {err}"));

            // The control: undamaged, it opens.
            assert_eq!(
                cipher.decrypt(&key, usage, &ciphertext).expect("opens"),
                plaintext,
                "{enctype:?} usage {usage}: the control must open"
            );

            for index in 0..ciphertext.len() {
                let mut damaged = ciphertext.clone();
                // One bit in the middle of the octet, which is neither a no-op nor a wholesale
                // replacement that would trip a length check instead of the integrity one.
                damaged[index] ^= 0x01;
                assert!(
                    cipher.decrypt(&key, usage, &damaged).is_err(),
                    "{enctype:?} usage {usage}: octet {index} of {} was not checked",
                    ciphertext.len()
                );
            }
        }
    }
}

/// A ciphertext shortened or lengthened by one octet must be refused, not read as a prefix.
///
/// RFC 3961 §5.3 and RFC 8009 §5: the profile's overhead is fixed per enctype - a confounder, the
/// plaintext, the padding to a block boundary and the tag - so any length that does not decompose
/// that way is not a ciphertext this profile produced.
#[test]
fn a_ciphertext_of_the_wrong_length_is_refused() {
    let cipher = OwnCipher;
    let plaintext = b"eighteen octets ok";

    for enctype in ENCTYPES {
        let key = key_for(enctype);
        let usage = rrl_crypto::usage::AS_REP_ENCPART;
        let ciphertext = cipher.encrypt(&key, usage, plaintext).expect("encrypts");

        for wrong in [
            &ciphertext[..ciphertext.len() - 1],
            &[&ciphertext[..], &[0u8][..]].concat(),
        ] {
            assert!(
                cipher.decrypt(&key, usage, wrong).is_err(),
                "{enctype:?}: a length of {} was accepted for a ciphertext of {}",
                wrong.len(),
                ciphertext.len()
            );
        }

        // Truncated to less than the overhead: nothing about it is a ciphertext at all.
        assert!(
            cipher
                .decrypt(&key, usage, &ciphertext[..enctype.overhead() - 1])
                .is_err(),
            "{enctype:?}: less than the overhead was accepted"
        );
    }
}

/// The same ciphertext under a different usage is a different key, and must not open.
///
/// This is what stops a service from using the ticket it was given as the key for a message it
/// sends to somebody else: the usage number is part of the derivation (RFC 3961 §5.1), and a cipher
/// that ignored it would open one with the other.
#[test]
fn a_ciphertext_does_not_open_under_another_usage() {
    let cipher = OwnCipher;
    let plaintext = b"usage is part of the key";

    for enctype in ENCTYPES {
        let key = key_for(enctype);
        let ciphertext = cipher
            .encrypt(&key, USAGES[0], plaintext)
            .expect("encrypts");

        for other in &USAGES[1..] {
            assert!(
                cipher.decrypt(&key, *other, &ciphertext).is_err(),
                "{enctype:?}: a ciphertext made under usage {} opened under {other}",
                USAGES[0]
            );
        }
    }
}

/// A key of the wrong length is refused when it is made, not when it is used.
///
/// A key one octet short is the sort of value a configuration file produces, and deriving from it
/// would either panic inside a cipher or silently truncate. Both are worse than an error at the
/// point the key is constructed.
#[test]
fn a_key_of_the_wrong_length_never_becomes_a_key() {
    for enctype in ENCTYPES {
        for length in [0, 1, enctype.key_len() - 1, enctype.key_len() + 1, 64] {
            assert!(
                Key::new(enctype, vec![0u8; length]).is_err(),
                "{enctype:?}: a key of {length} octets was accepted"
            );
        }
        assert!(Key::new(enctype, vec![0u8; enctype.key_len()]).is_ok());
    }
}

/// Two encryptions of one plaintext differ, and both open.
///
/// The confounder is the only source of IV in both profiles - RFC 3962 §6 for AES-CTS, RFC 8009 §8
/// for the SHA-2 enctypes - so a cipher that reused it, or fixed it at zero, would produce the same
/// ciphertext twice under one key. That is the failure that breaks the mode while passing every
/// known-answer vector.
#[test]
fn the_same_plaintext_never_encrypts_to_the_same_ciphertext() {
    let cipher = OwnCipher;
    let plaintext = b"repeated plaintext, one key";

    for enctype in ENCTYPES {
        let key = key_for(enctype);
        let usage = rrl_crypto::usage::TGS_REQ_AD_SESSKEY;

        let first = cipher.encrypt(&key, usage, plaintext).expect("encrypts");
        // A dozen, not two: a counter-based IV would collide on a small sample or not at all
        // depending on where it starts.
        let mut seen = std::collections::HashSet::new();
        seen.insert(first.clone());
        for round in 1..12 {
            let again = cipher.encrypt(&key, usage, plaintext).expect("encrypts");
            assert!(
                seen.insert(again.clone()),
                "{enctype:?}: round {round} produced a ciphertext already produced - the \
                 confounder is not fresh"
            );
            assert_eq!(
                cipher.decrypt(&key, usage, &again).expect("opens"),
                plaintext,
                "{enctype:?}: round {round} did not open"
            );
        }
    }
}

/// An explicitly supplied confounder makes the encryption reproducible, and it still verifies.
///
/// `encrypt_with_confounder` exists for the known-answer vectors, so it must be the same
/// computation the random path performs: same octets for the same confounder, and a ciphertext the
/// normal decrypt accepts.
#[test]
fn a_fixed_confounder_makes_the_same_ciphertext_and_still_verifies() {
    let cipher = OwnCipher;
    let plaintext = b"deterministic on request";
    let confounder = [0x11u8; 16];

    for enctype in ENCTYPES {
        let key = key_for(enctype);
        let usage = rrl_crypto::usage::AS_REQ_PA_ENC_TS;

        let a = cipher
            .encrypt_with_confounder(&key, usage, plaintext, &confounder)
            .expect("encrypts");
        let b = cipher
            .encrypt_with_confounder(&key, usage, plaintext, &confounder)
            .expect("encrypts");
        assert_eq!(
            a, b,
            "{enctype:?}: the same confounder gave different octets"
        );
        assert_eq!(
            cipher.decrypt(&key, usage, &a).expect("opens"),
            plaintext,
            "{enctype:?}: the deterministic ciphertext did not open"
        );
    }
}

/// Every plaintext length from zero to three blocks, plus a long one, round-trips.
///
/// The block-boundary cases are where CTS and the padding rules disagree with themselves: zero
/// octets, one octet, one short of a block, exactly one block, one past it. OpenSSL's recipes walk
/// these lengths for the same reason.
#[test]
fn every_plaintext_length_round_trips() {
    let cipher = OwnCipher;

    for enctype in ENCTYPES {
        let key = key_for(enctype);
        for usage in USAGES {
            for len in (0..=48).chain([64, 200, 1000]) {
                let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let ciphertext = cipher
                    .encrypt(&key, usage, &plaintext)
                    .unwrap_or_else(|err| panic!("{enctype:?} len {len}: encrypt: {err}"));
                assert_eq!(
                    ciphertext.len(),
                    len + enctype.overhead(),
                    "{enctype:?} len {len}: the overhead is not the profile's"
                );
                assert_eq!(
                    cipher.decrypt(&key, usage, &ciphertext).expect("opens"),
                    plaintext,
                    "{enctype:?} usage {usage} len {len}: round trip"
                );
            }
        }
    }
}

/// A checksum of one octet more or less is refused, and a damaged one is refused.
///
/// `verify_checksum` is the constant-time comparison the callers rely on; a comparison that returns
/// success for a prefix would make every MAC in the protocol forgeable at its first octet.
#[test]
fn a_checksum_is_verified_over_its_whole_length() {
    let cipher = OwnCipher;
    let data = b"the message a checksum covers";

    for enctype in ENCTYPES {
        let key = key_for(enctype);
        let usage = rrl_crypto::usage::TGS_REQ_AUTH_CKSUM;
        let tag = cipher.checksum(&key, usage, data).expect("checksums");

        assert!(
            cipher.verify_checksum(&key, usage, data, &tag).is_ok(),
            "{enctype:?}: the correct checksum was refused"
        );

        for index in 0..tag.len() {
            let mut damaged = tag.clone();
            damaged[index] ^= 0x80;
            assert!(
                cipher.verify_checksum(&key, usage, data, &damaged).is_err(),
                "{enctype:?}: octet {index} of the checksum was not compared"
            );
        }

        assert!(
            cipher
                .verify_checksum(&key, usage, data, &tag[..tag.len() - 1])
                .is_err(),
            "{enctype:?}: a truncated checksum was accepted"
        );
        assert!(
            cipher
                .verify_checksum(&key, usage, data, &[&tag[..], &[0u8][..]].concat())
                .is_err(),
            "{enctype:?}: a checksum with an extra octet was accepted"
        );
        assert!(
            cipher
                .verify_checksum(&key, usage, b"a different message", &tag)
                .is_err(),
            "{enctype:?}: the checksum verified for different data"
        );
    }
}
