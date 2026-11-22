//! RFC 3961 §5.3 / RFC 8009 §5: the encryption profile, with the derived keys supplied.
//!
//! The two profiles differ in *which octets go under the MAC*, and that is the whole reason this
//! module exists as a separate layer:
//!
//! * **17/18** (RFC 3962 §5.3) — MAC over the plaintext, appended after the ciphertext. The tag
//!   cannot be checked before decrypting.
//! * **19/20** (RFC 8009 §5) — MAC over `IV | C`, so the receiver verifies integrity *before*
//!   decrypting and never parses an unauthenticated plaintext.
//!
//! A single routine parameterised by hash and key size cannot serve both: the MAC inputs differ,
//! not just the primitives. So they are two arms of one `match`, and the arm is chosen by
//! [`Enctype::is_rfc8009`].
//!
//! # Why the keys are arguments
//!
//! `Ke` and `Ki` here are the *specific* keys for one key usage — `Ke = DK(base, usage|0xAA)`,
//! `Ki = DK(base, usage|0x55)` — not the long-term key. Deriving them is [`crate::kdf`]'s job, and
//! keeping that out of this module lets a caller derive once and use the keys for several
//! operations (a TGS reply seals a ticket and a reply part under the same usage family), while a
//! caller that has only the base key uses [`crate::Cipher`], which does the derivation.
//!
//! Lengths are checked against the enctype at the door: for enctype 20 a 32-octet `Ki` is exactly
//! the shape of a silent bug, because SHA-384 emits 48 octets and truncating to 32 succeeds
//! quietly.

use crate::aes_cts;
use crate::kdf;
use crate::{Enctype, Error, Result, ct_eq};

/// The AES block size, which is the confounder length and the zero IV of the profile.
pub const BLOCK: usize = 16;

/// The IV Kerberos always uses for the profile: all zeros (RFC 3962 §5, RFC 8009 §5).
const ZERO_IV: [u8; BLOCK] = [0u8; BLOCK];

/// Fails if `ke` is not the right length for `enctype`.
fn check_ke(enctype: Enctype, ke: &[u8]) -> Result<()> {
    if ke.len() != enctype.key_len() {
        return Err(Error::KeyLength {
            enctype,
            want: enctype.key_len(),
            got: ke.len(),
        });
    }
    Ok(())
}

/// Fails if `ki` (or `kc`, which has the same length) is not the right length for `enctype`.
fn check_ki(enctype: Enctype, ki: &[u8]) -> Result<()> {
    if ki.len() != enctype.integrity_key_len() {
        return Err(Error::KeyLength {
            enctype,
            want: enctype.integrity_key_len(),
            got: ki.len(),
        });
    }
    Ok(())
}

/// `HMAC` over `msg` with the enctype's hash.
fn hmac(enctype: Enctype, key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384};
    Ok(match enctype.sha2_kind() {
        None => {
            let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::crypto("HMAC-SHA1 key"))?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        Some(kdf::Sha2Kind::Sha256) => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::crypto("HMAC-SHA256 key"))?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        Some(kdf::Sha2Kind::Sha384) => {
            let mut m = <Hmac<Sha384> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::crypto("HMAC-SHA384 key"))?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    })
}

/// Encrypt `plaintext` with a fresh confounder drawn from the OS.
///
/// The confounder is the only source of IV unpredictability in the construction (RFC 8009 §8):
/// a repeated one leaks that two messages began with the same octets. It therefore comes from
/// the system's random source on every call, never from a counter.
pub fn encrypt(enctype: Enctype, ke: &[u8], ki: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_parts(enctype, ke, ki, &[plaintext])
}

/// [`encrypt`] of the concatenation of `parts`, without building it first.
pub fn encrypt_parts(enctype: Enctype, ke: &[u8], ki: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>> {
    let mut confounder = vec![0u8; enctype.confounder_len()];
    getrandom::fill(&mut confounder).map_err(|e| Error::crypto(format!("getrandom: {e}")))?;
    encrypt_parts_with_confounder(enctype, ke, ki, &confounder, parts)
}

/// [`encrypt`] with the confounder supplied.
///
/// Public because a published vector fixes the confounder: RFC 8009 Appendix A gives eight sample
/// encryptions with known confounders, and without an injection point those vectors cannot be run
/// at all — one is left round-tripping against oneself, which is how a wrong MAC input survives a
/// green suite. Production callers want [`encrypt`]; a fixed confounder outside a test destroys
/// the non-malleability the profile requires.
pub fn encrypt_with_confounder(
    enctype: Enctype,
    ke: &[u8],
    ki: &[u8],
    confounder: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    encrypt_parts_with_confounder(enctype, ke, ki, confounder, &[plaintext])
}

/// [`encrypt_with_confounder`] of the concatenation of `parts`.
pub fn encrypt_parts_with_confounder(
    enctype: Enctype,
    ke: &[u8],
    ki: &[u8],
    confounder: &[u8],
    parts: &[&[u8]],
) -> Result<Vec<u8>> {
    check_ke(enctype, ke)?;
    check_ki(enctype, ki)?;
    check_confounder(enctype, confounder)?;
    let plain = joined(enctype, confounder, parts);
    seal(enctype, ke, ki, &plain)
}

/// The confounder has to be exactly the length the enctype reserves for it.
fn check_confounder(enctype: Enctype, confounder: &[u8]) -> Result<()> {
    if confounder.len() == enctype.confounder_len() {
        return Ok(());
    }
    Err(Error::crypto(format!(
        "confounder is {} octets, {} needs {}",
        confounder.len(),
        enctype.name(),
        enctype.confounder_len()
    )))
}

/// The plaintext to protect: the confounder, then the parts in the order given.
fn joined(enctype: Enctype, confounder: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let len = confounder.len() + parts.iter().map(|p| p.len()).sum::<usize>() + enctype.mac_len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(confounder);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// The sealed message: what this enctype's RFC says the MAC covers, and where the tag goes.
fn seal(enctype: Enctype, ke: &[u8], ki: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    match enctype.sha2_kind() {
        // RFC 3962 §5.3: the MAC covers the plaintext, confounder included, and follows the
        // ciphertext.
        None => {
            let tag = hmac(enctype, ki, plain)?;
            Ok(tagged(
                aes_cts::encrypt(ke, &ZERO_IV, plain)?,
                &tag,
                enctype,
            ))
        }
        // RFC 8009 §5: the MAC covers `IV | C`, so the receiver can check it before decrypting.
        Some(_) => {
            let cipher = aes_cts::encrypt(ke, &ZERO_IV, plain)?;
            let mut macced = Vec::with_capacity(BLOCK + cipher.len());
            macced.extend_from_slice(&ZERO_IV);
            macced.extend_from_slice(&cipher);
            let tag = hmac(enctype, ki, &macced)?;
            Ok(tagged(cipher, &tag, enctype))
        }
    }
}

/// The sealed message: the ciphertext with its MAC truncated to this enctype's length.
fn tagged(mut cipher: Vec<u8>, tag: &[u8], enctype: Enctype) -> Vec<u8> {
    cipher.extend_from_slice(&tag[..enctype.mac_len()]);
    cipher
}

/// [`decrypt`], returning the plaintext without the confounder.
pub fn decrypt(enctype: Enctype, ke: &[u8], ki: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    check_ke(enctype, ke)?;
    check_ki(enctype, ki)?;
    let mac_len = enctype.mac_len();
    let (cipher, tag) = split_tag(enctype, ciphertext, mac_len)?;
    let plain = open(enctype, ke, ki, cipher, tag, mac_len)?;
    // The confounder is there so that two encryptions of the same plaintext differ; it is not part
    // of what the caller asked for, and a plaintext shorter than it means the key was wrong.
    if plain.len() < enctype.confounder_len() {
        return Err(Error::crypto(
            "decrypted plaintext is shorter than the confounder",
        ));
    }
    Ok(plain[enctype.confounder_len()..].to_vec())
}

/// The ciphertext and its tag: the tag is the last `mac_len` octets.
///
/// A ciphertext shorter than a block plus a tag cannot be one: the confounder alone is a block, and
/// the tag has to follow it.
fn split_tag(enctype: Enctype, ciphertext: &[u8], mac_len: usize) -> Result<(&[u8], &[u8])> {
    if ciphertext.len() < BLOCK + mac_len {
        return Err(Error::crypto(format!(
            "ciphertext is {} octets; {} needs at least {}",
            ciphertext.len(),
            enctype.name(),
            BLOCK + mac_len
        )));
    }
    Ok(ciphertext.split_at(ciphertext.len() - mac_len))
}

/// The plaintext with its confounder: integrity first where the enctype allows it.
///
/// The two SHA-2 enctypes (RFC 8009) MAC `IV | C`, so a forged ciphertext never reaches the block
/// cipher; the SHA-1 ones (RFC 3962) MAC the plaintext, so they have to decrypt first and check
/// after.
fn open(
    enctype: Enctype,
    ke: &[u8],
    ki: &[u8],
    cipher: &[u8],
    tag: &[u8],
    mac_len: usize,
) -> Result<Vec<u8>> {
    match enctype.sha2_kind() {
        None => {
            let plain = aes_cts::decrypt(ke, &ZERO_IV, cipher)?;
            check_tag(enctype, ki, &plain, tag, mac_len)?;
            Ok(plain)
        }
        Some(_) => {
            let mut macced = Vec::with_capacity(BLOCK + cipher.len());
            macced.extend_from_slice(&ZERO_IV);
            macced.extend_from_slice(cipher);
            check_tag(enctype, ki, &macced, tag, mac_len)?;
            aes_cts::decrypt(ke, &ZERO_IV, cipher)
        }
    }
}

/// One integrity check, in constant time, over whatever this enctype covers.
fn check_tag(
    enctype: Enctype,
    ki: &[u8],
    covered: &[u8],
    tag: &[u8],
    mac_len: usize,
) -> Result<()> {
    let expect = hmac(enctype, ki, covered)?;
    if !ct_eq(&expect[..mac_len], tag) {
        return Err(Error::crypto("integrity check failed"));
    }
    Ok(())
}

/// The keyed checksum of RFC 3961 §5.4 / RFC 8009 §6: `HMAC` with `Kc`, truncated to `h` octets.
pub fn checksum(enctype: Enctype, kc: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    checksum_parts(enctype, kc, &[data])
}

/// [`checksum`] of the concatenation of `parts`.
pub fn checksum_parts(enctype: Enctype, kc: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>> {
    if kc.len() != enctype.checksum_key_len() {
        return Err(Error::KeyLength {
            enctype,
            want: enctype.checksum_key_len(),
            got: kc.len(),
        });
    }
    let mut msg = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        msg.extend_from_slice(part);
    }
    let tag = hmac(enctype, kc, &msg)?;
    Ok(tag[..enctype.mac_len()].to_vec())
}

/// Fails unless `tag` is the [`checksum`] of `data` under `kc`.
///
/// Constant-time: a comparison that stops at the first differing octet tells an attacker how much
/// of a forged tag was right, which is enough to forge one byte at a time.
pub fn verify_checksum(enctype: Enctype, kc: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
    let expect = checksum(enctype, kc, data)?;
    if ct_eq(&expect, tag) {
        Ok(())
    } else {
        Err(Error::crypto("checksum does not verify"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every enctype round-trips at every length that matters, with the tag checked on the way
    /// back. The lengths include the one-block case, where ciphertext stealing reduces to CBC and
    /// an implementation can quietly invent its own convention.
    #[test]
    fn every_enctype_round_trips_at_every_length() {
        for enctype in Enctype::ALL {
            let ke = vec![0x11u8; enctype.key_len()];
            let ki = vec![0x22u8; enctype.integrity_key_len()];
            for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64] {
                let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let sealed = encrypt(enctype, &ke, &ki, &plain).expect("encrypt");
                assert_eq!(
                    sealed.len(),
                    plain.len() + enctype.confounder_len() + enctype.mac_len(),
                    "{enctype:?} overhead at len {len}"
                );
                assert_eq!(
                    decrypt(enctype, &ke, &ki, &sealed).expect("decrypt"),
                    plain,
                    "{enctype:?} round trip at len {len}"
                );
            }
        }
    }

    /// A single flipped octet, anywhere, has to fail the integrity check — and for 19/20 it has to
    /// fail *before* decryption, which is what makes the two profiles different.
    #[test]
    fn a_flipped_octet_is_refused() {
        for enctype in Enctype::ALL {
            let ke = vec![0x11u8; enctype.key_len()];
            let ki = vec![0x22u8; enctype.integrity_key_len()];
            let sealed = encrypt(enctype, &ke, &ki, b"the answer is forty-two").expect("encrypt");
            for i in [0usize, sealed.len() / 2, sealed.len() - 1] {
                let mut broken = sealed.clone();
                broken[i] ^= 0x01;
                assert!(
                    decrypt(enctype, &ke, &ki, &broken).is_err(),
                    "{enctype:?}: a flipped octet at {i} must not decrypt"
                );
            }
        }
    }

    /// A key of the wrong length is refused at the door rather than derived into something else.
    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let enctype = Enctype::Aes256Sha384;
        let ke = vec![0x11u8; enctype.key_len()];
        let short_ki = vec![0x22u8; 32]; // the shape of the classic enctype-20 bug
        let err = encrypt(enctype, &ke, &short_ki, b"x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("key"), "{err}");
    }

    /// The checksum is truncated to `h` octets and verifies, and a one-bit change does not.
    #[test]
    fn a_checksum_verifies_and_a_changed_one_does_not() {
        for enctype in Enctype::ALL {
            let kc = vec![0x33u8; enctype.checksum_key_len()];
            let tag = checksum(enctype, &kc, b"grace hopper").expect("checksum");
            assert_eq!(tag.len(), enctype.mac_len());
            verify_checksum(enctype, &kc, b"grace hopper", &tag).expect("verifies");
            assert!(verify_checksum(enctype, &kc, b"grace hopper!", &tag).is_err());
        }
    }

    /// `parts` and the joined buffer are the same message: the seam exists for a caller that would
    /// otherwise copy, not to change what is signed.
    #[test]
    fn parts_are_the_same_as_the_joined_message() {
        let enctype = Enctype::Aes256Sha1;
        let kc = vec![0x33u8; enctype.checksum_key_len()];
        assert_eq!(
            checksum(enctype, &kc, b"abc").unwrap(),
            checksum_parts(enctype, &kc, &[b"a", b"bc"]).unwrap()
        );

        let ke = vec![0x11u8; enctype.key_len()];
        let ki = vec![0x22u8; enctype.integrity_key_len()];
        let conf = [0x77u8; 16];
        assert_eq!(
            encrypt_with_confounder(enctype, &ke, &ki, &conf, b"abc").unwrap(),
            encrypt_parts_with_confounder(enctype, &ke, &ki, &conf, &[b"a", b"bc"]).unwrap()
        );
    }

    /// A confounder of the wrong length is refused rather than padded: the length is what the
    /// receiver strips, so a short one silently shifts the plaintext.
    #[test]
    fn a_short_confounder_is_refused() {
        let enctype = Enctype::Aes256Sha1;
        let ke = vec![0x11u8; enctype.key_len()];
        let ki = vec![0x22u8; enctype.integrity_key_len()];
        let err = encrypt_with_confounder(enctype, &ke, &ki, &[0u8; 8], b"x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("confounder"), "{err}");
    }
}
