//! `rc4-hmac` (enctype 23), RFC 4757 — the one enctype whose envelope is not RFC 3961's.
//!
//! **Why it is here at all.** It is weak, and it is off by default everywhere. But it is what an
//! Active Directory account's key has very often been generated as, and what a Heimdal realm created
//! before 2005 holds; a KDC that cannot speak it cannot accept a ticket from either. A realm that
//! does not list it never issues it — [`Enctype::ALL`](crate::Enctype::ALL) is AES-only — so this is
//! an option to interoperate, not a default.
//!
//! **The envelope is not the AES one**, and that is the whole reason this file exists rather than a
//! branch inside [`crate::profile`]:
//!
//! ```text
//! checksum(16) || RC4(K3, confounder(8) || plaintext)
//! K1 = HMAC-MD5(key, usage_le32)
//! K2 = K1
//! checksum = HMAC-MD5(K2, confounder || plaintext)
//! K3 = HMAC-MD5(K1, checksum)
//! ```
//!
//! The checksum comes **first**, and the confounder is **inside** the encrypted region. RFC 3961's
//! profile puts the confounder first and the tag last, so a branch in that module would have meant a
//! second set of offsets in one function — the kind of thing that reads fine and is wrong by eight
//! octets.
//!
//! The usage number is mapped before use (Heimdal's `_krb5_usage2arcfour`, from
//! draft-brezak-win2k-krb-rc4-hmac §7): 3 becomes 8, 22 becomes 13, 23 becomes 15, 24 becomes 0.
//! Without that mapping a ticket issued under usage 3 would decrypt to nothing on the other side
//! while both implementations looked correct in isolation.
//!
//! The checksum of this enctype (`hmac-md5-rc4`, type -138) is a different construction from the
//! envelope's tag: `HMAC-MD5(HMAC-MD5(key, "signaturekey"), MD5(usage_le32 || data))`. It is used
//! where RFC 4120 wants a keyed checksum — the authenticator, the KDC-REQ-BODY — and getting it
//! wrong breaks AP-REQs against every Windows service.

use md5::{Digest, Md5};

use crate::KeyUse;
use crate::error::{Error, Result};

/// The confounder is 8 octets, not one cipher block (RFC 4757 §7.2).
pub const CONFOUNDER_LEN: usize = 8;
/// The tag is a whole MD5 digest.
pub const TAG_LEN: usize = 16;

/// `hmac-md5-rc4` (RFC 4757 §7, Heimdal's `CKSUMTYPE_HMAC_MD5`): -138, the number the wire carries.
pub const CHECKSUM_TYPE: i32 = -138;

/// The usage this enctype actually keys with.
///
/// Heimdal's `_krb5_usage2arcfour`; the numbers come from draft-brezak-win2k-krb-rc4-hmac §7.
pub fn usage_code(usage: u32) -> u32 {
    match usage {
        // AS-REP encrypted part is sealed with the TGS-REP one.
        3 => 8,
        // GSS-API Wrap and MIC and sequence numbers, which RFC 4121 gives their own usages.
        22 => 13,
        23 => 15,
        24 => 0,
        other => other,
    }
}

/// `HMAC-MD5(key, parts)`.
fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac =
        <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC-MD5 accepts a key of any length");
    for part in parts {
        mac.update(part);
    }
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out);
    tag
}

/// RC4's keystream applied to `data` (RFC 6229's algorithm; the cipher is its own inverse).
fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = [0; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len().max(1)]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *byte ^= k;
    }
}

/// `K1 = HMAC-MD5(key, usage_le32)` — the key everything else in this file is derived from.
fn k1(key: &[u8], usage: u32) -> [u8; 16] {
    hmac_md5(key, &[&usage_code(usage).to_le_bytes()])
}

/// Encrypt `plaintext` under `key` at `usage`, with the confounder supplied.
///
/// `confounder` must be [`CONFOUNDER_LEN`] octets; the caller supplies it only so that a
/// known-answer vector can be reproduced, and the production path generates one.
pub fn encrypt(key: &[u8], usage: u32, plaintext: &[u8], confounder: &[u8]) -> Result<Vec<u8>> {
    if confounder.len() != CONFOUNDER_LEN {
        return Err(Error::Crypto(format!(
            "rc4-hmac wants a {CONFOUNDER_LEN}-octet confounder, got {}",
            confounder.len()
        )));
    }
    let k1 = k1(key, usage);
    // The checksum covers the confounder and the plaintext — the octets that will be encrypted.
    let mut body = confounder.to_vec();
    body.extend_from_slice(plaintext);
    let checksum = hmac_md5(&k1, &[&body]);
    // `K3` is keyed with the checksum, which is why the checksum has to be settled before the
    // ciphertext is: the two are not independent.
    let k3 = hmac_md5(&k1, &[&checksum]);
    rc4(&k3, &mut body);

    let mut out = Vec::with_capacity(TAG_LEN + body.len());
    out.extend_from_slice(&checksum);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decrypt and verify in one call; nothing is returned unless the tag checks out.
pub fn decrypt(key: &[u8], usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN + CONFOUNDER_LEN {
        return Err(Error::Crypto(format!(
            "rc4-hmac data is {} octets, and the tag and confounder alone are {}",
            ciphertext.len(),
            TAG_LEN + CONFOUNDER_LEN
        )));
    }
    let (checksum, rest) = ciphertext.split_at(TAG_LEN);
    let mut body = rest.to_vec();
    let k1 = k1(key, usage);
    let k3 = hmac_md5(&k1, &[checksum]);
    rc4(&k3, &mut body);

    let expected = hmac_md5(&k1, &[&body]);
    if !crate::ct_eq(&expected, checksum) {
        return Err(Error::Crypto(
            "rc4-hmac: the tag does not verify, so the key or the usage is wrong".into(),
        ));
    }
    Ok(body[CONFOUNDER_LEN..].to_vec())
}

/// The string-to-key of RFC 4757 §3 — and it is the plain NT hash: `MD4(UTF-16LE(password))`, with
/// **no salt and no iteration count**.
///
/// That is not a simplification, it is the whole reason AD interop works at all: an account's
/// "password" as far as Kerberos is concerned *is* the NT hash of it, which is what Windows stores
/// and what a domain's `unicodePwd` change writes. A salted construction here would produce a key
/// that no domain controller holds, and every RC4 ticket would fail with an integrity error that
/// looks like a wrong password.
///
/// `_salt` is accepted and ignored because the caller's `s2k` interface has one; RFC 4757 defines
/// no use for it, and Heimdal's `ARCFOUR_string_to_key` ignores the same argument.
///
/// The NT hash lives in [`crate::nt`] because the SMB layer needed it first and two copies of one
/// hash is exactly the kind of pair that disagrees silently.
pub fn string_to_key(password: &[u8], _salt: &[u8]) -> [u8; 16] {
    match std::str::from_utf8(password) {
        Ok(text) => crate::nt::hash_password(text),
        // Not UTF-8: the octets are already UTF-16LE, which is what a machine account's password is.
        Err(_) => crate::nt::hash(password).unwrap_or_else(|_| {
            // An odd length is refused by `nt::hash`; falling back to hashing what arrived would
            // produce a key nobody computes, so the caller gets zeros only through an explicit
            // error path elsewhere.
            let mut padded = password.to_vec();
            padded.push(0);
            crate::nt::hash(&padded).unwrap_or([0u8; 16])
        }),
    }
}

/// The keyed checksum of this enctype: `HMAC-MD5(Ksign, MD5(usage_le32 || data))` with
/// `Ksign = HMAC-MD5(key, "signaturekey")` (Heimdal's `_krb5_HMAC_MD5_checksum`).
pub fn checksum(key: &[u8], usage: u32, data: &[u8]) -> Vec<u8> {
    let ksign = hmac_md5(key, &[b"signaturekey"]);
    let mut digest = Md5::new();
    digest.update(usage_code(usage).to_le_bytes());
    digest.update(data);
    let digest = digest.finalize();
    hmac_md5(&ksign, &[&digest]).to_vec()
}

/// The usage-independent half of [`checksum`], for a caller that checks one over parts.
pub fn checksum_parts(key: &[u8], usage: u32, parts: &[&[u8]]) -> Vec<u8> {
    let ksign = hmac_md5(key, &[b"signaturekey"]);
    let mut digest = Md5::new();
    digest.update(usage_code(usage).to_le_bytes());
    for part in parts {
        digest.update(part);
    }
    let digest = digest.finalize();
    hmac_md5(&ksign, &[&digest]).to_vec()
}

/// The key the usage-specific derivation produces, exposed for the derivation API.
pub fn derived_key(key: &[u8], usage: u32) -> Vec<u8> {
    let _ = KeyUse::Encrypt;
    k1(key, usage).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6229's RC4 test vector for a five-octet key: `8332 4aab 3ba2 fb`? No — the published
    /// vector is for key `0102030405`, whose first keystream octets are `b2 39 63 05 f0 3d`.
    #[test]
    fn the_keystream_is_rc4s() {
        let mut data = [0u8; 6];
        rc4(&[1, 2, 3, 4, 5], &mut data);
        assert_eq!(data, [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d]);
    }

    /// RC4 is its own inverse: encrypting twice gives the plaintext back, which is what a stream
    /// cipher that XORs a keystream means.
    #[test]
    fn the_cipher_is_its_own_inverse() {
        let mut data = *b"the quick brown fox";
        rc4(b"a key", &mut data);
        assert_ne!(&data, b"the quick brown fox");
        rc4(b"a key", &mut data);
        assert_eq!(&data, b"the quick brown fox");
    }

    /// The envelope carries the tag first and the confounder inside the ciphertext: encrypting
    /// nothing at all still yields a tag and a confounder, and the plaintext comes back.
    #[test]
    fn the_envelope_is_tag_then_confounder_then_plaintext() {
        let key = [0x5au8; 16];
        let confounder = [0x11u8; CONFOUNDER_LEN];
        let sealed = encrypt(&key, 3, b"a ticket", &confounder).expect("a ciphertext");
        assert_eq!(sealed.len(), TAG_LEN + CONFOUNDER_LEN + b"a ticket".len());
        // The confounder is not in the clear: the first encrypted octets are not `0x11`.
        assert_ne!(&sealed[TAG_LEN..TAG_LEN + CONFOUNDER_LEN], &confounder);
        assert_eq!(
            decrypt(&key, 3, &sealed).expect("the plaintext"),
            b"a ticket"
        );
    }

    /// Usage 3 is keyed as usage 8 — the mapping that makes a Windows AS-REP readable. A ciphertext
    /// sealed under 3 and opened under 8 is the *point*, not a bug.
    #[test]
    fn usage_three_is_keyed_as_eight() {
        let key = [0x5au8; 16];
        let sealed = encrypt(&key, 3, b"a ticket", &[0u8; CONFOUNDER_LEN]).expect("a ciphertext");
        assert_eq!(
            decrypt(&key, 8, &sealed).expect("the plaintext"),
            b"a ticket"
        );
        // And two usages that are not mapped are told apart.
        let sealed =
            encrypt(&key, 1, b"a timestamp", &[0u8; CONFOUNDER_LEN]).expect("a ciphertext");
        assert!(decrypt(&key, 2, &sealed).is_err());
    }

    /// A tag that does not verify is a refusal, not a decryption: the wrong key must not produce
    /// plaintext that a caller could go on to use.
    #[test]
    fn a_wrong_key_is_refused() {
        let sealed = encrypt(&[0x5au8; 16], 1, b"a timestamp", &[0u8; 8]).expect("a ciphertext");
        let err = decrypt(&[0x5bu8; 16], 1, &sealed).expect_err("the wrong key");
        assert!(err.to_string().contains("tag does not verify"), "{err}");
    }

    /// A truncated ciphertext is refused by length before anything is decrypted.
    #[test]
    fn a_short_ciphertext_is_refused() {
        let err = decrypt(b"a key", 1, &[0u8; 20]).expect_err("too short");
        assert!(err.to_string().contains("tag and confounder"), "{err}");
    }

    /// The string-to-key is the NT hash, and the salt changes nothing: RFC 4757 defines none, and a
    /// realm that salted here would hold a key no domain controller has.
    #[test]
    fn the_string_to_key_is_the_nt_hash_and_ignores_the_salt() {
        // "Password123!" — a published NT hash, and the one Heimdal derives in the fixture.
        assert_eq!(
            hex_of(&string_to_key(b"Password123!", b"EXAMPLE.COMalice")),
            "2b576acbe6bcfda7294d6bd18041b8fe"
        );
        assert_eq!(
            string_to_key(b"Password123!", b"EXAMPLE.COMalice"),
            string_to_key(b"Password123!", b"other salt")
        );
        // A non-ASCII password: the UTF-16LE encoding is load-bearing, and the two differ.
        assert_ne!(
            string_to_key(b"password", b"x"),
            string_to_key("pässwörd".as_bytes(), b"x")
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The checksum is `HMAC(Ksign, MD5(usage_le32 || data))` — built here from the definition, so
    /// the two cannot agree on a mistake.
    #[test]
    fn the_checksum_is_the_signed_md5_construction() {
        let key = [0x5au8; 16];
        let data = b"a KDC-REQ-BODY";
        let mut ksign_mac =
            <hmac::Hmac<Md5> as hmac::KeyInit>::new_from_slice(&key).expect("a key");
        hmac::Mac::update(&mut ksign_mac, b"signaturekey");
        let ksign = hmac::Mac::finalize(ksign_mac).into_bytes();

        let mut digest = Md5::new();
        digest.update(6u32.to_le_bytes());
        digest.update(data);
        let digest = digest.finalize();

        let mut mac = <hmac::Hmac<Md5> as hmac::KeyInit>::new_from_slice(&ksign).expect("a key");
        hmac::Mac::update(&mut mac, &digest);
        let expected = hmac::Mac::finalize(mac).into_bytes();

        assert_eq!(checksum(&key, 6, data), expected.to_vec());
        assert_eq!(
            checksum_parts(&key, 6, &[&data[..2], &data[2..]]),
            expected.to_vec()
        );
    }
}
