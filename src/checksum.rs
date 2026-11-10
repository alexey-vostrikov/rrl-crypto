//! Keyed checksums: the constructions that take a Kerberos key and produce a tag.
//!
//! RFC 3961 §5.4 describes the profile's own checksum, which is an HMAC with `Kc` truncated to the
//! enctype's MAC length; that lives in [`crate::profile`] because it needs the enctype. What is
//! here is the other family: checksums that a protocol names by number and computes over a
//! structure the enctype knows nothing about.
//!
//! # Why this is one function and not two copies
//!
//! [`KERB_CHECKSUM_HMAC_MD5`] is used by the PAC (`rrl-krb`, MS-PAC §2.6.1) and by S4U's
//! `PA-FOR-USER` (`rust-kdc`, MS-SFU §2.2.3). Both need the same construction from RFC 4757 §7.1,
//! and it was written twice before this module existed. Two copies of a checksum are two ways to
//! produce a tag the other side rejects, and that surfaces as "the PAC does not verify" on a
//! domain rather than as a failing test.
//!
//! # The construction, and why it is not a plain HMAC
//!
//! RFC 4757 §7.1 derives a signature key first:
//!
//! ```text
//! Ksign = HMAC-MD5(key, "signaturekey\0")
//! tag   = HMAC-MD5(Ksign, MD5(usage_le || data))
//! ```
//!
//! Skipping the first step gives a tag that verifies nowhere. The inner MD5 over the usage word
//! and the message is what makes a signature over a long PAC cost one hash of it, and the usage
//! word is *little-endian* because that is the wire order the RC4-HMAC era used everywhere. Both
//! are the kind of detail that a self-round-trip cannot catch: an implementation that got either
//! wrong would agree with itself perfectly and with Windows never.

use crate::ct_eq;

/// `KERB_CHECKSUM_HMAC_MD5`, RFC 4757 §7.1 — the older of the two checksum types a PAC carries.
///
/// The value is negative because the checksum-type space is `Int32` and this one sits above
/// `0x7FFFFFFF`: MIT spells it `CKSUMTYPE_HMAC_MD5_ARCFOUR = -138`, which is `0xFFFFFF76` on the
/// wire. Pinned here against the literal so that a typo cannot ride along with the constant name
/// everywhere it is used.
pub const KERB_CHECKSUM_HMAC_MD5: i32 = -138;

/// The length of a [`kerb_checksum_hmac_md5`] tag: MD5's output, never truncated.
pub const KERB_CHECKSUM_HMAC_MD5_LEN: usize = 16;

/// The signature key of RFC 4757 §7.1, `"signaturekey"` with its terminating NUL.
const SIGNATURE_KEY: &[u8] = b"signaturekey\0";

/// `KERB_CHECKSUM_HMAC_MD5` over `data` under `key` at `usage` (RFC 4757 §7.1).
///
/// Infallible on purpose: HMAC accepts a key of any length, so the only `new_from_slice` failure
/// mode this could report is one that cannot happen. An unreachable error variant is worse than
/// none — it invites a caller to handle something that will never arrive.
///
/// `usage` is the Kerberos key usage (`MS-SFU` uses 17, the PAC uses 0), and it goes onto the wire
/// little-endian.
pub fn kerb_checksum_hmac_md5(
    key: &[u8],
    usage: u32,
    data: &[u8],
) -> [u8; KERB_CHECKSUM_HMAC_MD5_LEN] {
    use hmac::{Hmac, KeyInit, Mac};
    use md5::{Digest, Md5};

    let mut ksign =
        <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    ksign.update(SIGNATURE_KEY);
    let ksign = ksign.finalize().into_bytes();

    let mut inner = Md5::new();
    inner.update(usage.to_le_bytes());
    inner.update(data);
    let digest = inner.finalize();

    let mut outer =
        <Hmac<Md5> as KeyInit>::new_from_slice(&ksign).expect("HMAC accepts any key length");
    outer.update(&digest);
    outer.finalize().into_bytes().into()
}

/// Checks a [`kerb_checksum_hmac_md5`] tag without leaking where it differs.
///
/// A comparison that returns at the first differing octet tells an attacker how much of a forged
/// tag was right, one query at a time — and a PAC signature is verified on a server that answers.
pub fn verify_kerb_checksum_hmac_md5(key: &[u8], usage: u32, data: &[u8], tag: &[u8]) -> bool {
    ct_eq(&kerb_checksum_hmac_md5(key, usage, data), tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The number is a wire constant, and a test that reads it from the same constant proves
    /// nothing. `-138` is `CKSUMTYPE_HMAC_MD5_ARCFOUR` in MIT's `krb5.h`.
    #[test]
    fn the_checksum_type_is_the_number_mit_uses() {
        assert_eq!(KERB_CHECKSUM_HMAC_MD5, -138);
        assert_eq!(KERB_CHECKSUM_HMAC_MD5 as u32, 0xFFFF_FF76);
        assert_eq!(KERB_CHECKSUM_HMAC_MD5_LEN, 16);
    }

    /// RFC 4757 §7.1's two steps, checked against a hand computation rather than against the
    /// function under test: `Ksign` is the HMAC-MD5 of the literal `"signaturekey\0"`, and the tag
    /// is the HMAC-MD5 of `MD5(usage_le || data)` under `Ksign`.
    ///
    /// This is the test that would catch a plain HMAC (either step skipped) and a big-endian
    /// usage, which no round-trip can.
    #[test]
    fn the_two_steps_are_the_ones_rfc_4757_describes() {
        use hmac::{Hmac, KeyInit, Mac};
        use md5::{Digest, Md5};

        let key = [0x0bu8; 16];
        let usage = 17u32;
        let data = b"the message a PAC would sign";

        // Step one, by hand.
        let mut k = <Hmac<Md5> as KeyInit>::new_from_slice(&key).expect("key");
        k.update(b"signaturekey\0");
        let ksign = k.finalize().into_bytes();

        // Step two, by hand, with the usage word written little-endian explicitly.
        let mut inner = Md5::new();
        inner.update([17u8, 0, 0, 0]);
        inner.update(data);
        let digest = inner.finalize();
        let mut outer = <Hmac<Md5> as KeyInit>::new_from_slice(&ksign).expect("key");
        outer.update(&digest);
        let expected: [u8; 16] = outer.finalize().into_bytes().into();

        assert_eq!(kerb_checksum_hmac_md5(&key, usage, data), expected);
    }

    /// A plain HMAC over the message is a different value, so a caller that skipped the `Ksign`
    /// step — the classic mistake — would fail here rather than agree with itself.
    #[test]
    fn it_is_not_a_plain_hmac() {
        use hmac::{Hmac, KeyInit, Mac};
        use md5::Md5;

        let key = [0x5au8; 16];
        let mut plain = <Hmac<Md5> as KeyInit>::new_from_slice(&key).expect("key");
        plain.update(b"data");
        let plain: [u8; 16] = plain.finalize().into_bytes().into();

        assert_ne!(kerb_checksum_hmac_md5(&key, 0, b"data"), plain);
    }

    /// The usage word is part of the input: two usages over the same data differ.
    #[test]
    fn a_different_usage_gives_a_different_tag() {
        let key = [0x11u8; 16];
        assert_ne!(
            kerb_checksum_hmac_md5(&key, 0, b"pac"),
            kerb_checksum_hmac_md5(&key, 17, b"pac")
        );
    }

    /// Verification accepts the right tag and refuses a changed one, at every octet.
    #[test]
    fn verification_notices_every_changed_octet() {
        let key = [0x22u8; 16];
        let tag = kerb_checksum_hmac_md5(&key, 3, b"evidence");
        assert!(verify_kerb_checksum_hmac_md5(&key, 3, b"evidence", &tag));

        for i in 0..16 {
            let mut broken = tag;
            broken[i] ^= 0x01;
            assert!(
                !verify_kerb_checksum_hmac_md5(&key, 3, b"evidence", &broken),
                "a tag changed at octet {i} must not verify"
            );
        }
        // A tag of the wrong length is refused rather than compared on its prefix.
        assert!(!verify_kerb_checksum_hmac_md5(
            &key,
            3,
            b"evidence",
            &tag[..15]
        ));
    }

    /// A key of any length is accepted — HMAC normalises it — which is why the function reports no
    /// error: an empty key is a caller's bug, not a cryptographic one, and it still produces a tag.
    #[test]
    fn any_key_length_works() {
        for len in [0usize, 1, 16, 32, 200] {
            let key = vec![0x7fu8; len];
            assert_eq!(kerb_checksum_hmac_md5(&key, 0, b"x").len(), 16);
        }
    }
}
