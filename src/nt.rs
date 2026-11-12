//! The NT hash: MD4 over a password's UTF-16LE octets (MS-NLMP 3.3.1).
//!
//! # Why it takes octets and not a string
//!
//! A machine account's password is not text: a join draws it from 120 random octets and sends them
//! as UTF-16LE, so the value may contain unpaired surrogates that no `String` can hold. A function
//! that took `&str` would have to be fed a lossy spelling, and the hash would then be computed over
//! something nobody sent. The octets are what arrives and the octets are what gets hashed.
//!
//! # Why here
//!
//! Two crates computed this independently - the directory that derives an account's keys, and the
//! SMB layer that checks a secure channel - which is exactly the kind of pair that disagrees
//! silently: both are correct on the same input and one of them is fed a different input.
//!
//! Plain MD4, no salt, no iteration. It is not a password hash in the modern sense and must not be
//! used as one; it exists because a domain's wire protocol defines the secure channel in terms of
//! it.

use crate::{Error, Result};

/// MD4 over the password's UTF-16LE octets.
///
/// An odd number of octets is refused rather than padded or truncated: UTF-16LE is a sequence of
/// two-octet units, so an odd length is not a password that was ever encoded this way, and hashing
/// it would produce a value no client computes.
pub fn hash(utf16: &[u8]) -> Result<[u8; 16]> {
    if !utf16.len().is_multiple_of(2) {
        return Err(Error::crypto(format!(
            "an NT hash is taken over UTF-16LE, which comes in whole two-octet units; \
             an odd number of octets ({}) is not a password encoded this way",
            utf16.len()
        )));
    }

    use md4::{Digest, Md4};
    let mut hasher = Md4::new();
    hasher.update(utf16);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// The same hash, for a password held as text.
///
/// The convenience spelling for callers that have a password rather than octets - a bootstrap that
/// reads one from a configuration file. It encodes with `encode_utf16`, so the two entry points
/// agree by construction.
pub fn hash_password(password: &str) -> [u8; 16] {
    let octets: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    hash(&octets).expect("a string's UTF-16LE encoding is always an even number of octets")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-NLMP 3.3.1 with the password "Password".
    ///
    /// The expected value is its own: not built from anything this crate computes, and checkable
    /// with `printf 'Password' | iconv -f utf-8 -t utf-16le | openssl dgst -md4 -provider legacy`.
    #[test]
    fn the_hash_of_password_matches_the_published_value() {
        let utf16: Vec<u8> = "Password"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            hash(&utf16).expect("an even number of octets"),
            [
                0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f,
                0xd8, 0x52
            ]
        );
    }

    /// An empty password has a hash too, and it is not the empty string.
    ///
    /// A function that returned `[0u8; 16]` for the empty input would still pass the test above.
    #[test]
    fn an_empty_password_hashes_to_md4_of_nothing() {
        assert_eq!(
            hash(&[]).expect("an even number of octets, zero included"),
            [
                0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
                0x89, 0xc0
            ]
        );
    }

    /// A password that is not a sequence of UTF-16 units is refused.
    #[test]
    fn an_odd_number_of_octets_is_refused() {
        let err = hash(&[0x50, 0x00, 0x61]).expect_err("three octets are not a UTF-16 password");
        assert!(
            err.to_string().contains("odd") || err.to_string().contains("UTF-16"),
            "the refusal must say why: {err}"
        );
    }

    /// The text entry point and the octet entry point are one computation.
    #[test]
    fn the_text_spelling_agrees_with_the_octets() {
        let utf16: Vec<u8> = "Password"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            hash_password("Password"),
            hash(&utf16).expect("an even number of octets")
        );
    }

    /// One bit anywhere in the password changes the hash: a hash that ignored the tail of a long
    /// password would still pass every vector above, all of which are short.
    #[test]
    fn a_long_password_is_hashed_in_full() {
        let a: Vec<u8> = "x"
            .repeat(200)
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let b_octets = &mut a.clone();
        let last = b_octets.len() - 2;
        b_octets[last] ^= 0x01;

        assert_ne!(
            hash(&a).expect("even"),
            hash(b_octets).expect("even"),
            "the last unit of a 200-character password must reach the hash"
        );
    }
}
