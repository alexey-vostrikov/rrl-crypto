//! RSA PKCS #1 v1.5 signatures (RFC 8017 §8.2) over SHA-2: verifying the
//! KDC's and the CAs' signatures, and signing a client's AuthPack.
//!
//! Verification re-encodes the expected EMSA-PKCS1-v1_5 block and compares
//! it whole, as RFC 8017 §8.2.2 recommends, so there is no padding parser
//! to fool (Bleichenbacher's 2006 forgery). Signing uses the private
//! exponent through constant-time Montgomery exponentiation (the `rsa`
//! crate's 0.9 line leaks timing there: RUSTSEC-2023-0071) and checks the
//! signature before releasing it, against fault attacks.

use super::asn1::{self, ReaderExt};
use super::bigint::{less, modpow};
pub use super::keys::Hash;
use crate::der::{self, DerError, Reader};

pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// Moduli outside this range are refused: below 2048 bits is weaker than
/// OpenSSL's security level 2 allows; above 16384 only costs time.
const MIN_BITS: usize = 2048;
const MAX_BITS: usize = 16384;

/// EMSA-PKCS1-v1_5 for a `k`-octet modulus: `00 01 FF.. 00 DigestInfo`,
/// the DigestInfo's AlgorithmIdentifier with NULL parameters or without.
fn emsa(hash: Hash, digest: &[u8], k: usize, with_null: bool) -> Option<Vec<u8>> {
    let info = der::seq(&[
        asn1::alg_id(hash.oid(), with_null.then(asn1::null)),
        der::octets(digest),
    ]);
    if k < info.len() + 11 {
        return None;
    }
    let mut em = vec![0xFF; k];
    em[0] = 0;
    em[1] = 1;
    em[k - info.len() - 1] = 0;
    em[k - info.len()..].copy_from_slice(&info);
    Some(em)
}

/// An RSA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

/// The modulus has to be the size this implementation works in, and odd.
///
/// Even is not a workable modulus at all: an even `n` has 2 as a factor, and every exponentiation
/// modulo it loses information. The length check is a policy decision — it keeps the arithmetic
/// inside the size the tests cover — and it says so rather than leaving a reader to guess.
fn check_modulus(n: &[u8]) -> Result<(), DerError> {
    let bits = n.len() * 8;
    if !(MIN_BITS..=MAX_BITS).contains(&bits) {
        return Err(DerError(format!(
            "unsupported RSA modulus of {} octets",
            n.len()
        )));
    }
    if n[n.len() - 1] & 1 == 0 {
        return Err(DerError("an RSA modulus cannot be even".into()));
    }
    Ok(())
}

/// The public exponent has to be odd, more than one, and small enough to exponentiate with.
///
/// `e = 1` is refused by name because it is the one wrong exponent that produces a signature check
/// which passes for every input: `m^1 mod n = m`, so any `sig == emsa(..)` verifies.
fn check_exponent(e: &[u8]) -> Result<(), DerError> {
    if e.is_empty() || e.len() > 8 {
        return Err(DerError("unsupported RSA public exponent".into()));
    }
    if e == [1] || e[e.len() - 1] & 1 == 0 {
        return Err(DerError("unsupported RSA public exponent".into()));
    }
    Ok(())
}

impl PublicKey {
    /// `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`, the
    /// content of an `rsaEncryption` SubjectPublicKeyInfo's BIT STRING.
    pub fn from_der(der: &[u8]) -> Result<PublicKey, DerError> {
        let mut r = Reader::new(der);
        let mut s = r.seq()?;
        let n = s.uint()?.to_vec();
        let e = s.uint()?.to_vec();
        s.done("RSAPublicKey")?;
        r.done("RSAPublicKey")?;
        check_modulus(&n)?;
        check_exponent(&e)?;
        Ok(PublicKey { n, e })
    }

    /// Whether `sig` is this key's PKCS #1 v1.5 signature over `digest`.
    pub fn verify(&self, hash: Hash, digest: &[u8], sig: &[u8]) -> bool {
        let k = self.n.len();
        if sig.len() != k || !less(sig, &self.n) {
            return false;
        }
        let Some(em) = modpow(sig, &self.e, &self.n) else {
            return false;
        };
        [true, false]
            .into_iter()
            .any(|null| emsa(hash, digest, k, null).as_deref() == Some(&em[..]))
    }

    /// This modulus' length in octets: what an encrypted block must fill.
    #[cfg(any(test, feature = "test-support"))]
    pub fn modulus_len(&self) -> usize {
        self.n.len()
    }

    /// PKCS #1 v1.5 **encryption** (type 2) of `plaintext`: `00 02 PS 00 M`, with `PS` non-zero and
    /// at least eight octets long. The mirror of [`PrivateKey::decrypt_pkcs1_v15`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn encrypt_pkcs1_v15(&self, plaintext: &[u8]) -> Result<Vec<u8>, DerError> {
        use rand::RngCore;
        let k = self.modulus_len();
        if plaintext.len() + 11 > k {
            return Err(DerError(
                "the plaintext does not fit this RSA key with PKCS #1 v1.5 padding".into(),
            ));
        }
        let mut em = vec![0x00, 0x02];
        let mut ps = vec![0u8; k - plaintext.len() - 3];
        while ps.contains(&0) {
            rand::thread_rng().fill_bytes(&mut ps);
        }
        em.extend_from_slice(&ps);
        em.push(0x00);
        em.extend_from_slice(plaintext);
        if !less(&em, &self.n) {
            return Err(DerError("the padded block is not below the modulus".into()));
        }
        modpow(&em, &self.e, &self.n).ok_or_else(|| DerError("RSA encryption failed".into()))
    }
}

/// An RSA private key.
#[derive(Clone)]
pub struct PrivateKey {
    public: PublicKey,
    d: Vec<u8>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RSA private key ({} bits)", self.public.n.len() * 8)
    }
}

/// The key inside a PKCS #8 wrapper.
fn pkcs8_inner(s: &mut Reader<'_>) -> Result<PrivateKey, DerError> {
    let (alg, _) = s.alg_id()?;
    if alg != asn1::oid(RSA_ENCRYPTION) {
        return Err(DerError(
            "the private key is not RSA (only RSA keys are supported)".into(),
        ));
    }
    PrivateKey::from_der(s.octets()?)
}

/// The key in its own `RSAPrivateKey`: `n`, `e`, `d`, and the CRT parameters nothing here uses.
fn pkcs1_inner(s: &mut Reader<'_>) -> Result<PrivateKey, DerError> {
    let n = s.uint()?.to_vec();
    let e = s.uint()?.to_vec();
    let d = s.uint()?.to_vec();
    let public = PublicKey::from_der(&der::seq(&[asn1::uint(&n), asn1::uint(&e)]))?;
    if d.is_empty() || !less(&d, &public.n) {
        return Err(DerError("bad RSA private exponent".into()));
    }
    // `d` is padded to the modulus length, so the exponentiation's time says nothing about its
    // length.
    let mut padded = vec![0; public.n.len() - d.len()];
    padded.extend_from_slice(&d);
    Ok(PrivateKey { public, d: padded })
}

/// The ciphertext as the k-octet integer it has to be.
///
/// A value wider than the modulus is not a block this key can have made: `modpow` would silently
/// work modulo n and produce a plaintext the padding check then rejects, with a message about
/// padding where the truth is about the ciphertext's size.
fn left_pad(ciphertext: &[u8], k: usize) -> Result<Vec<u8>, DerError> {
    if ciphertext.is_empty() || ciphertext.len() > k {
        return Err(DerError(
            "the encrypted key is not the modulus' length".into(),
        ));
    }
    let mut c = vec![0; k - ciphertext.len()];
    c.extend_from_slice(ciphertext);
    Ok(c)
}

/// The message inside a PKCS #1 v1.5 block: `00 02 PS 00 M`, with `PS` at least eight octets.
fn unpkcs1(em: &[u8]) -> Result<Vec<u8>, DerError> {
    let bad = || DerError("the encrypted key is not a PKCS #1 v1.5 block".into());
    if em.len() < 2 || em[0] != 0x00 || em[1] != 0x02 {
        return Err(bad());
    }
    let rest = &em[2..];
    let sep = rest.iter().position(|&b| b == 0).ok_or_else(bad)?;
    // RFC 8017 §7.2.2: the padding string is at least eight octets, which is what makes a
    // block guessable only to someone who could already compute the key.
    if sep < 8 {
        return Err(bad());
    }
    Ok(rest[sep + 1..].to_vec())
}

impl PrivateKey {
    /// PKCS #1 `RSAPrivateKey` (PEM `RSA PRIVATE KEY`) or a PKCS #8
    /// `PrivateKeyInfo` holding one (PEM `PRIVATE KEY`, what `openssl req
    /// -newkey` writes).
    pub fn from_der(der: &[u8]) -> Result<PrivateKey, DerError> {
        let mut r = Reader::new(der);
        let mut s = r.seq()?;
        r.done("private key")?;
        s.uint()?; // version
        // PKCS #8 wraps the same structure: AlgorithmIdentifier, then the key in an OCTET STRING.
        if s.rest().first() == Some(&der::SEQUENCE) {
            pkcs8_inner(&mut s)
        } else {
            pkcs1_inner(&mut s)
        }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The PKCS #1 v1.5 signature over `digest`, the DigestInfo with NULL
    /// parameters as OpenSSL writes it.
    pub fn sign(&self, hash: Hash, digest: &[u8]) -> Result<Vec<u8>, DerError> {
        let k = self.public.n.len();
        let em = emsa(hash, digest, k, true)
            .ok_or_else(|| DerError("RSA modulus too small for the digest".into()))?;
        let sig = modpow(&em, &self.d, &self.public.n)
            .ok_or_else(|| DerError("RSA signing failed".into()))?;
        if !self.public.verify(hash, digest, &sig) {
            return Err(DerError(
                "RSA signature does not verify (inconsistent private key)".into(),
            ));
        }
        Ok(sig)
    }

    /// The plaintext of a PKCS #1 v1.5 **encryption** block (type 2), which is what CMS
    /// `KeyTransRecipientInfo` carries: `c = m^d mod n`, then `00 02 PS 00 M` with at least eight
    /// non-zero padding octets.
    ///
    /// The padding check is deliberately one error: a decoder that says *which* byte of the padding
    /// was wrong hands an attacker the oracle PKCS #1 v1.5 is famous for, and there is nothing an
    /// operator could do with the distinction anyway. Type 1 (a signature block) is refused rather
    /// than unwrapped — a signature fed in as an encrypted key must not produce a plaintext.
    pub fn decrypt_pkcs1_v15(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DerError> {
        let k = self.public.n.len();
        let c = left_pad(ciphertext, k)?;
        if !less(&c, &self.public.n) {
            return Err(DerError(
                "the encrypted key is not below the modulus".into(),
            ));
        }
        let m = modpow(&c, &self.d, &self.public.n)
            .ok_or_else(|| DerError("RSA decryption failed".into()))?;
        // `modpow` may drop leading zero octets; the block is exactly k long.
        let mut em = vec![0; k - m.len().min(k)];
        em.extend_from_slice(&m[m.len().saturating_sub(k)..]);
        unpkcs1(&em)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A 2048-bit key made by `openssl genrsa` for these tests.
    pub const TEST_KEY_PEM: &str = include_str!("testdata/rsa2048.pem");

    pub fn test_key() -> PrivateKey {
        let blocks = super::super::pem::blocks(TEST_KEY_PEM.as_bytes()).unwrap();
        PrivateKey::from_der(&blocks[0].1).unwrap()
    }

    #[test]
    fn signatures_round_trip_and_bind_digest_and_hash() {
        let key = test_key();
        let d = Hash::Sha256.digest(b"message");
        let sig = key.sign(Hash::Sha256, &d).unwrap();
        assert!(key.public().verify(Hash::Sha256, &d, &sig));
        assert!(
            !key.public()
                .verify(Hash::Sha256, &Hash::Sha256.digest(b"other"), &sig)
        );
        assert!(
            !key.public()
                .verify(Hash::Sha512, &Hash::Sha512.digest(b"message"), &sig)
        );
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!key.public().verify(Hash::Sha256, &d, &bad));
        assert!(!key.public().verify(Hash::Sha256, &d, &sig[1..]));
    }

    #[test]
    fn a_signature_without_null_parameters_also_verifies() {
        // RFC 8017 §8.2.2 note 2: some signers omit the NULL.
        let key = test_key();
        let d = Hash::Sha384.digest(b"m");
        let em = emsa(Hash::Sha384, &d, key.public.n.len(), false).unwrap();
        let sig = modpow(&em, &key.d, &key.public.n).unwrap();
        assert!(key.public().verify(Hash::Sha384, &d, &sig));
    }

    #[test]
    fn a_forged_low_exponent_signature_is_refused() {
        // Garbage after the DigestInfo, which a lenient parser of the
        // padding would skip: the whole-block comparison does not.
        let key = test_key();
        let d = Hash::Sha256.digest(b"m");
        let mut em = emsa(Hash::Sha256, &d, key.public.n.len(), true).unwrap();
        let k = em.len();
        em.copy_within(11.., 10);
        em[k - 1] = 0x42;
        let sig = modpow(&em, &key.d, &key.public.n).unwrap();
        assert!(!key.public().verify(Hash::Sha256, &d, &sig));
    }

    #[test]
    fn a_block_with_the_right_digest_and_anything_else_wrong_is_refused() {
        // Each block ends in the right digest, so a verifier that looked
        // only at the digest would take it.
        let key = test_key();
        let d = Hash::Sha256.digest(b"m");
        let good = emsa(Hash::Sha256, &d, key.public.n.len(), true).unwrap();
        let info_at = good.len() - 51; // DigestInfo for SHA-256 with NULL: 51 octets
        for (what, at, v) in [
            ("block type", 1, 2),
            ("padding octet", 5, 0xFE),
            ("separator", info_at - 1, 0xFF),
            ("hash OID", info_at + 14, 0x02), // ...4.2.1 -> ...4.2.2
        ] {
            let mut em = good.clone();
            em[at] = v;
            let sig = modpow(&em, &key.d, &key.public.n).unwrap();
            assert!(!key.public().verify(Hash::Sha256, &d, &sig), "{what}");
        }
        let sig = modpow(&good, &key.d, &key.public.n).unwrap();
        assert!(key.public().verify(Hash::Sha256, &d, &sig));
    }

    #[test]
    fn weak_public_keys_are_refused() {
        let small = der::seq(&[asn1::uint(&[0xC3; 128]), asn1::uint(&[1, 0, 1])]);
        assert!(PublicKey::from_der(&small).is_err());
        let even_e = der::seq(&[asn1::uint(&[0xC3; 256]), asn1::uint(&[2])]);
        assert!(PublicKey::from_der(&even_e).is_err());
        let ok = der::seq(&[asn1::uint(&[0xC3; 256]), asn1::uint(&[1, 0, 1])]);
        assert!(PublicKey::from_der(&ok).is_ok());
    }
}
