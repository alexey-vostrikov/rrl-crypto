//! The signature keys PKINIT certificates carry, RSA or elliptic-curve,
//! and the algorithms they sign with.

use super::asn1::{self, ReaderExt};
use super::ec;
use super::rsa;
use crate::der::{DerError, Reader};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

type Result<T> = std::result::Result<T, DerError>;

/// `sha1WithRSAEncryption`: accepted for verification, never offered.
const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";

/// The digests a signature may use. SHA-1 is not among them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-1 (RFC 3370). **Verification only**: Heimdal's KDC signs its PKINIT replies with it and
    /// its `supportedCMSTypes` handling does not always take the client's preference. Nothing in
    /// this crate signs with SHA-1 — [`SigAlg::ALL`], the list a client offers, has no SHA-1 entry.
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn oid(self) -> &'static str {
        match self {
            Hash::Sha1 => "1.3.14.3.2.26",
            Hash::Sha256 => "2.16.840.1.101.3.4.2.1",
            Hash::Sha384 => "2.16.840.1.101.3.4.2.2",
            Hash::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub fn from_oid(oid: &[u8]) -> Option<Hash> {
        [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512]
            .into_iter()
            .find(|h| asn1::oid(h.oid()) == oid)
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// A signature algorithm: PKCS #1 v1.5 RSA or ECDSA, with a hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    Rsa(Hash),
    Ecdsa(Hash),
}

impl SigAlg {
    /// Every one accepted, strongest first: MIT 1.22's supportedCMSTypes.
    pub const ALL: [SigAlg; 6] = [
        SigAlg::Ecdsa(Hash::Sha512),
        SigAlg::Ecdsa(Hash::Sha384),
        SigAlg::Ecdsa(Hash::Sha256),
        SigAlg::Rsa(Hash::Sha512),
        SigAlg::Rsa(Hash::Sha384),
        SigAlg::Rsa(Hash::Sha256),
    ];

    pub fn oid(self) -> &'static str {
        match self {
            SigAlg::Rsa(Hash::Sha1) => SHA1_WITH_RSA,
            SigAlg::Rsa(Hash::Sha256) => SHA256_WITH_RSA,
            SigAlg::Rsa(Hash::Sha384) => SHA384_WITH_RSA,
            SigAlg::Rsa(Hash::Sha512) => SHA512_WITH_RSA,
            SigAlg::Ecdsa(Hash::Sha256) => ECDSA_WITH_SHA256,
            SigAlg::Ecdsa(Hash::Sha384) => ECDSA_WITH_SHA384,
            SigAlg::Ecdsa(Hash::Sha512) => ECDSA_WITH_SHA512,
            // No ECDSA-with-SHA-1 exists in PKINIT practice, and nothing here produces one.
            SigAlg::Ecdsa(Hash::Sha1) => ECDSA_WITH_SHA256,
        }
    }

    /// The algorithm an OID names, for **verification**. SHA-1 is here and not in [`SigAlg::ALL`]:
    /// it is accepted from a peer whose KDC still signs with it (Heimdal 7.8 does), and never
    /// offered — a client of this crate cannot be made to sign with SHA-1 through this type.
    pub fn from_oid(oid: &[u8]) -> Option<SigAlg> {
        if oid == asn1::oid(SHA1_WITH_RSA) {
            return Some(SigAlg::Rsa(Hash::Sha1));
        }
        SigAlg::ALL.into_iter().find(|a| asn1::oid(a.oid()) == oid)
    }

    pub fn hash(self) -> Hash {
        match self {
            SigAlg::Rsa(h) | SigAlg::Ecdsa(h) => h,
        }
    }

    /// The AlgorithmIdentifier: NULL parameters for RSA (RFC 4055), none
    /// for ECDSA (RFC 5758 §3.2).
    pub fn alg_id(self) -> Vec<u8> {
        match self {
            SigAlg::Rsa(_) => asn1::alg_id(self.oid(), Some(asn1::null())),
            SigAlg::Ecdsa(_) => asn1::alg_id(self.oid(), None),
        }
    }
}

/// A certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Rsa(rsa::PublicKey),
    Ec(ec::PublicKey),
}

impl PublicKey {
    /// From a SubjectPublicKeyInfo's algorithm, its parameters and the
    /// BIT STRING's content.
    pub fn from_spki(alg: &[u8], params: Option<&[u8]>, key: &[u8]) -> Result<PublicKey> {
        if alg == asn1::oid(rsa::RSA_ENCRYPTION) {
            Ok(PublicKey::Rsa(rsa::PublicKey::from_der(key)?))
        } else if alg == asn1::oid(ec::ID_EC_PUBLIC_KEY) {
            let curve = ec::Curve::from_params(params)?;
            Ok(PublicKey::Ec(ec::PublicKey::from_point(curve, key)?))
        } else {
            Err(DerError(
                "unsupported public key algorithm (only RSA and EC)".into(),
            ))
        }
    }

    /// Whether `sig` is this key's signature by `alg` over `digest` (made
    /// with `alg`'s hash). A key of the other kind never verifies.
    pub fn verify(&self, alg: SigAlg, digest: &[u8], sig: &[u8]) -> bool {
        match (self, alg) {
            (PublicKey::Rsa(k), SigAlg::Rsa(h)) => k.verify(h, digest, sig),
            (PublicKey::Ec(k), SigAlg::Ecdsa(_)) => k.verify(digest, sig),
            _ => false,
        }
    }
}

/// A client's private key.
#[derive(Debug, Clone)]
pub enum PrivateKey {
    Rsa(rsa::PrivateKey),
    Ec(ec::PrivateKey),
}

/// The key a `PrivateKeyInfo` names, by the algorithm in its header.
///
/// An RSA key is handed the whole `der` rather than its inner octets: `rsa::PrivateKey::from_der`
/// reads either shape, and passing the wrapper is what makes the two entry points one parser.
fn key_of(alg: &[u8], params: Option<&[u8]>, s: &mut Reader<'_>, der: &[u8]) -> Result<PrivateKey> {
    if alg == asn1::oid(rsa::RSA_ENCRYPTION) {
        return Ok(PrivateKey::Rsa(rsa::PrivateKey::from_der(der)?));
    }
    if alg == asn1::oid(ec::ID_EC_PUBLIC_KEY) {
        let curve = ec::Curve::from_params(params)?;
        return Ok(PrivateKey::Ec(ec::PrivateKey::from_sec1(
            s.octets()?,
            Some(curve),
        )?));
    }
    Err(DerError(
        "unsupported private key algorithm (only RSA and EC)".into(),
    ))
}

impl PrivateKey {
    /// The key as an RSA key, when it is one: RSA key transport needs a modulus to be encrypted
    /// to, and an EC key cannot receive it.
    pub fn rsa(&self) -> Option<rsa::PrivateKey> {
        match self {
            PrivateKey::Rsa(k) => Some(k.clone()),
            PrivateKey::Ec(_) => None,
        }
    }

    /// The first private key among PEM blocks: PKCS #8 `PRIVATE KEY`
    /// (RSA or EC), `RSA PRIVATE KEY` (PKCS #1) or `EC PRIVATE KEY`
    /// (SEC1), unencrypted.
    pub fn from_pem_blocks(blocks: &[(String, Vec<u8>)]) -> Result<PrivateKey> {
        Self::from_pem_blocks_with_password(blocks, None)
    }

    /// The first private key among PEM blocks, encrypted or not.
    ///
    /// `ENCRYPTED PRIVATE KEY` is the `EncryptedPrivateKeyInfo` of PKCS #8 - what
    /// `openssl genpkey -aes-256-cbc` writes and what a service's mTLS identity usually is. A block
    /// of that shape without a password is refused by name rather than skipped: a caller that
    /// forgot the password has a key it cannot use, and "no unencrypted key found" would send it
    /// looking for a different file.
    pub fn from_pem_blocks_with_password(
        blocks: &[(String, Vec<u8>)],
        password: Option<&str>,
    ) -> Result<PrivateKey> {
        for (label, der) in blocks {
            match label.as_str() {
                "RSA PRIVATE KEY" => return Ok(PrivateKey::Rsa(rsa::PrivateKey::from_der(der)?)),
                "EC PRIVATE KEY" => {
                    return Ok(PrivateKey::Ec(ec::PrivateKey::from_sec1(der, None)?));
                }
                "PRIVATE KEY" => return Self::from_der_pkcs8(der),
                "ENCRYPTED PRIVATE KEY" => {
                    let password = password.ok_or_else(|| {
                        DerError(
                            "an encrypted private key was found and no password was given".into(),
                        )
                    })?;
                    let plain = super::pkcs12::decrypt_private_key_info(der, password)
                        .map_err(|err| DerError(format!("encrypted private key: {err}")))?;
                    return Self::from_der_pkcs8(&plain);
                }
                _ => {}
            }
        }
        Err(DerError(
            "no RSA or EC private key found in the PEM blocks".into(),
        ))
    }

    /// `PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier,
    /// privateKey OCTET STRING, ... }`, from memory.
    ///
    /// The same bytes `PRIVATE KEY` carries: a caller that has the DER - from a PKCS #12 key bag, a
    /// decrypted `ENCRYPTED PRIVATE KEY`, or a secret store that keeps DER and not PEM - does not
    /// have to wrap it in a PEM envelope to be read here.
    pub fn from_der_pkcs8(der: &[u8]) -> Result<PrivateKey> {
        let mut r = Reader::new(der);
        let mut s = r.seq()?;
        r.done("PrivateKeyInfo")?;
        s.int()?; // version
        let (alg, params) = s.alg_id()?;
        key_of(alg, params, &mut s, der)
    }

    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(k) => PublicKey::Rsa(k.public().clone()),
            PrivateKey::Ec(k) => PublicKey::Ec(k.public().clone()),
        }
    }

    /// What MIT's client signs with: SHA-256, with RSA or ECDSA as the
    /// key is.
    pub fn sig_alg(&self) -> SigAlg {
        match self {
            PrivateKey::Rsa(_) => SigAlg::Rsa(Hash::Sha256),
            PrivateKey::Ec(_) => SigAlg::Ecdsa(Hash::Sha256),
        }
    }

    /// The signature over `digest`, made with [`PrivateKey::sig_alg`]'s hash.
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Rsa(k) => k.sign(Hash::Sha256, digest),
            PrivateKey::Ec(k) => k.sign(digest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs::pem;

    fn key(pem_text: &[u8]) -> PrivateKey {
        PrivateKey::from_pem_blocks(&pem::blocks(pem_text).unwrap()).unwrap()
    }

    /// A signature verifies only under an algorithm of its key's kind:
    /// certificate signatures get no leeway on the label.
    #[test]
    fn keys_verify_only_their_own_kind_of_signature() {
        let ec = key(include_bytes!("testdata/ec-kdc-key.pem"));
        let rsa = key(include_bytes!("testdata/kdc-key.pem"));
        let d = Hash::Sha256.digest(b"m");
        let (ec_sig, rsa_sig) = (ec.sign(&d).unwrap(), rsa.sign(&d).unwrap());
        assert!(ec.public().verify(SigAlg::Ecdsa(Hash::Sha256), &d, &ec_sig));
        assert!(!ec.public().verify(SigAlg::Rsa(Hash::Sha256), &d, &ec_sig));
        assert!(rsa.public().verify(SigAlg::Rsa(Hash::Sha256), &d, &rsa_sig));
        assert!(
            !rsa.public()
                .verify(SigAlg::Ecdsa(Hash::Sha256), &d, &rsa_sig)
        );
        assert_eq!(ec.sig_alg(), SigAlg::Ecdsa(Hash::Sha256));
        assert_eq!(rsa.sig_alg(), SigAlg::Rsa(Hash::Sha256));
    }

    #[test]
    fn signature_algorithms_round_trip_their_oids() {
        for a in SigAlg::ALL {
            assert_eq!(SigAlg::from_oid(&asn1::oid(a.oid())), Some(a));
        }
        // RFC 5758: no parameters for ECDSA; RFC 4055: NULL for RSA.
        assert!(!SigAlg::Ecdsa(Hash::Sha256).alg_id().ends_with(&[5, 0]));
        assert!(SigAlg::Rsa(Hash::Sha256).alg_id().ends_with(&[5, 0]));
    }

    /// Every label a PEM file may put a key under, and what happens to the ones that carry none.
    ///
    /// `from_pem_blocks` walks the blocks in order and takes the first that holds an unencrypted
    /// key: a file holding a certificate and a key is the normal shape of what `openssl pkcs12`
    /// writes, so skipping a block is the common path rather than an edge case — and it was the one
    /// no test entered.
    #[test]
    fn every_label_a_pem_file_uses_is_read_and_others_are_skipped() {
        // PKCS #8, which is what `openssl genrsa` writes today: "PRIVATE KEY".
        let pkcs8 = pem::blocks(include_bytes!("testdata/kdc-key.pem")).unwrap();
        assert_eq!(pkcs8[0].0, "PRIVATE KEY");
        assert!(matches!(
            PrivateKey::from_pem_blocks(&pkcs8).unwrap(),
            PrivateKey::Rsa(_)
        ));

        // SEC 1 EC key, "EC PRIVATE KEY", whose curve is inside rather than beside it.
        let sec1 = pem::blocks(include_bytes!("testdata/ec-kdc-key.pem")).unwrap();
        assert_eq!(sec1[0].0, "EC PRIVATE KEY");
        assert!(matches!(
            PrivateKey::from_pem_blocks(&sec1).unwrap(),
            PrivateKey::Ec(_)
        ));

        // A certificate first, then the key: the certificate is skipped, not refused.
        let mut mixed = vec![("CERTIFICATE".to_string(), vec![0x30, 0x00])];
        mixed.extend(pkcs8.clone());
        assert!(matches!(
            PrivateKey::from_pem_blocks(&mixed).unwrap(),
            PrivateKey::Rsa(_)
        ));

        // Nothing that holds a key.
        let none = vec![("CERTIFICATE".to_string(), vec![0x30, 0x00])];
        let e = PrivateKey::from_pem_blocks(&none).unwrap_err();
        assert!(e.0.contains("no RSA or EC private key found"), "{e}");
        assert!(
            PrivateKey::from_pem_blocks(&[]).is_err(),
            "an empty file holds none"
        );
    }

    /// The format `openssl genpkey -aes-256-cbc -pass pass:…` writes, which is what an mTLS
    /// deployment hands a service and what nothing here could read before.
    ///
    /// The fixture's unencrypted twin was made from the same key, so the two readers have to agree
    /// on the key they produce: what is compared is a signature, because two keys that verify for
    /// each other's signatures are the same pair, and the modulus is private to this module.
    #[test]
    fn an_encrypted_pkcs8_key_opens_with_its_password() {
        let blocks = pem::blocks(include_bytes!("testdata/encrypted-pkcs8.pem")).unwrap();
        assert_eq!(blocks[0].0, "ENCRYPTED PRIVATE KEY");

        let opened = PrivateKey::from_pem_blocks_with_password(&blocks, Some("rrl-stand")).unwrap();
        let twin = key(include_bytes!("testdata/plain-twin-pkcs8.pem"));

        let digest = Hash::Sha256.digest(b"encrypted pkcs8");
        let sig = opened.sign(&digest).unwrap();
        assert!(
            twin.public()
                .verify(SigAlg::Rsa(Hash::Sha256), &digest, &sig),
            "the encrypted key and its twin are the same key"
        );
        let back = twin.sign(&digest).unwrap();
        assert!(
            opened
                .public()
                .verify(SigAlg::Rsa(Hash::Sha256), &digest, &back),
            "and in the other direction"
        );
    }

    /// A wrong password is a refusal a caller can print, not a panic and not a key of the wrong
    /// shape: PBES2 authenticates nothing, so the message names both possibilities honestly.
    #[test]
    fn a_wrong_password_is_refused_by_name() {
        let blocks = pem::blocks(include_bytes!("testdata/encrypted-pkcs8.pem")).unwrap();
        let err = PrivateKey::from_pem_blocks_with_password(&blocks, Some("not-the-password"))
            .expect_err("a wrong password cannot open the key");
        assert!(err.0.contains("cannot decrypt"), "{err}");
        assert!(err.0.contains("password is wrong"), "{err}");
    }

    /// Without a password the block is named, not skipped: "no key found" would send a caller
    /// looking for a different file than the one it has.
    #[test]
    fn an_encrypted_key_without_a_password_says_so() {
        let blocks = pem::blocks(include_bytes!("testdata/encrypted-pkcs8.pem")).unwrap();
        let err = PrivateKey::from_pem_blocks(&blocks).expect_err("no password, no key");
        assert!(err.0.contains("encrypted private key was found"), "{err}");
    }

    /// A consumer that keeps DER - a secret store, a PKCS #12 bag, a decrypted envelope - reads the
    /// key without building a PEM envelope around it first.
    #[test]
    fn pkcs8_is_read_from_der_without_a_pem_envelope() {
        let blocks = pem::blocks(include_bytes!("testdata/plain-twin-pkcs8.pem")).unwrap();
        let from_der = PrivateKey::from_der_pkcs8(&blocks[0].1).unwrap();
        let from_pem = PrivateKey::from_pem_blocks(&blocks).unwrap();

        let digest = Hash::Sha256.digest(b"der entry");
        let sig = from_der.sign(&digest).unwrap();
        assert!(
            from_pem
                .public()
                .verify(SigAlg::Rsa(Hash::Sha256), &digest, &sig)
        );
    }
}
