//! The cryptography of RRL, in one place.
//!
//! `rrl` is a Kerberos KDC that speaks LDAP and SMB, and all three need cryptography that
//! interoperates with someone else's implementation: a KDC has to agree with every client, a
//! directory with every LDAP client, an SMB server with Windows. The rule for what belongs here
//! is therefore *who needs it*, not which RFC it is written in — one copy of each construction,
//! consumed by everything in the project.
//!
//! The primitives are RustCrypto's; what this crate adds is the constructions:
//!
//! * Kerberos (`kdf`, `nfold`, `aes_cts`, `profile`) — DR/DK, n-fold, the string-to-key
//!   constructions with their salts and iteration counts, AES in CBC-CS3, the RFC 3961 §5.3
//!   profile, and the key-usage numbering that decides which derived key encrypts and which
//!   authenticates;
//! * `checksum` — the keyed checksums a protocol names by number, starting with
//!   `KERB_CHECKSUM_HMAC_MD5`, which the PAC and S4U both need and which used to exist twice.
//!
//! No sockets, no clocks, no caches, no `chrono`: the crates that consume this one are sans-io and
//! must stay that way.
//!
//! # One line of RustCrypto, deliberately
//!
//! A project that pulls `aes` once through one dependency and once through another ends up with
//! two of them linked into the same binary. That is not a size problem — it is an audit problem:
//! a fix has to reach every line, and nothing fails when it reaches only one. This crate and the
//! SMB server that consumes it therefore sit on the same versions of `aes`, `hmac`, `sha2`,
//! `digest` and `cipher`, and a test asserts the tree carries one of each.
//!
//! # Two backends
//!
//! [`OwnCipher`] is this crate's implementation. The `crypto-rskrb5` feature adds a second one
//! over `rskrb5::crypto`, a third-party implementation of the same RFCs. Every known-answer
//! vector runs against both, so a disagreement is caught by `cargo test` rather than by a client
//! that cannot log in. That differential run is the reason the backend is a trait: one table, two
//! implementations, and a third party (MIT's published answers) as the referee.
//!
//! # What is checked against what
//!
//! `tests/` carries MIT's `crypto_tests` answers for enctypes 17-20 and Heimdal's `n-fold`,
//! `derived-key` and `aes` vectors. A format proved only by its own output is not proved, so the
//! tables are external and the differential run is how they are used.

pub mod aes_cts;
pub mod checksum;
pub mod error;
pub mod kdf;
pub mod nfold;
pub mod nt;
pub mod profile;
pub mod rc4; // rc4-hmac (enctype 23), RFC 4757: the one envelope that is not RFC 3961's

#[cfg(feature = "crypto-rskrb5")]
pub mod rskrb5_backend;

pub use error::{Error, Result};

use std::sync::Arc;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub use kdf::{KeyUse, Sha2Kind, dk, dr, kdf_hmac_sha2, s2k, usage, usage_constant};

/// The AES block size, and the length of every Kerberos confounder.
pub const AES_BLOCK: usize = 16;

/// `aes{128,256}-cts-hmac-{sha1-96,sha256-128,sha384-192}`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
/// The four AES enctypes this crate implements.
pub enum Enctype {
    /// `aes128-cts-hmac-sha1-96` (RFC 3962).
    Aes128Sha1 = 17,
    /// `aes256-cts-hmac-sha1-96` (RFC 3962).
    Aes256Sha1 = 18,
    /// `aes128-cts-hmac-sha256-128` (RFC 8009).
    Aes128Sha256 = 19,
    /// `aes256-cts-hmac-sha384-192` (RFC 8009).
    Aes256Sha384 = 20,
    /// `rc4-hmac` (RFC 4757): weak, and needed to accept a key or a ticket that carries it.
    ///
    /// Not in [`Enctype::ALL`], so a realm never offers it unless its configuration says so. Its
    /// envelope is not RFC 3961's — see [`crate::rc4`].
    Rc4Hmac = 23,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Enctype {
    /// The RFC 3961 number, as it appears on the wire and in every `krb5.conf`.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_i32(self.id())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Enctype {
    /// Refuses a number this KDC does not implement, rather than defaulting to
    /// one: a request asking for an enctype the caller could not have meant is a
    /// mistake worth reporting.
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let id = i32::deserialize(deserializer)?;
        Enctype::from_id(id).ok_or_else(|| {
            serde::de::Error::custom(format!("enctype {id} is not one this KDC implements"))
        })
    }
}

impl Enctype {
    /// Strongest first: the order a KDC offers them in, and the order an
    /// `allowed_enctypes` list is matched in.
    pub const ALL: [Enctype; 4] = [
        Enctype::Aes256Sha384,
        Enctype::Aes256Sha1,
        Enctype::Aes128Sha256,
        Enctype::Aes128Sha1,
    ];

    /// The enctype with this RFC 3961 number, if it is one of the four.
    pub fn from_id(id: i32) -> Option<Self> {
        match id {
            17 => Some(Enctype::Aes128Sha1),
            18 => Some(Enctype::Aes256Sha1),
            19 => Some(Enctype::Aes128Sha256),
            20 => Some(Enctype::Aes256Sha384),
            23 => Some(Enctype::Rc4Hmac),
            _ => None,
        }
    }

    /// The name Heimdal and MIT print, and the one `krb5.conf` lists.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "aes128-cts-hmac-sha1-96" | "aes128-sha1" | "aes-128" => Some(Enctype::Aes128Sha1),
            "aes256-cts-hmac-sha1-96" | "aes256-sha1" | "aes-256" => Some(Enctype::Aes256Sha1),
            "aes128-cts-hmac-sha256-128" | "aes128-sha2" => Some(Enctype::Aes128Sha256),
            "aes256-cts-hmac-sha384-192" | "aes256-sha2" => Some(Enctype::Aes256Sha384),
            // Heimdal's alias and MIT's, both of which appear in real `krb5.conf` files.
            "rc4-hmac" | "arcfour-hmac" | "arcfour-hmac-md5" | "rc4-hmac-md5" => {
                Some(Enctype::Rc4Hmac)
            }
            _ => None,
        }
    }

    /// The RFC 3961 enctype number, as it appears on the wire.
    pub fn id(self) -> i32 {
        self as i32
    }

    /// The name Heimdal, MIT and `krb5.conf` use.
    pub fn name(self) -> &'static str {
        match self {
            Enctype::Aes128Sha1 => "aes128-cts-hmac-sha1-96",
            Enctype::Aes256Sha1 => "aes256-cts-hmac-sha1-96",
            Enctype::Aes128Sha256 => "aes128-cts-hmac-sha256-128",
            Enctype::Aes256Sha384 => "aes256-cts-hmac-sha384-192",
            Enctype::Rc4Hmac => "rc4-hmac",
        }
    }

    /// The length of the protocol key `Ke`.
    pub fn key_len(self) -> usize {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes128Sha256 => 16,
            Enctype::Aes256Sha1 | Enctype::Aes256Sha384 => 32,
            Enctype::Rc4Hmac => 16,
        }
    }

    /// The confounder is one cipher block for every enctype (RFC 3961 §5.3,
    /// RFC 8009 §5).
    /// The confounder length: one cipher block for every enctype.
    pub fn confounder_len(self) -> usize {
        match self {
            // Eight octets, not a cipher block: RC4 has no block, and RFC 4757 §7.2 fixes eight.
            Enctype::Rc4Hmac => crate::rc4::CONFOUNDER_LEN,
            _ => AES_BLOCK,
        }
    }

    /// Truncated MAC length (RFC 3962 §6, RFC 8009 §6).
    pub fn mac_len(self) -> usize {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => 12,
            Enctype::Aes128Sha256 => 16,
            Enctype::Aes256Sha384 => 24,
            Enctype::Rc4Hmac => 16,
        }
    }

    /// The size of the derived integrity key `Ki`.
    ///
    /// RFC 3962 §5.3 sizes it exactly like the protocol key. RFC 8009 §5 gives
    /// `aes256-cts-hmac-sha384-192` a **192-bit** `Ki` and `Kc` against a
    /// 256-bit `Ke`, so for that enctype the integrity key is 24 octets, not
    /// 32. Deriving 32 and truncating the MAC instead produces a tag no peer
    /// agrees with — MIT's `crypto_tests` catches exactly this.
    pub fn integrity_key_len(self) -> usize {
        match self {
            Enctype::Aes256Sha384 => 24,
            other => other.key_len(),
        }
    }

    /// Whether this enctype's envelope is RFC 4757's rather than RFC 3961's.
    ///
    /// One enctype, and the distinction has to be visible: the offsets differ, the tag comes first,
    /// and the usage number is mapped before it is used.
    pub fn is_rc4(self) -> bool {
        matches!(self, Enctype::Rc4Hmac)
    }

    /// The size of the derived checksum key `Kc` (RFC 3962 §5.3, RFC 8009 §5).
    /// The enctype for a wire number, or an error naming the number.
    ///
    /// [`Enctype::from_id`] answers `Option`, which is the right shape inside this crate. This is
    /// the shape a caller that has just read the number off the wire wants: the number belongs in
    /// the message it produces.
    pub fn from_i32(id: i32) -> Result<Self> {
        Enctype::from_id(id).ok_or(Error::UnsupportedEnctype(id))
    }

    /// The wire enctype number. Same as [`Enctype::id`], under the name MIT and Heimdal use.
    pub fn etype(self) -> i32 {
        self.id()
    }

    /// The wire enctype number, for a caller that spells it `as_i32`.
    pub fn as_i32(self) -> i32 {
        self.id()
    }

    /// The long-term key size in octets. Same as [`Enctype::key_len`], under the name the
    /// reference implementations use for the key a keytab stores.
    pub fn key_size(self) -> usize {
        self.key_len()
    }

    /// `Ke` — the encryption key length (RFC 3961 §5.3). Same as [`Enctype::key_len`], under the
    /// name the RFC and both reference implementations use.
    pub fn ke_len(self) -> usize {
        self.key_len()
    }

    /// `Ki` — the integrity key length (RFC 3961 §5.3).
    pub fn ki_len(self) -> usize {
        self.integrity_key_len()
    }

    /// `Kc` — the checksum key length (RFC 3961 §5.3).
    pub fn kc_len(self) -> usize {
        self.checksum_key_len()
    }

    /// Whether this enctype uses the RFC 8009 profile, where the MAC covers `IV | C`.
    pub fn is_rfc8009(self) -> bool {
        self.sha2_kind().is_some()
    }

    /// What the profile adds to a plaintext: the confounder and the MAC.
    pub fn overhead(self) -> usize {
        self.confounder_len() + self.mac_len()
    }

    pub fn checksum_key_len(self) -> usize {
        self.integrity_key_len()
    }

    /// The keyed checksum type that goes with this enctype.
    pub fn checksum_type(self) -> i32 {
        match self {
            Enctype::Aes128Sha1 => 15,   // hmac-sha1-96-aes128
            Enctype::Aes256Sha1 => 16,   // hmac-sha1-96-aes256
            Enctype::Aes128Sha256 => 19, // hmac-sha256-128-aes128
            Enctype::Aes256Sha384 => 20, // hmac-sha384-192-aes256
            // `hmac-md5-rc4`: negative, and that is the number on the wire.
            Enctype::Rc4Hmac => crate::rc4::CHECKSUM_TYPE,
        }
    }

    /// `None` for RFC 3962 (SHA-1), the hash family for RFC 8009.
    pub fn sha2_kind(self) -> Option<Sha2Kind> {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => None,
            Enctype::Aes128Sha256 => Some(Sha2Kind::Sha256),
            Enctype::Aes256Sha384 => Some(Sha2Kind::Sha384),
            // Neither family: RFC 4757 predates both, and its profile is its own.
            Enctype::Rc4Hmac => None,
        }
    }

    /// The default `s2kparams` iteration count (RFC 3962 §A.2, RFC 8009 §4).
    pub fn default_iterations(self) -> u32 {
        match self.sha2_kind() {
            None => kdf::DEFAULT_ITERATIONS_SHA1,
            Some(_) => kdf::DEFAULT_ITERATIONS_SHA2,
        }
    }

    /// Parses an `allowed_enctypes`-style list. Unknown names are refused: a
    /// configuration that names `rc4-hmac` and is silently given AES instead
    /// is worse than one that fails at startup.
    pub fn parse_list(names: &[&str]) -> Result<Vec<Enctype>> {
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            // A name first, as `krb5.conf` writes it, then a number: the RFC 3961
            // number appears in `klist -e` output and in documentation, and an
            // operator pasting `18` should get the enctype rather than a message
            // claiming 18 is not implemented.
            let parsed = Enctype::from_name(n)
                .or_else(|| n.trim().parse::<i32>().ok().and_then(Enctype::from_id));
            match parsed {
                Some(e) if !out.contains(&e) => out.push(e),
                Some(_) => {}
                None => {
                    return Err(Error::Config(format!(
                        "enctype {n:?} is not one this KDC implements; it issues {} (RFC 3962 and RFC 8009 only)",
                        Enctype::ALL
                            .iter()
                            .map(|e| e.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
        }
        Ok(out)
    }
}

/// A Kerberos key of a known enctype.
///
/// Bytes are zeroized on drop: a KDC holds the `krbtgt` key, and that key is
/// the realm.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
/// A Kerberos key of a known enctype.
pub struct Key {
    #[zeroize(skip)]
    enctype: Enctype,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material: this type ends up in logs the moment a
        // struct containing it derives Debug.
        write!(
            f,
            "Key({}, {} octets)",
            self.enctype.name(),
            self.bytes.len()
        )
    }
}

impl Key {
    /// A key from its raw octets, which must be exactly the enctype's size.
    pub fn new(enctype: Enctype, bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.len() != enctype.key_len() {
            return Err(Error::KeyLength {
                enctype,
                want: enctype.key_len(),
                got: bytes.len(),
            });
        }
        Ok(Key { enctype, bytes })
    }

    /// The `rsa-md5` checksum (type 7) over `message`, keyed with this key.
    ///
    /// Not an RFC 3961 profile checksum: it is MD5 over the key followed by the data, which is what
    /// MIT and Heimdal compute, and it can be used with a key of any enctype. Windows sends exactly
    /// this for the body of a `TGS-REQ` even when the TGT's session key is AES, so a KDC that accepts
    /// only the enctype's own checksum refuses every service ticket from a Windows client after
    /// issuing it a perfectly good TGT.
    pub fn rsa_md5_checksum(&self, message: &[u8]) -> [u8; 16] {
        use md5::{Digest, Md5};
        let mut digest = Md5::new();
        digest.update(&self.bytes);
        digest.update(message);
        digest.finalize().into()
    }

    /// Whether `tag` is the `rsa-md5` checksum of `message` under this key.
    pub fn verify_rsa_md5_checksum(&self, message: &[u8], tag: &[u8]) -> bool {
        ct_eq(&self.rsa_md5_checksum(message), tag)
    }

    /// The enctype these octets are a key for.
    pub fn enctype(&self) -> Enctype {
        self.enctype
    }

    /// The key material.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The key length in octets.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false: a zero-length key is refused by [`Key::new`].
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The cryptographic operations a KDC performs, as a replaceable backend.
///
/// Every method takes the raw key rather than a backend-specific type, so
/// implementations share nothing but octets — which is the point: a
/// disagreement is then a disagreement about the wire, not about an API.
pub trait Cipher: std::fmt::Debug + Send + Sync {
    /// Which implementation this is, for logs and test names.
    fn name(&self) -> &'static str;

    /// A fresh random key, from the OS.
    fn random(&self, enctype: Enctype) -> Result<Key>;

    /// RFC 3962 §A / RFC 8009 §4 string-to-key.
    ///
    /// `params` is the `s2kparams` octet string from `ETYPE-INFO2`: four
    /// big-endian octets of iteration count, or `None` for the enctype default.
    fn s2k(
        &self,
        enctype: Enctype,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Key>;

    /// [`Cipher::s2k`] without the minimum-iteration refusal, for published vectors.
    ///
    /// RFC 3962 Appendix B and MIT's `crypto_tests` derive with iteration counts of 1 and 1200,
    /// so a test that compares against them cannot go through the strict path. The default
    /// forwards to [`Cipher::s2k`] — a backend that has no separate strict path is not thereby
    /// weakened, it simply never refused.
    fn s2k_allow_weak(
        &self,
        enctype: Enctype,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Key> {
        self.s2k(enctype, password, salt, params)
    }

    /// The usage-specific key (DR/DK for 17/18, KDF-HMAC-SHA2 for 19/20).
    fn derive_key(
        &self,
        enctype: Enctype,
        base: &[u8],
        usage: u32,
        use_: KeyUse,
    ) -> Result<Vec<u8>>;

    /// Encrypt with a fresh random confounder.
    fn encrypt(&self, key: &Key, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Encrypt with a caller-supplied confounder — for known-answer vectors
    /// and deterministic tests. Never use it in production code: a repeated
    /// confounder under the same key breaks the profile's security.
    fn encrypt_with_confounder(
        &self,
        key: &Key,
        usage: u32,
        plaintext: &[u8],
        confounder: &[u8],
    ) -> Result<Vec<u8>>;

    /// Decrypt and verify in one call; nothing is returned unless the tag
    /// checks out.
    fn decrypt(&self, key: &Key, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Keyed checksum (RFC 3961 §5.3, RFC 8009 §6).
    fn checksum(&self, key: &Key, usage: u32, data: &[u8]) -> Result<Vec<u8>>;

    /// Check a keyed checksum in constant time.
    fn verify_checksum(&self, key: &Key, usage: u32, data: &[u8], tag: &[u8]) -> Result<()> {
        let expected = self.checksum(key, usage, data)?;
        if ct_eq(&expected, tag) {
            Ok(())
        } else {
            Err(Error::Crypto("checksum mismatch".into()))
        }
    }
}

/// This crate's implementation of [`Cipher`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnCipher;

impl OwnCipher {
    /// The backend, boxed for handing to a KDC.
    pub fn backend() -> Arc<dyn Cipher> {
        Arc::new(OwnCipher)
    }
}

impl Cipher for OwnCipher {
    fn name(&self) -> &'static str {
        "own"
    }

    fn random(&self, enctype: Enctype) -> Result<Key> {
        let mut bytes = vec![0u8; enctype.key_len()];
        getrandom::fill(&mut bytes).map_err(|e| Error::crypto(format!("getrandom: {e}")))?;
        Key::new(enctype, bytes)
    }

    fn s2k(
        &self,
        enctype: Enctype,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Key> {
        if enctype.is_rc4() {
            // No iteration count: RFC 4757 §3 hashes the password in UTF-16LE under the principal,
            // and a `s2kparams` value there means the caller expected a different enctype.
            if let Some(params) = params
                && !params.is_empty()
            {
                return Err(Error::Config(
                    "rc4-hmac has no string-to-key parameters: its key is a single HMAC".into(),
                ));
            }
            return Key::new(enctype, rc4::string_to_key(password, salt));
        }
        Key::new(enctype, kdf::s2k(enctype, password, salt, params)?)
    }

    fn s2k_allow_weak(
        &self,
        enctype: Enctype,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Key> {
        if enctype.is_rc4() {
            // RC4 has no iteration count, so there is no weak variant to allow: the strict path is
            // the only path.
            return self.s2k(enctype, password, salt, params);
        }
        Key::new(
            enctype,
            kdf::s2k_allow_weak(enctype, password, salt, params)?,
        )
    }

    fn derive_key(
        &self,
        enctype: Enctype,
        base: &[u8],
        usage: u32,
        use_: KeyUse,
    ) -> Result<Vec<u8>> {
        if enctype.is_rc4() {
            // `K1 = HMAC-MD5(key, usage_le32)`, and encryption and integrity share it: RFC 4757 has
            // one usage key where RFC 3961 has `Ke` and `Ki`.
            let _ = use_;
            return Ok(rc4::derived_key(base, usage));
        }
        kdf::derive_key(enctype, base, usage, use_)
    }

    fn encrypt(&self, key: &Key, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.enctype().is_rc4() {
            let mut confounder = vec![0u8; key.enctype().confounder_len()];
            getrandom::fill(&mut confounder)
                .map_err(|e| Error::crypto(format!("getrandom: {e}")))?;
            return rc4::encrypt(key.bytes(), usage, plaintext, &confounder);
        }
        let (ke, ki) = self.parts(key, usage)?;
        profile::encrypt(key.enctype(), &ke, &ki, plaintext)
    }

    fn encrypt_with_confounder(
        &self,
        key: &Key,
        usage: u32,
        plaintext: &[u8],
        confounder: &[u8],
    ) -> Result<Vec<u8>> {
        if key.enctype().is_rc4() {
            return rc4::encrypt(key.bytes(), usage, plaintext, confounder);
        }
        let (ke, ki) = self.parts(key, usage)?;
        profile::encrypt_with_confounder(key.enctype(), &ke, &ki, confounder, plaintext)
    }

    fn decrypt(&self, key: &Key, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if key.enctype().is_rc4() {
            return rc4::decrypt(key.bytes(), usage, ciphertext);
        }
        let (ke, ki) = self.parts(key, usage)?;
        profile::decrypt(key.enctype(), &ke, &ki, ciphertext)
    }

    fn checksum(&self, key: &Key, usage: u32, data: &[u8]) -> Result<Vec<u8>> {
        if key.enctype().is_rc4() {
            // Not a derivation: the whole checksum of this enctype is its own construction, keyed
            // with the long-term key rather than a usage-derived one.
            return Ok(rc4::checksum(key.bytes(), usage, data));
        }
        let kc = kdf::derive_key(key.enctype(), key.bytes(), usage, KeyUse::Checksum)?;
        profile::checksum(key.enctype(), &kc, data)
    }

    fn verify_checksum(&self, key: &Key, usage: u32, data: &[u8], tag: &[u8]) -> Result<()> {
        let kc = kdf::derive_key(key.enctype(), key.bytes(), usage, KeyUse::Checksum)?;
        profile::verify_checksum(key.enctype(), &kc, data, tag)
    }
}

impl OwnCipher {
    /// The `Ke`/`Ki` for `usage`, which the profile takes as arguments.
    ///
    /// Derived here rather than in the profile because that layer is also used by callers that
    /// already hold the derived keys (a TGS reply derives once and seals several structures).
    fn parts(&self, key: &Key, usage: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let e = key.enctype();
        Ok((
            kdf::derive_key(e, key.bytes(), usage, KeyUse::Encrypt)?,
            kdf::derive_key(e, key.bytes(), usage, KeyUse::Integrity)?,
        ))
    }
}

/// Constant-time equality for tags and keys.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_md5_is_keyed_the_way_a_windows_client_keys_it() {
        // Type 7 is MD5 over the key followed by the data, not a derived profile checksum. The vector
        // is computed independently (`md5("key" || "data")`), so a change to the construction - adding
        // a length, deriving a key, swapping the order - fails here rather than in a domain join.
        let key =
            Key::new(Enctype::Aes128Sha1, (0u8..16).collect::<Vec<_>>()).expect("a 16-octet key");
        assert_eq!(
            key.rsa_md5_checksum(b"data"),
            [
                0x27, 0x23, 0xa0, 0xbb, 0xc6, 0x0b, 0xf2, 0x9b, 0xf2, 0xdd, 0x30, 0xdd, 0x96, 0x23,
                0xc8, 0x04
            ]
        );
        assert!(key.verify_rsa_md5_checksum(b"data", &key.rsa_md5_checksum(b"data")));
        assert!(!key.verify_rsa_md5_checksum(b"other", &key.rsa_md5_checksum(b"data")));
    }

    #[test]
    fn enctype_table_is_self_consistent() {
        for e in Enctype::ALL {
            assert_eq!(Enctype::from_id(e.id()), Some(e));
            assert_eq!(Enctype::from_name(e.name()), Some(e));
            assert_eq!(e.key_len(), if e.id() % 2 == 0 { 32 } else { 16 });
            assert!(e.mac_len() >= 12);
        }
        // RC4 is implemented, and deliberately not in `ALL`: a realm that lists it can accept an
        // AD or Heimdal key, and a realm that does not never offers it.
        assert_eq!(Enctype::from_id(23), Some(Enctype::Rc4Hmac));
        assert!(
            !Enctype::ALL.contains(&Enctype::Rc4Hmac),
            "a weak enctype must not be in the list a realm offers by default"
        );
        assert_eq!(Enctype::Rc4Hmac.confounder_len(), 8);
        assert_eq!(Enctype::Rc4Hmac.checksum_type(), crate::rc4::CHECKSUM_TYPE);
    }

    #[test]
    fn enctype_list_refuses_what_it_cannot_issue() {
        assert_eq!(
            Enctype::parse_list(&["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"]).unwrap(),
            vec![Enctype::Aes256Sha1, Enctype::Aes128Sha1]
        );
        // Duplicates collapse; unknown names are refused, not ignored.
        assert_eq!(
            Enctype::parse_list(&["aes-256", "aes256-sha1"]).unwrap(),
            vec![Enctype::Aes256Sha1]
        );
        // RC4's three spellings all name it; des3 is still not implemented, and saying so is the
        // point of the strict parse.
        for name in ["rc4-hmac", "arcfour-hmac", "arcfour-hmac-md5"] {
            assert_eq!(
                Enctype::parse_list(&[name]).unwrap(),
                vec![Enctype::Rc4Hmac],
                "{name}"
            );
        }
        assert!(Enctype::parse_list(&["des3-cbc-sha1"]).is_err());
    }

    fn cipher() -> OwnCipher {
        OwnCipher
    }

    #[test]
    fn round_trip_all_enctypes() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let ct = c
                .encrypt(&key, usage::AS_REP_ENCPART, b"hello ticket")
                .unwrap();
            let pt = c.decrypt(&key, usage::AS_REP_ENCPART, &ct).unwrap();
            assert_eq!(pt, b"hello ticket", "{}", e.name());
        }
    }

    #[test]
    fn wrong_usage_fails_the_integrity_check() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let ct = c
                .encrypt(&key, usage::AS_REP_ENCPART, b"encrypted part")
                .unwrap();
            assert!(
                c.decrypt(&key, usage::KDC_REP_TICKET, &ct).is_err(),
                "{} accepted a foreign usage",
                e.name()
            );
        }
    }

    #[test]
    fn a_flipped_bit_is_refused() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let mut ct = c
                .encrypt(&key, usage::KDC_REP_TICKET, b"ticket body")
                .unwrap();
            let last = ct.len() - 1;
            ct[last] ^= 1;
            assert!(
                c.decrypt(&key, usage::KDC_REP_TICKET, &ct).is_err(),
                "{}",
                e.name()
            );
        }
    }

    #[test]
    fn checksums_round_trip_and_refuse_a_foreign_usage() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let tag = c
                .checksum(&key, usage::TGS_REQ_AUTH_CKSUM, b"req-body")
                .unwrap();
            assert_eq!(tag.len(), e.mac_len());
            c.verify_checksum(&key, usage::TGS_REQ_AUTH_CKSUM, b"req-body", &tag)
                .unwrap();
            assert!(
                c.verify_checksum(&key, usage::AP_REQ_AUTH_CKSUM, b"req-body", &tag)
                    .is_err()
            );
        }
    }

    #[test]
    fn key_length_is_enforced() {
        assert!(Key::new(Enctype::Aes256Sha1, vec![0u8; 16]).is_err());
        assert!(Key::new(Enctype::Aes128Sha1, vec![0u8; 32]).is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let key = Key::new(Enctype::Aes128Sha1, vec![0x41u8; 16]).unwrap();
        let printed = format!("{key:?}");
        assert!(!printed.contains("41"), "{printed}");
        assert!(printed.contains("16 octets"), "{printed}");
    }

    #[test]
    fn a_short_confounder_is_refused() {
        let c = cipher();
        let key = c.random(Enctype::Aes128Sha1).unwrap();
        assert!(c.encrypt_with_confounder(&key, 3, b"x", &[0u8; 8]).is_err());
    }

    /// Four consumers compared secrets by hand before this had a test of its own: a secure
    /// channel's credential, an SMB2 signature, an NTLM proof and a Kerberos checksum. One of the
    /// four got the length check wrong at some point, so the behaviour is pinned here rather than
    /// assumed.
    #[test]
    fn a_comparison_is_equal_only_when_every_octet_is() {
        assert!(ct_eq(b"", b""), "two empty slices hold the same nothing");
        assert!(ct_eq(b"secret", b"secret"));

        // Every position, not one: an implementation that skipped the last octet - the one a
        // length-and-prefix comparison would skip - passes a single-position test written at the
        // front.
        let a = b"the value being compared";
        for index in 0..a.len() {
            let mut b = a.to_vec();
            b[index] ^= 0x01;
            assert!(
                !ct_eq(a, &b),
                "octet {index} of {} was not compared",
                a.len()
            );
        }
    }

    /// A shorter value is not a prefix of a longer one.
    #[test]
    fn a_difference_in_length_is_a_difference() {
        assert!(!ct_eq(b"secret", b"secre"));
        assert!(!ct_eq(b"secre", b"secret"));
        assert!(
            !ct_eq(b"", b"secret"),
            "the empty value must not match a non-empty one"
        );
        assert!(!ct_eq(b"secret", b""));
        // Same prefix, same length difference, other order: a comparison that returns the result of
        // the length check without looking at the contents gets this one right by accident and the
        // one above wrong.
        assert!(!ct_eq(b"secret ", b"secret"));
    }
}
