//! Key derivation: RFC 3961 §5.1 DR/DK for enctypes 17/18, the
//! SP800-108-style KDF-HMAC-SHA2 of RFC 8009 §3 for 19/20, and string-to-key.
//!
//! These are three different functions, not variants of one:
//!
//! * **DR/DK** (17, 18) n-folds the constant to the cipher block, then
//!   encrypts it repeatedly with AES-ECB, chaining through the *plaintext*:
//!   `B1 = E(T)`, `B2 = E(B1)`, key = `k-truncate(B1 || B2 || ...)`.
//! * **KDF-HMAC-SHA2** (19, 20) is counter mode with a fixed counter of 1:
//!   `HMAC(key, 0x00000001 || label || 0x00 || k_bits)`.
//! * **string-to-key** is PBKDF2 over the password and salt, with the hash and
//!   iteration default chosen by enctype (SHA-1/4096 for 17/18, SHA-256 or
//!   SHA-384/32768 for 19/20).
//!
//! Getting the first two confused yields a key of the right length that no
//! peer agrees with, so both are pinned to published vectors: MIT's
//! `crypto_tests` (in `tests/vectors_mit.rs`) and Heimdal's
//! `derived-key-test.c` / `aes-test.c` (below).

use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384};

use super::Enctype;
use super::nfold::n_fold;
use crate::{Error, Result};

const AES_BLOCK: usize = 16;

/// RFC 3962 §A.2 default iteration count for AES-SHA1 string-to-key.
pub const DEFAULT_ITERATIONS_SHA1: u32 = 4096;

/// RFC 8009 §4 default for AES-SHA2 string-to-key.
/// RFC 8009 §4 default iteration count for AES-SHA2 string-to-key.
pub const DEFAULT_ITERATIONS_SHA2: u32 = 32_768;

/// A cap that turns a hostile or corrupt `s2kparams` into an error instead of
/// an hour of CPU in the middle of an authentication.
/// The highest iteration count this crate will compute.
pub const MAX_ITERATIONS: u32 = 10_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// Which SHA-2 family member an RFC 8009 enctype uses.
pub enum Sha2Kind {
    /// `aes128-cts-hmac-sha256-128` (enctype 19).
    Sha256,
    /// `aes256-cts-hmac-sha384-192` (enctype 20).
    Sha384,
}

impl Sha2Kind {
    /// The digest this kind produces, in bits.
    ///
    /// The KDF computes one HMAC and truncates it, so this is also the longest output it can give —
    /// RFC 3961 §5.1 caps the derived length at the hash length. Public because a caller that asks
    /// for a length needs to know the ceiling before it asks, rather than read it out of an error.
    pub const fn output_bits(self) -> u32 {
        match self {
            Sha2Kind::Sha256 => 256,
            Sha2Kind::Sha384 => 384,
        }
    }
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn hmac_sha384(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m =
        <Hmac<Sha384> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn hmac_by(kind: Sha2Kind, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match kind {
        Sha2Kind::Sha256 => hmac_sha256(key, msg),
        Sha2Kind::Sha384 => hmac_sha384(key, msg),
    }
}

/// The enctype's PRF (RFC 3961 §3, RFC 8009 §5.1).
///
/// **Not** a plain HMAC, and this is the trap: for the SHA1 enctypes the simplified
/// profile defines
///
/// ```text
/// tmp = SHA-1(message)[..16]
/// PRF = E(DK(protocol-key, "prf"), tmp)     with the all-zero initial state
/// ```
///
/// — one AES block, keyed by a *derived* key, not the key itself. A plain
/// `HMAC-SHA1(key, message)` is shorter, cheaper and wrong: RFC 6113's `PRF+` is built
/// on this function, so the wrong PRF produces a `cf2` output that no other
/// implementation computes. The published `t_cf2` vectors are what caught it here.
///
/// The RFC 8009 enctypes use `KDF-HMAC-SHA2` with the label `"prf"` instead, which is
/// the same construction that derives their keys.
pub fn prf(enctype: Enctype, key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    match enctype.sha2_kind() {
        Some(kind) => {
            let bits = match kind {
                Sha2Kind::Sha256 => 256,
                Sha2Kind::Sha384 => 384,
            };
            kdf_hmac_sha2(kind, key, b"prf", Some(msg), bits)
        }
        None => {
            if key.len() != enctype.key_len() {
                return Err(Error::Crypto(format!(
                    "the PRF of {enctype:?} needs a {}-octet key, got {}",
                    enctype.key_len(),
                    key.len()
                )));
            }
            use sha1::Digest;
            let kp = dk(key, b"prf", enctype.key_len())?;
            let mut block = [0u8; 16];
            block.copy_from_slice(&sha1::Sha1::digest(msg)[..16]);
            crate::aes_cts::encrypt(&kp, &[0u8; 16], &block)
        }
    }
}

/// RFC 6113 §5.1 `PRF+`: `PRF(k, 1 || seed) || PRF(k, 2 || seed) || …`, truncated.
///
/// The counter is **one octet**, not the four that SP800-108 uses. That looks like a
/// deviation and is not: MIT's `krb5_c_prfplus` and Heimdal both use one octet, and a
/// four-octet counter produces a key that no other implementation computes. The
/// vectors in this module's tests come from MIT's `t_cf2`, which is why this is
/// pinned rather than reasoned about.
pub fn prf_plus(enctype: Enctype, key: &[u8], seed: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len + 64);
    let mut input = Vec::with_capacity(1 + seed.len());
    for counter in 1u8..=255 {
        if out.len() >= len {
            break;
        }
        input.clear();
        input.push(counter);
        input.extend_from_slice(seed);
        out.extend_from_slice(&prf(enctype, key, &input)?);
    }
    if out.len() < len {
        return Err(Error::Crypto(format!(
            "PRF+ cannot produce {len} octets from a {}-octet hash",
            out.len()
        )));
    }
    out.truncate(len);
    Ok(out)
}

/// RFC 6113 §5.1 `KRB-FX-CF2`: `PRF+(k1, pepper1) XOR PRF+(k2, pepper2)`.
///
/// The result is a key of `enctype` — `k1`'s — because random-to-key is the identity
/// for AES. FAST uses it to strengthen a reply key with a per-exchange secret, and
/// PKINIT to combine the KDC's contribution with the client's; in both the point is
/// that neither side alone can compute the result.
pub fn cf2(
    k1: &[u8],
    pepper1: &str,
    enctype: Enctype,
    k2: &[u8],
    pepper2: &str,
) -> Result<Vec<u8>> {
    let n = enctype.key_len();
    let a = prf_plus(enctype, k1, pepper1.as_bytes(), n)?;
    let b = prf_plus(enctype, k2, pepper2.as_bytes(), n)?;
    Ok(a.iter().zip(&b).map(|(x, y)| x ^ y).collect())
}

/// RFC 3961 §5.1 `DR(Key, Constant) = k-truncate(B1 || B2 || ...)`.
///
/// The constant is n-folded — never zero-padded — and each iteration encrypts
/// the *previous ciphertext* with the all-zero initial state (ECB), not a
/// chained IV. AES-128 needs one block, AES-256 two.
pub fn dr(base_key: &[u8], constant: &[u8], k: usize) -> Result<Vec<u8>> {
    check_dr_args(base_key, constant, k)?;
    let block = dr_block(constant)?;
    Ok(dr_expand(base_key, block, k))
}

/// The three refusals a caller can earn before any AES is done.
///
/// They are one statement — "these arguments describe no derivation RFC 3961 defines" — and each
/// names the argument at fault, because a caller reading the message is the one who can fix it.
fn check_dr_args(base_key: &[u8], constant: &[u8], k: usize) -> Result<()> {
    if base_key.len() != 16 && base_key.len() != 32 {
        return Err(Error::Crypto(format!(
            "DR/DK needs a 16- or 32-octet AES key, got {}",
            base_key.len()
        )));
    }
    if constant.is_empty() {
        return Err(Error::Crypto("DR constant is empty".into()));
    }
    if k == 0 || k > 32 {
        return Err(Error::Crypto(format!("DR output length {k} out of range")));
    }
    Ok(())
}

/// The constant folded to one AES block.
///
/// A constant longer than the block is refused rather than truncated: RFC 3961 §5.1 caps it, and
/// truncating would make two different constants derive the same key.
fn dr_block(constant: &[u8]) -> Result<[u8; AES_BLOCK]> {
    let mut block = [0u8; AES_BLOCK];
    match constant.len() {
        AES_BLOCK => block.copy_from_slice(constant),
        n if n > AES_BLOCK => {
            return Err(Error::Crypto(format!(
                "DR constant is {n} octets; RFC 3961 §5.1 caps it at the block size"
            )));
        }
        _ => block.copy_from_slice(&n_fold(constant, AES_BLOCK * 8)),
    }
    Ok(block)
}

/// The key, expanded a block at a time: `K1 = E(K, K1)`, `K2 = E(K, K1)`, and so on.
fn dr_expand(base_key: &[u8], mut block: [u8; AES_BLOCK], k: usize) -> Vec<u8> {
    use aes::cipher::KeyInit;
    let mut out = Vec::with_capacity(k + AES_BLOCK);
    if base_key.len() == 16 {
        let c = aes::Aes128::new_from_slice(base_key).expect("a 16-octet key");
        encrypt_into(&c, &mut block, &mut out, k);
    } else {
        let c = aes::Aes256::new_from_slice(base_key).expect("a 32-octet key");
        encrypt_into(&c, &mut block, &mut out, k);
    }
    out.truncate(k);
    out
}

/// Encrypts `block` in place until `out` holds at least `k` octets.
fn encrypt_into<C>(cipher: &C, block: &mut [u8; AES_BLOCK], out: &mut Vec<u8>, k: usize)
where
    C: aes::cipher::BlockSizeUser<BlockSize = aes::cipher::consts::U16>
        + aes::cipher::BlockCipherEncrypt,
{
    while out.len() < k {
        let mut b = aes::cipher::Block::<C>::try_from(&block[..]).expect("a sixteen-octet block");
        cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
        out.extend_from_slice(block);
    }
}

/// RFC 3961 §5.1 `DK = random-to-key(DR(...))`. For every AES enctype
/// `random-to-key` is the identity, so this is `DR`.
pub fn dk(base_key: &[u8], constant: &[u8], k: usize) -> Result<Vec<u8>> {
    dr(base_key, constant, k)
}

/// RFC 8009 §3 `KDF-HMAC-SHA2(key, label, [context,] k)`.
///
/// The counter is fixed at 1, the separator `0x00` is present even without a
/// context, and `k` is the length in **bits** — writing the octet count there
/// produces a plausible key that is silently wrong, because the field is
/// inside the MAC.
///
/// One HMAC is computed and truncated, so `k` cannot exceed the digest the kind produces: RFC 3961
/// §5.1 caps the output at the hash length for exactly this reason. The guard says so and returns
/// `Err`; before it did, a caller asking for more got a panic out of the slice below — an argument
/// error surfacing as a crash inside a crypto crate.
pub fn kdf_hmac_sha2(
    kind: Sha2Kind,
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    k_bits: u32,
) -> Result<Vec<u8>> {
    if k_bits == 0 || !k_bits.is_multiple_of(8) || k_bits > kind.output_bits() {
        return Err(Error::Crypto(format!(
            "KDF output length {k_bits} bits is not a valid whole-octet length for \
             {kind:?}, which yields at most {} bits",
            kind.output_bits()
        )));
    }
    let mut msg = Vec::with_capacity(4 + label.len() + 1 + context.map_or(0, |c| c.len()) + 4);
    msg.extend_from_slice(&1u32.to_be_bytes());
    msg.extend_from_slice(label);
    msg.push(0);
    if let Some(c) = context {
        msg.extend_from_slice(c);
    }
    msg.extend_from_slice(&k_bits.to_be_bytes());
    let mac = hmac_by(kind, key, &msg);
    Ok(mac[..(k_bits / 8) as usize].to_vec())
}

/// The hash a KDF is built on, where the choice is a parameter rather than an enctype.
///
/// `Sha2Kind` answers "which SHA-2" for the enctypes, and stops there because RFC 3961 and RFC 8009
/// only ever ask for 256 or 384. A counter-mode KDF is asked by whatever protocol is calling it -
/// SP 800-56A names SHA-1, SHA-256 and SHA-512 - so the set here is wider and includes the one hash
/// this crate otherwise leaves to the Kerberos checksums.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KdfHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// SP 800-56A single-step KDF: `H(counter || Z || OtherInfo)`, counters from 1, truncated to `len`.
///
/// The counter is 32-bit big-endian and starts at one, and `OtherInfo` is opaque here: what goes into
/// it is the protocol's business - PKINIT builds it from two principals and the enctypes, and a
/// different protocol would build something else. `len` is in **octets**, unlike the SP 800-108
/// function above, whose field is in bits because that field travels inside the MAC; here the length
/// never reaches the hash, so it cannot be got wrong the same way.
pub fn sp_800_56a(kind: KdfHash, z: &[u8], other_info: &[u8], len: usize) -> Vec<u8> {
    fn run<H: Digest>(z: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 64);
        let mut counter = 1u32;
        while out.len() < len {
            let mut h = H::new();
            h.update(counter.to_be_bytes());
            h.update(z);
            h.update(info);
            out.extend_from_slice(&h.finalize());
            counter += 1;
        }
        out.truncate(len);
        out
    }
    match kind {
        KdfHash::Sha1 => run::<sha1::Sha1>(z, other_info, len),
        KdfHash::Sha256 => run::<sha2::Sha256>(z, other_info, len),
        KdfHash::Sha384 => run::<sha2::Sha384>(z, other_info, len),
        KdfHash::Sha512 => run::<sha2::Sha512>(z, other_info, len),
    }
}

/// PBKDF2 (RFC 8018 §5.2) over any PRF the caller supplies.
///
/// Public because PKCS#12's password-based encryption is the same construction with SHA-1 or a
/// SHA-2 chosen by the file, and a second implementation of it would be a second answer to "how are
/// the octets of a derived key produced". The PRF is a parameter rather than fixed so that the
/// legacy bags, which predate SHA-2, are covered by the same loop.
pub fn pbkdf2(
    prf: impl Fn(&[u8], &[u8]) -> Vec<u8>,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + 32);
    let mut index: u32 = 1;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&index.to_be_bytes());
        let mut u = prf(password, &msg);
        let mut t = u.clone();
        for _ in 1..iterations {
            u = prf(password, &u);
            for (a, b) in t.iter_mut().zip(&u) {
                *a ^= b;
            }
        }
        out.extend_from_slice(&t);
        index += 1;
    }
    out.truncate(out_len);
    out
}

/// The constant string-to-key folds in after PBKDF2 (RFC 3962 §A.2).
const S2K_CONSTANT: &[u8] = b"kerberos";

/// The iteration count `s2kparams` asks for, refusing one below the enctype's default.
///
/// A KDC that sends `s2kparams` with a low count is asking for a key that falls to an offline
/// dictionary attack in seconds, and the client has no way to tell that it happened: the key is
/// the right length, the exchange succeeds, and the weakness surfaces only when someone with the
/// ticket tries. Refusing is the only answer that reaches the operator.
///
/// `allow_weak` exists for the published vectors alone — RFC 3962 Appendix B and MIT's
/// `crypto_tests` use counts like 1200 and 1, so a test that goes through `s2k` cannot run them.
fn s2k_iterations(enctype: Enctype, params: Option<&[u8]>, allow_weak: bool) -> Result<u32> {
    let count = match params {
        None | Some([]) => return Ok(enctype.default_iterations()),
        Some(p) if p.len() >= 4 => u32::from_be_bytes([p[0], p[1], p[2], p[3]]),
        Some(p) => {
            return Err(Error::Crypto(format!(
                "s2kparams is {} octets, expected 4",
                p.len()
            )));
        }
    };
    if count > MAX_ITERATIONS {
        return Err(Error::Crypto(format!(
            "s2kparams iteration count {count} exceeds the {MAX_ITERATIONS} cap"
        )));
    }
    let min = enctype.default_iterations();
    if count < min && !allow_weak {
        return Err(Error::Crypto(format!(
            "s2kparams iteration count {count} is below the enctype's default of {min};              a key from it falls to an offline dictionary attack"
        )));
    }
    Ok(count)
}

/// RFC 3962 §A / RFC 8009 §4 string-to-key.
///
/// `params` is the `s2kparams` octet string from the KDC's `ETYPE-INFO2`: four
/// big-endian octets of iteration count, or absent for the enctype default. A count below the
/// enctype's default is refused — see [`s2k_iterations`].
pub fn s2k(
    enctype: Enctype,
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
) -> Result<Vec<u8>> {
    s2k_with(enctype, password, salt, params, false)
}

/// [`s2k`] without the minimum-iteration refusal, for the published vectors.
///
/// RFC 3962 Appendix B and MIT's `crypto_tests` use iteration counts of 1200 and 1; those
/// vectors are the reason the derivation can be checked against a third party at all, and they
/// cannot pass through a function that refuses them. Nothing in a KDC path may call this.
pub fn s2k_allow_weak(
    enctype: Enctype,
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
) -> Result<Vec<u8>> {
    s2k_with(enctype, password, salt, params, true)
}

fn s2k_with(
    enctype: Enctype,
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
    allow_weak: bool,
) -> Result<Vec<u8>> {
    let iterations = s2k_iterations(enctype, params, allow_weak)?;
    let len = enctype.key_len();
    // RFC 8009 §4 replaces the salt with `enctype-name || 0x00 || salt`, so one
    // password and one salt give a different key per enctype. RFC 3962 has no
    // such prefix. Heimdal builds this in `_krb5_AES_SHA2_salt`; using the raw
    // salt here yields a key of the right length that only this KDC computes.
    let saltp = match enctype.sha2_kind() {
        None => salt.to_vec(),
        Some(_) => {
            let mut v = Vec::with_capacity(enctype.name().len() + 1 + salt.len());
            v.extend_from_slice(enctype.name().as_bytes());
            v.push(0);
            v.extend_from_slice(salt);
            v
        }
    };
    // PBKDF2 gives a base key; the enctype's own KDF with the constant
    // "kerberos" turns it into the protocol key. Skipping this step yields a
    // key of exactly the right length that no other implementation agrees
    // with — the single most common AES string-to-key bug.
    let base = match enctype.sha2_kind() {
        None => pbkdf2(hmac_sha1, password, &saltp, iterations, len),
        Some(Sha2Kind::Sha256) => pbkdf2(hmac_sha256, password, &saltp, iterations, len),
        Some(Sha2Kind::Sha384) => pbkdf2(hmac_sha384, password, &saltp, iterations, len),
    };
    match enctype.sha2_kind() {
        None => dk(&base, S2K_CONSTANT, len),
        Some(kind) => kdf_hmac_sha2(kind, &base, S2K_CONSTANT, None, (len * 8) as u32),
    }
}

/// Which of the three derived keys a usage constant is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyUse {
    /// `0xAA`: encryption key.
    Encrypt,
    /// `0x55`: integrity key.
    Integrity,
    /// `0x99`: checksum key.
    Checksum,
}

impl KeyUse {
    fn tag(self) -> u8 {
        match self {
            KeyUse::Encrypt => 0xaa,
            KeyUse::Integrity => 0x55,
            KeyUse::Checksum => 0x99,
        }
    }
}

/// RFC 3961 §5.3: the usage in four big-endian octets, followed by the use tag.
pub fn usage_constant(usage: u32, use_: KeyUse) -> [u8; 5] {
    let u = usage.to_be_bytes();
    [u[0], u[1], u[2], u[3], use_.tag()]
}

/// The usage-specific key: DR/DK for 17/18, KDF-HMAC-SHA2 for 19/20.
///
/// The output length depends on *which* key is wanted, not only on the enctype:
/// `Ke` and `Ki` are the protocol key size, while `Kc` is the checksum key size
/// (RFC 3962 §5.3 keeps it equal to the key; RFC 8009 §5 makes it 128 bits for
/// enctype 19 and 192 for enctype 20 — so for `aes256-cts-hmac-sha384-192` the
/// checksum key is 24 octets, not 32).
pub fn derive_key(enctype: Enctype, base_key: &[u8], usage: u32, use_: KeyUse) -> Result<Vec<u8>> {
    let len = match use_ {
        KeyUse::Checksum => enctype.checksum_key_len(),
        KeyUse::Integrity => enctype.integrity_key_len(),
        KeyUse::Encrypt => enctype.key_len(),
    };
    derive_key_len(enctype, base_key, usage, use_, len)
}

/// The same, at an explicit output length — MAC keys are sized by the enctype,
/// not by the caller, so this exists for the string-to-key path where a
/// truncated key is wanted.
pub fn derive_key_len(
    enctype: Enctype,
    base_key: &[u8],
    usage: u32,
    use_: KeyUse,
    len: usize,
) -> Result<Vec<u8>> {
    let constant = usage_constant(usage, use_);
    match enctype.sha2_kind() {
        None => dk(base_key, &constant, len),
        Some(kind) => kdf_hmac_sha2(kind, base_key, &constant, None, (len * 8) as u32),
    }
}

/// Kerberos key usages (RFC 4120 §7.5.1) this KDC needs by name.
/// The key usages (RFC 4120 §7.5.1) this KDC needs by name.
pub mod usage {
    /// PA-ENC-TIMESTAMP in an AS-REQ.
    pub const AS_REQ_PA_ENC_TS: u32 = 1;
    /// A ticket's `EncTicketPart`.
    pub const KDC_REP_TICKET: u32 = 2;
    /// An AS-REP's `EncASRepPart`.
    pub const AS_REP_ENCPART: u32 = 3;
    /// The session key inside TGS-REQ authorization data.
    pub const TGS_REQ_AD_SESSKEY: u32 = 4;
    /// The subkey inside TGS-REQ authorization data.
    pub const TGS_REQ_AD_SUBKEY: u32 = 5;
    /// The checksum over `KDC-REQ-BODY` in a TGS-REQ authenticator.
    pub const TGS_REQ_AUTH_CKSUM: u32 = 6;
    /// A TGS-REQ's authenticator.
    pub const TGS_REQ_AUTH: u32 = 7;
    /// A TGS-REP's `EncTGSRepPart`, session key.
    pub const TGS_REP_ENCPART_SESSKEY: u32 = 8;
    /// A TGS-REP's `EncTGSRepPart`, subkey.
    pub const TGS_REP_ENCPART_SUBKEY: u32 = 9;
    /// The checksum in an AP-REQ authenticator.
    pub const AP_REQ_AUTH_CKSUM: u32 = 10;
    /// An AP-REQ authenticator.
    pub const AP_REQ_AUTH: u32 = 11;
    /// An AP-REP's `EncAPRepPart`.
    pub const AP_REP_ENCPART: u32 = 12;
    /// A KRB-PRIV's encrypted part.
    pub const KRB_PRIV_ENCPART: u32 = 13;
    /// A KRB-CRED's encrypted part.
    pub const KRB_CRED_ENCPART: u32 = 14;
    /// A KRB-SAFE's checksum.
    pub const KRB_SAFE_CKSUM: u32 = 15;
    /// An RFC 4121 Wrap token sealed by the context **acceptor**.
    pub const ACCEPTOR_SEAL: u32 = 22;
    /// An RFC 4121 MIC token signed by the context acceptor.
    pub const ACCEPTOR_SIGN: u32 = 23;
    /// An RFC 4121 Wrap token sealed by the context **initiator**.
    pub const INITIATOR_SEAL: u32 = 24;
    /// An RFC 4121 MIC token signed by the context initiator.
    pub const INITIATOR_SIGN: u32 = 25;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MIT `crypto_tests` derive vectors (key, constant = usage||tag, derived).
    const DERIVE: &[(i32, &str, &str, &str)] = &[
        (
            17,
            "42263c6e89f4fc28b8df68ee09799f15",
            "0000000299",
            "34280a382bc92769b2da2f9ef066854b",
        ),
        (
            17,
            "42263c6e89f4fc28b8df68ee09799f15",
            "00000002aa",
            "5b14fc4e250e14ddf9dccf1af6674f53",
        ),
        (
            17,
            "42263c6e89f4fc28b8df68ee09799f15",
            "0000000255",
            "4ed31063621684f09ae8d89991af3e8f",
        ),
        (
            18,
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
            "0000000299",
            "bfab388bdcb238e9f9c98d6a878304f04d30c82556375ac507a7a852790f4674",
        ),
    ];

    /// SP 800-56A's counter-mode KDF, against a digest computed outside this crate.
    ///
    /// The vectors are `H(counter_be32 || Z || OtherInfo)` in Python, so they pin the construction
    /// rather than this implementation of it. The 48-octet case is the one that matters: it is the
    /// only one that runs the counter past 1, and a KDF that forgets to increment produces the first
    /// block repeated - which agrees with the 32-octet vector and disagrees here.
    #[test]
    fn sp_800_56a_is_the_counter_mode_construction() {
        let z = b"secret-shared-value";
        let info = b"protocol-info";

        assert_eq!(
            hex::encode(sp_800_56a(KdfHash::Sha256, z, info, 32)),
            "daf5ddeb8aefb7796b539fa9a21d727b41a0ca2087e8b4b6e9ae2c3f5e41c625"
        );
        assert_eq!(
            hex::encode(sp_800_56a(KdfHash::Sha1, z, info, 20)),
            "5092029790433acb243d80ee4a44387bcfbe7ad8"
        );
        assert_eq!(
            hex::encode(sp_800_56a(KdfHash::Sha512, z, info, 16)),
            "99eabb05abc10acdaecc4f9a69f74dba"
        );
        assert_eq!(
            hex::encode(sp_800_56a(KdfHash::Sha256, z, info, 48)),
            "daf5ddeb8aefb7796b539fa9a21d727b41a0ca2087e8b4b6e9ae2c3f5e41c625\
             b36b600c284ab6de3bd5562f272b707f"
        );
        // A zero-length request is nothing, not the first block: truncation happens at the end.
        assert!(sp_800_56a(KdfHash::Sha256, z, info, 0).is_empty());
    }

    #[test]
    fn mit_derive_vectors() {
        for (etype, key, constant, want) in DERIVE {
            let e = Enctype::from_id(*etype).unwrap();
            let key = hex::decode(key).unwrap();
            let constant = hex::decode(constant).unwrap();
            let got = dk(&key, &constant, e.key_len()).unwrap();
            assert_eq!(hex::encode(&got), *want, "etype {etype}");
        }
    }

    /// Heimdal `lib/krb5/aes-test.c` string-to-key vectors.
    const S2K: &[(i32, &str, &str, u32, &str)] = &[
        (
            17,
            "password",
            "ATHENA.MIT.EDUraeburn",
            1,
            "42263c6e89f4fc28b8df68ee09799f15",
        ),
        (
            18,
            "password",
            "ATHENA.MIT.EDUraeburn",
            1,
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
        ),
        (
            17,
            "password",
            "ATHENA.MIT.EDUraeburn",
            2,
            "c651bf29e2300ac27fa469d693bdda13",
        ),
        (
            18,
            "password",
            "ATHENA.MIT.EDUraeburn",
            2,
            "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
        ),
        (
            17,
            "password",
            "ATHENA.MIT.EDUraeburn",
            1200,
            "4c01cd46d632d01e6dbe230a01ed642a",
        ),
        (
            18,
            "password",
            "ATHENA.MIT.EDUraeburn",
            1200,
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
        ),
        (
            17,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "pass phrase equals block size",
            1200,
            "59d1bb789a828b1aa54ef9c2883f69ed",
        ),
        (
            18,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "pass phrase equals block size",
            1200,
            "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
        ),
        (
            17,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "pass phrase exceeds block size",
            1200,
            "cb8005dc5f90179a7f02104c0018751d",
        ),
        (
            18,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "pass phrase exceeds block size",
            1200,
            "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
        ),
        // "g-clef" (U+1D11E) as UTF-8, RFC 3962's non-ASCII case.
        (
            17,
            "\u{1d11e}",
            "EXAMPLE.COMpianist",
            50,
            "f149c1f2e154a73452d43e7fe62a56e5",
        ),
        (
            18,
            "\u{1d11e}",
            "EXAMPLE.COMpianist",
            50,
            "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
        ),
    ];

    /// A low `s2kparams` count is refused, and the refusal names the count and the floor: the
    /// operator needs to know what the KDC asked for, not merely that the key was not derived.
    #[test]
    fn a_low_iteration_count_is_refused() {
        for count in [1u32, 1200, 4095] {
            let err = s2k(
                Enctype::Aes128Sha1,
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&count.to_be_bytes()),
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains(&count.to_string()), "{err}");
            assert!(
                err.contains("4096"),
                "the floor belongs in the message: {err}"
            );
        }
        // The default, and anything above it, still derives.
        for count in [4096u32, 5000] {
            s2k(
                Enctype::Aes128Sha1,
                b"password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&count.to_be_bytes()),
            )
            .expect("a count at or above the default derives");
        }
    }

    /// The vectors and the strict path agree on the derivation, and differ only in whether a weak
    /// count is allowed — so `s2k_allow_weak` is not a second implementation.
    #[test]
    fn the_weak_path_is_the_same_derivation() {
        let params = 1200u32.to_be_bytes();
        assert!(
            s2k(Enctype::Aes128Sha1, b"p", b"s", Some(&params))
                .unwrap_err()
                .to_string()
                .contains("1200")
        );
        let strong = 4096u32.to_be_bytes();
        assert_eq!(
            s2k(Enctype::Aes128Sha1, b"p", b"s", Some(&strong)).unwrap(),
            s2k_allow_weak(Enctype::Aes128Sha1, b"p", b"s", Some(&strong)).unwrap()
        );
    }

    #[test]
    fn heimdal_s2k_vectors_sha1() {
        for (etype, password, salt, iterations, want) in S2K {
            let e = Enctype::from_id(*etype).unwrap();
            let params = iterations.to_be_bytes();
            let got =
                s2k_allow_weak(e, password.as_bytes(), salt.as_bytes(), Some(&params)).unwrap();
            assert_eq!(
                hex::encode(&got),
                *want,
                "s2k_allow_weak({password:?}, {salt:?}, {iterations}, etype {etype})"
            );
        }
    }

    /// Heimdal's table also carries a binary salt, which a UTF-8-only test
    /// would never reach.
    #[test]
    fn heimdal_s2k_with_binary_salt() {
        let salt = [0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12];
        let got = s2k_allow_weak(
            Enctype::Aes128Sha1,
            b"password",
            &salt,
            Some(&5u32.to_be_bytes()),
        )
        .unwrap();
        assert_eq!(hex::encode(&got), "e9b23d52273747dd5c35cb55be619d8e");
        let got = s2k_allow_weak(
            Enctype::Aes256Sha1,
            b"password",
            &salt,
            Some(&5u32.to_be_bytes()),
        )
        .unwrap();
        assert_eq!(
            hex::encode(&got),
            "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31"
        );
    }

    #[test]
    fn s2k_rejects_a_hostile_iteration_count() {
        assert!(
            s2k(
                Enctype::Aes256Sha1,
                b"pw",
                b"salt",
                Some(&u32::MAX.to_be_bytes())
            )
            .is_err()
        );
        assert!(
            s2k(
                Enctype::Aes256Sha1,
                b"pw",
                b"salt",
                Some(&0u32.to_be_bytes())
            )
            .is_err()
        );
        assert!(s2k(Enctype::Aes256Sha1, b"pw", b"salt", Some(&[0, 0])).is_err());
    }

    #[test]
    fn dr_needs_a_real_constant() {
        assert!(dr(&[0u8; 16], b"", 16).is_err());
        assert!(dr(&[0u8; 16], &[0u8; 17], 16).is_err());
        assert!(dr(&[0u8; 15], b"const", 16).is_err());
    }

    /// Both ends of the output length, separately: RFC 3961 §5.1 makes a key at most 32 octets, and
    /// the guard reads `k == 0 || k > 32`.
    ///
    /// The mutation that survived was `||` → `&&`, which rejects neither end: `dr(…, 0)` then returns
    /// an empty key and `dr(…, 33)` an over-long one, and nothing notices. The existing tests asked
    /// for 16 octets and a bad key or constant, so both ends of this guard were never reached.
    #[test]
    fn dr_refuses_an_output_length_outside_one_to_thirty_two() {
        assert!(
            dr(&[0u8; 16], b"const", 0).is_err(),
            "zero octets is not a key"
        );
        assert!(
            dr(&[0u8; 16], b"const", 33).is_err(),
            "33 octets is past the cap"
        );
        for k in [1usize, 32] {
            let got = dr(&[0u8; 16], b"const", k).expect("a legal length");
            assert_eq!(got.len(), k, "the caller gets exactly the octets asked for");
        }
    }

    /// A constant of exactly one AES block goes in unfolded.
    ///
    /// The mutation `len > AES_BLOCK` → `>=` survives here and that is correct: the equality branch
    /// above it is taken first, so the `else if` is only reached when the length differs from a
    /// block, and `>` and `>=` cannot be told apart. An equivalent mutant, not a gap — but the
    /// behaviour still deserves a test, because the identity it rests on (folding a block-sized
    /// constant is folding nothing) is what makes the two paths agree, and no published vector
    /// reaches this branch at all: every DR vector uses `usage || tag`, five octets for the AES
    /// enctypes.
    #[test]
    fn dr_takes_a_constant_of_exactly_one_block() {
        let constant = [7u8; 16];
        let got = dr(&[0u8; 16], &constant, 16).expect("a full-block constant is legal");
        let folded = dr(&[0u8; 16], &n_fold(&constant, AES_BLOCK * 8), 16).expect("folded");
        assert_eq!(
            got, folded,
            "a block-sized constant is used as it is, which is the same as folding it"
        );
        let other = dr(&[0u8; 16], &[8u8; 16], 16).expect("another constant");
        assert_ne!(got, other, "the constant reaches the cipher");
    }

    /// SP 800-108's `L` names the output in bits, but this KDF computes one HMAC and truncates it,
    /// so the ceiling is the kind's own digest — 256 bits for SHA-256, 384 for SHA-384 — and it is
    /// inclusive.
    ///
    /// Both mutations of the old `k_bits > 8 * 64` survived because only 100 bits was ever tried,
    /// which fails the whole-octet check first. The old bound was wrong besides: asking SHA-256 for
    /// 512 bits passed the guard and then panicked on the truncation, so an argument error came out
    /// as a crash. The test that found it asks for one bit past the hash and one exactly at it.
    #[test]
    fn kdf_output_cap_is_the_hash_length() {
        let max = kdf_hmac_sha2(Sha2Kind::Sha256, &[0u8; 16], b"lbl", None, 256)
            .expect("256 bits is as far as SHA-256 reaches");
        assert_eq!(max.len(), 32);
        // The text, not just the `is_err`: a caller reading this out of a log needs to know which
        // length and which ceiling, and `DerError::fmt` surviving its mutation in the sibling crate
        // is what an unchecked message reads like. Substrings, because the prefix belongs to `Error`.
        let err = kdf_hmac_sha2(Sha2Kind::Sha256, &[0u8; 16], b"lbl", None, 264)
            .unwrap_err()
            .to_string();
        assert!(err.contains("264 bits"), "{err}");
        assert!(err.contains("Sha256"), "{err}");
        assert!(err.contains("at most 256 bits"), "{err}");

        let wide = kdf_hmac_sha2(Sha2Kind::Sha384, &[0u8; 16], b"lbl", None, 384)
            .expect("384 bits is as far as SHA-384 reaches");
        assert_eq!(wide.len(), 48);
        assert!(kdf_hmac_sha2(Sha2Kind::Sha384, &[0u8; 16], b"lbl", None, 392).is_err());
    }

    /// The hash length the KDF reports is the one it truncates to. A pair that disagreed would let a
    /// caller ask for a length the guard allows and the slice then panics on, which is how the
    /// 512-bit case behaved.
    #[test]
    fn the_reported_output_length_is_what_the_kdf_produces() {
        for kind in [Sha2Kind::Sha256, Sha2Kind::Sha384] {
            let bits = kind.output_bits();
            let got = kdf_hmac_sha2(kind, &[0u8; 16], b"lbl", None, bits).expect("the maximum");
            assert_eq!(
                got.len() as u32 * 8,
                bits,
                "the ceiling is the digest for {kind:?}"
            );
            assert!(
                kdf_hmac_sha2(kind, &[0u8; 16], b"lbl", None, bits + 8).is_err(),
                "one octet past the ceiling is an error for {kind:?}"
            );
        }
    }

    /// The `s2kparams` iteration cap is inclusive: the cap itself is a count a KDC may send, one
    /// more is refused.
    ///
    /// `count > MAX_ITERATIONS` mutated to `>=` refuses the maximum. Nothing noticed, because the
    /// tests around it only used counts far below the cap and one `u32::MAX`.
    #[test]
    fn the_iteration_cap_admits_its_own_value() {
        assert!(
            s2k_iterations(
                Enctype::Aes256Sha1,
                Some(&MAX_ITERATIONS.to_be_bytes()),
                true
            )
            .is_ok(),
            "the cap itself is a legal count"
        );
        assert!(
            s2k_iterations(
                Enctype::Aes256Sha1,
                Some(&(MAX_ITERATIONS + 1).to_be_bytes()),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn kdf_refuses_ragged_lengths() {
        assert!(
            kdf_hmac_sha2(Sha2Kind::Sha256, &[0u8; 16], b"lbl", None, 100).is_err(),
            "100 bits is not whole octets"
        );
    }

    /// MIT's `lib/crypto/crypto_tests/t_cf2` vectors: `key1`/`key2` are
    /// string-to-key with the salt equal to the password, peppers "a" and "b".
    ///
    /// These are the vectors that decide whether this crate's FAST and PKINIT can talk
    /// to anything else: the counter width in `PRF+` is the one detail where a
    /// plausible reading (SP800-108's four octets) produces keys no other
    /// implementation computes.
    #[test]
    fn cf2_matches_mits_published_vectors() {
        for (enctype, want) in [
            (Enctype::Aes128Sha1, "97df97e4b798b29eb31ed7280287a92a"),
            (
                Enctype::Aes256Sha1,
                "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b",
            ),
            (Enctype::Aes128Sha256, "edd02a39d2dbde31611c16e610be062c"),
            (
                Enctype::Aes256Sha384,
                "67f6ea530aea85a37dcbb23349ea52dcc61ca8493ff557252327fd8304341584",
            ),
        ] {
            let k1 = s2k(enctype, b"key1", b"key1", None).unwrap();
            let k2 = s2k(enctype, b"key2", b"key2", None).unwrap();
            let got = cf2(&k1, "a", enctype, &k2, "b").unwrap();
            assert_eq!(
                got.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                want,
                "{enctype:?}"
            );
            assert_eq!(got.len(), enctype.key_len());
        }
    }

    #[test]
    fn cf2_depends_on_both_keys_and_both_peppers() {
        // Neither side alone may compute the result: that is why FAST can strengthen a
        // reply key with a value only the armor key can deliver.
        let k1 = s2k(Enctype::Aes256Sha1, b"key1", b"key1", None).unwrap();
        let k2 = s2k(Enctype::Aes256Sha1, b"key2", b"key2", None).unwrap();
        let base = cf2(&k1, "a", Enctype::Aes256Sha1, &k2, "b").unwrap();
        assert_ne!(base, cf2(&k2, "a", Enctype::Aes256Sha1, &k1, "b").unwrap());
        assert_ne!(base, cf2(&k1, "b", Enctype::Aes256Sha1, &k2, "a").unwrap());
        assert_ne!(base, cf2(&k1, "a", Enctype::Aes256Sha1, &k1, "b").unwrap());
    }

    #[test]
    fn prf_plus_concatenates_the_counted_blocks() {
        let key = [0x11u8; 32];
        let one = prf_plus(Enctype::Aes256Sha1, &key, b"seed", 20).unwrap();
        let two = prf_plus(Enctype::Aes256Sha1, &key, b"seed", 40).unwrap();
        assert_eq!(
            &two[..20],
            &one[..],
            "a longer output extends the shorter one"
        );
        assert_eq!(one.len(), 20);
    }

    #[test]
    fn the_prf_refuses_a_key_of_the_wrong_length() {
        // The simplified-profile PRF derives its AES key with `DK`, which needs the
        // enctype's own key size; a 16-octet key under AES-256 is not a shorter key,
        // it is the wrong one.
        assert!(prf(Enctype::Aes256Sha1, &[0u8; 16], b"x").is_err());
        assert!(prf(Enctype::Aes128Sha1, &[0u8; 32], b"x").is_err());
        assert!(prf(Enctype::Aes128Sha1, &[0u8; 16], b"x").is_ok());
    }
}
