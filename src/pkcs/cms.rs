//! The CMS (RFC 5652) PKINIT uses: the KDC's SignedData around its DH
//! public value, checked to a trust anchor, and the client's SignedData
//! (or, anonymously, a bare ContentInfo) around its AuthPack, made as
//! MIT's `cms_signeddata_create` makes it.
//!
//! ```text
//! ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
//! SignedData ::= SEQUENCE {
//!     version, digestAlgorithms SET OF AlgorithmIdentifier,
//!     encapContentInfo SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING },
//!     certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
//!     crls [1] IMPLICIT OPTIONAL, signerInfos SET OF SignerInfo }
//! SignerInfo ::= SEQUENCE {
//!     version, sid IssuerAndSerialNumber, digestAlgorithm,
//!     signedAttrs [0] IMPLICIT SET OF Attribute OPTIONAL,
//!     signatureAlgorithm, signature OCTET STRING, unsignedAttrs [1] OPTIONAL }
//! ```

use super::asn1::{self, ReaderExt};
use super::crl;
use super::keys::{Hash, PrivateKey, PublicKey, SigAlg};
use super::rsa;
use super::x509::{self, Cert};
use crate::der::{self, DerError, Reader};

type Result<T> = std::result::Result<T, DerError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

/// A step marker while tracing a SignedData nobody here wrote: `KRB5_CMS_TRACE` in the environment
/// prints how far the parse got before it refused.
fn trace(step: &str) {
    if std::env::var_os("KRB5_CMS_TRACE").is_some() {
        eprintln!("cms: {step}");
    }
}

pub const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// `id-pkinit-authData`: the AuthPack's content type.
pub const ID_PKINIT_AUTH_DATA: &str = "1.3.6.1.5.2.3.1";
/// `id-pkinit-DHKeyData`: the KDCDHKeyInfo's content type.
pub const ID_PKINIT_DHKEY_DATA: &str = "1.3.6.1.5.2.3.2";
/// `id-pkinit-rkeyData` (RFC 4556 §3.2.3.2): the ReplyKeyPack's content type, inside a transported
/// key's SignedData. `1.3.6.1.5.2.3.4` is `id-pkinit-KPClientAuth`, an extended key usage, and
/// Heimdal answered with `.3` — which is what the RFC says and this said wrong.
pub const ID_PKINIT_RKEY_DATA: &str = "1.3.6.1.5.2.3.3";
const ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// `id-envelopedData`: what a KDC wraps the reply key in for RSA key transport.
pub const ID_ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
/// `aes256-CBC` and `aes128-CBC` (RFC 3565): the content encryptions this crate opens.
const ID_AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
const ID_AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
/// `rsaEncryption`, the only key transport CMS here opens.
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

/// An EnvelopedData ContentInfo holding `content`, its content-encryption key wrapped to
/// `recipient` with RSA PKCS #1 v1.5 and AES-256-CBC under a fresh key and IV.
///
/// This is the shape a KDC's `encKeyPack` has (RFC 4556 §3.2.3.2: the KDC makes a reply key and
/// "encrypts it in the client's public key"). The client only ever reads one — this builder exists
/// for tests and for a KDC built on this crate.
#[cfg(any(test, feature = "test-support"))]
pub fn enveloped_data(content_type: &str, content: &[u8], recipient: &Cert) -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cek);
    rand::thread_rng().fill_bytes(&mut iv);
    let encrypted = aes_cbc(true, &cek, &iv, content)?;
    let wrapped = match recipient.public_key()? {
        PublicKey::Rsa(k) => k.encrypt_pkcs1_v15(&cek)?,
        PublicKey::Ec(_) => return err("RSA key transport needs an RSA client key"),
    };

    let ktri = der::seq(&[
        der::int(0),
        der::seq(&[
            recipient.issuer.clone(),
            der::tlv(der::INTEGER, &recipient.serial),
        ]),
        asn1::alg_id(RSA_ENCRYPTION, Some(asn1::null())),
        der::octets(&wrapped),
    ]);
    let enveloped = der::seq(&[
        der::int(0),
        // `RecipientInfo ::= CHOICE { ktri KeyTransRecipientInfo, kari [1] ... }`: the key
        // transport alternative is the untagged SEQUENCE, and [1] is key agreement, not this.
        asn1::set_of(vec![ktri]),
        der::seq(&[
            asn1::oid_tlv(content_type),
            asn1::alg_id(ID_AES256_CBC, Some(der::octets(&iv))),
            // `encryptedContent [0] IMPLICIT OCTET STRING`, primitive: an explicit length makes
            // the constructed form unnecessary, and DER has no unnecessary forms.
            der::tlv(asn1::implicit(0), &encrypted),
        ]),
    ]);
    Ok(der::seq(&[
        asn1::oid_tlv(ID_ENVELOPED_DATA),
        der::field(0, enveloped),
    ]))
}

/// The content of an EnvelopedData encrypted to `cert`, opened with `key`: its content type, and
/// the plaintext.
///
/// An envelope addressed to another certificate is refused by name rather than attempted: a KDC
/// that answered with somebody else's envelope answered the wrong request, and a caller told
/// otherwise would hold a key it cannot use.
pub fn decrypt_enveloped(
    content_info: &[u8],
    key: &rsa::PrivateKey,
    cert: &Cert,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ed = envelope(content_info)?;
    let recipient = key_transport_recipient(&mut ed)?;
    let cek = unwrap_key(recipient, key, cert)?;
    content_field(&mut ed, &cek)
}

/// The `EnvelopedData` this `ContentInfo` carries, positioned at its first field.
fn envelope(content_info: &[u8]) -> Result<Reader<'_>> {
    let mut ci = Reader::new(content_info).seq()?;
    if ci.oid()? != asn1::oid(ID_ENVELOPED_DATA).as_slice() {
        return err("the KDC's reply key is not an EnvelopedData");
    }
    let enveloped = ci.expect(der::ctx(0))?;
    ci.done("ContentInfo")?;
    let mut ed = Reader::new(enveloped);
    ed.seq()
}

/// The one `RecipientInfo` this client can open: key transport.
///
/// Leaves `ed` positioned at the encrypted content. Key agreement is refused by name rather than
/// skipped: it is a recipient type this client implements nothing of, and a message encrypted under
/// it cannot be opened by trying the others.
fn key_transport_recipient<'a>(ed: &mut Reader<'a>) -> Result<&'a [u8]> {
    ed.uint()?; // version
    if ed.optional(der::ctx(0))?.is_some() {
        return err("the reply key's EnvelopedData carries an originatorInfo");
    }
    // `recipientInfos SET OF RecipientInfo`: the same encoding as a SEQUENCE, a different tag.
    let mut recipients = Reader::new(ed.expect(0x31)?);
    one_key_transport(&mut recipients)
}

/// The first `KeyTransRecipientInfo` of the set, and whether a `[1]` choice was met.
fn one_key_transport<'a>(recipients: &mut Reader<'a>) -> Result<&'a [u8]> {
    let mut found = None;
    while !recipients.is_empty() {
        let (tag, content) = recipients.next()?;
        match tag {
            der::SEQUENCE if found.is_none() => found = Some(content),
            t if t == der::ctx(1) => {
                return err(
                    "the reply key uses CMS key agreement, not key transport (nothing agreed a KEK)",
                );
            }
            _ => {}
        }
    }
    found.ok_or_else(|| {
        DerError("the reply key uses a recipient type this client does not implement".into())
    })
}

/// Unwraps the content-encryption key with the certificate it was wrapped to.
fn unwrap_key(ktri: &[u8], key: &rsa::PrivateKey, cert: &Cert) -> Result<Vec<u8>> {
    let mut ktri = Reader::new(ktri);
    ktri.uint()?; // version
    let (issuer, serial) = recipient_identity(&mut ktri)?;
    if issuer != cert.issuer || serial != cert.serial {
        return err("the reply key is encrypted to another certificate");
    }
    let (alg, _) = ktri.alg_id()?;
    if alg != asn1::oid(RSA_ENCRYPTION).as_slice() {
        return err("the reply key is not encrypted with RSA PKCS #1 v1.5");
    }
    let wrapped = ktri.octets()?.to_vec();
    ktri.done("KeyTransRecipientInfo")?;
    key.decrypt_pkcs1_v15(&wrapped)
}

/// The certificate a `KeyTransRecipientInfo` names, as `(issuer TLV, serial content)`.
fn recipient_identity(ktri: &mut Reader<'_>) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rid = ktri.seq()?;
    // The issuer is compared as the whole `Name` TLV, the serial as the INTEGER's content.
    let issuer = rid.next_raw()?.2.to_vec();
    let serial = asn1::uint_content(rid.next_raw()?.1)?.to_vec();
    Ok((issuer, serial))
}

/// The content type and the plaintext of the encrypted content.
fn content_field(ed: &mut Reader<'_>, cek: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut eci = ed.seq()?;
    let content_type = eci.oid()?.to_vec();
    let (alg, params) = eci.alg_id()?;
    let params =
        params.ok_or_else(|| DerError("the reply key's content encryption has no IV".into()))?;
    let iv = Reader::new(params).octets()?.to_vec();
    // Primitive as DER writes it; BER may construct it, and a KDC in the wild has been seen to.
    let (tag, ciphertext) = eci.next()?;
    if tag != asn1::implicit(0) && tag != der::ctx(0) {
        return err("the reply key's content encryption carries no ciphertext");
    }
    let plaintext = decrypt_content(alg, cek, &iv, ciphertext)?;
    Ok((content_type, plaintext))
}

/// AES-CBC, in the two key sizes the RFC names for CMS.
fn decrypt_content(alg: &[u8], cek: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if alg == asn1::oid(ID_AES256_CBC).as_slice() {
        return aes_cbc(false, cek, iv, ciphertext);
    }
    if alg == asn1::oid(ID_AES128_CBC).as_slice() {
        let short = cek
            .get(..16)
            .ok_or_else(|| DerError("a short key".into()))?;
        return aes_cbc(false, short, iv, ciphertext);
    }
    err("the reply key's content encryption is not AES-CBC")
}

/// One AES block, in place: the primitive CBC is built from.
type BlockFn = Box<dyn Fn(&mut [u8; 16])>;

/// AES-CBC with PKCS #7 padding, in one direction. Kerberos has CTS of its own; CMS does not, and
/// this crate asks AES for nothing more than single blocks here.
fn aes_cbc(encrypt: bool, key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let block = block_fn(key, encrypt)?;
    let prev: [u8; 16] = iv
        .try_into()
        .map_err(|_| DerError("the IV is not 16 octets".into()))?;
    if encrypt {
        return Ok(cbc_encrypt(&block, prev, &padded(input)));
    }
    let data = whole_blocks(input)?;
    unpad(cbc_decrypt(&block, prev, data))
}

/// The single-block operation, for the key size and direction asked for.
///
/// CMS here uses AES only; a key that is neither 128 nor 256 bits is a message the RFC does not
/// describe, and it is refused rather than padded out to a size that exists.
fn block_fn(key: &[u8], encrypt: bool) -> Result<BlockFn> {
    match key.len() {
        32 => aes_blocks::<aes::Aes256>(key, encrypt),
        16 => aes_blocks::<aes::Aes128>(key, encrypt),
        _ => err("the AES key is neither 16 nor 32 octets"),
    }
}

/// One block function over a 128-bit cipher, in the direction asked for.
///
/// The block size is fixed in the bound rather than left to the cipher: `Aes128` and `Aes256` both
/// have a sixteen-octet block, and saying so is what lets the closure take and return `[u8; 16]`
/// without a copy at every call.
fn aes_blocks<C>(key: &[u8], encrypt: bool) -> Result<BlockFn>
where
    C: aes::cipher::BlockSizeUser<BlockSize = aes::cipher::consts::U16>
        + aes::cipher::BlockCipherEncrypt
        + aes::cipher::BlockCipherDecrypt
        + aes::cipher::KeyInit
        + 'static,
{
    let cipher = <C as aes::cipher::KeyInit>::new_from_slice(key)
        .map_err(|_| DerError("a bad AES key".into()))?;
    Ok(if encrypt {
        Box::new(move |b: &mut [u8; 16]| crypt::<C>(b, |block| cipher.encrypt_block(block)))
    } else {
        Box::new(move |b: &mut [u8; 16]| crypt::<C>(b, |block| cipher.decrypt_block(block)))
    })
}

/// Runs one block through `f`, keeping the plain array as the boundary.
fn crypt<C>(b: &mut [u8; 16], f: impl Fn(&mut aes::cipher::Block<C>))
where
    C: aes::cipher::BlockSizeUser<BlockSize = aes::cipher::consts::U16>,
{
    let mut block = aes::cipher::Block::<C>::try_from(&b[..]).expect("a sixteen-octet block");
    f(&mut block);
    b.copy_from_slice(&block);
}

/// The plaintext with PKCS #7 padding: always at least one octet, so a full block gets a block.
fn padded(input: &[u8]) -> Vec<u8> {
    let pad = 16 - input.len() % 16;
    let mut data = input.to_vec();
    data.extend(std::iter::repeat_n(pad as u8, pad));
    data
}

/// The ciphertext, which has to be whole blocks and not nothing.
fn whole_blocks(input: &[u8]) -> Result<&[u8]> {
    if input.is_empty() || !input.len().is_multiple_of(16) {
        return err("the ciphertext is not whole blocks");
    }
    Ok(input)
}

/// CBC in the encrypting direction: each block is xored with the previous ciphertext.
fn cbc_encrypt(block: &BlockFn, mut prev: [u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut b = to_block(chunk);
        xor(&mut b, &prev);
        block(&mut b);
        prev = b;
        out.extend_from_slice(&b);
    }
    out
}

/// CBC in the decrypting direction: each block is xored with the ciphertext before it.
fn cbc_decrypt(block: &BlockFn, mut prev: [u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut b = to_block(chunk);
        block(&mut b);
        xor(&mut b, &prev);
        prev = to_block(chunk);
        out.extend_from_slice(&b);
    }
    out
}

/// A sixteen-octet block; the caller has already established the chunks are that long.
fn to_block(chunk: &[u8]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b.copy_from_slice(chunk);
    b
}

fn xor(b: &mut [u8; 16], p: &[u8; 16]) {
    for (x, y) in b.iter_mut().zip(p.iter()) {
        *x ^= *y;
    }
}

/// Removes PKCS #7 padding, refusing anything that is not.
///
/// The padding octets are checked, not just the count: a block whose last octets disagree says the
/// key was wrong, and accepting it would hand a caller bytes that were never the plaintext.
fn unpad(mut out: Vec<u8>) -> Result<Vec<u8>> {
    let pad = out.last().copied().unwrap_or(0) as usize;
    let tail = out.len().saturating_sub(pad);
    if pad == 0 || pad > 16 || out[tail..].iter().any(|&b| b as usize != pad) {
        return err("the padding is not PKCS #7");
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

/// `[0] EXPLICIT OCTET STRING` holding `content`.
fn econtent(content_type: &str, content: &[u8]) -> Vec<u8> {
    der::seq(&[
        asn1::oid_tlv(content_type),
        der::tlv(der::ctx(0), &der::octets(content)),
    ])
}

/// A ContentInfo of `content_type` holding `content` as an OCTET STRING:
/// what MIT's client sends for anonymous PKINIT to a KDC that has not
/// said it follows RFC 6112.
pub fn content_info(content_type: &str, content: &[u8]) -> Vec<u8> {
    econtent(content_type, content)
}

/// Who signs a SignedData: the key, and the certificates to send, the
/// signer's first.
pub struct Signer<'a> {
    pub key: &'a PrivateKey,
    pub certs: &'a [Cert],
}

/// The `SignedData` in `data`, which is either a `ContentInfo` of `id-signedData` — what MIT's KDC
/// puts in `dhSignedData` — or the bare `SignedData` itself. The second is what CMS asks for when a
/// SignedData is the *content* of an EnvelopedData (RFC 5652 §5.1: "the content is the value of the
/// encapsulated content type"), and it is what Heimdal's KDC sends in `encKeyPack`; a verifier that
/// knows only the first form interops with only one of the two KDCs.
fn signed_data_content(data: &[u8]) -> Result<&[u8]> {
    let mut outer = Reader::new(data);
    let mut top = outer.seq()?;
    let (tag, first) = top.next()?;
    if tag != asn1::OID {
        // The first field of a SignedData is its version, an INTEGER.
        return Ok(data);
    }
    if first != asn1::oid(ID_SIGNED_DATA) {
        return err("not a CMS SignedData");
    }
    top.expect(der::ctx(0))
}

/// A SignedData ContentInfo around `content`, signed with SHA-256 by
/// `signer` over the contentType and messageDigest attributes, or with no
/// signer at all (anonymous PKINIT, RFC 8062 §4.1).
pub fn signed_data(
    content_type: &str,
    content: &[u8],
    signer: Option<Signer<'_>>,
) -> Result<Vec<u8>> {
    let mut digest_algs = Vec::new();
    let mut signer_infos = Vec::new();
    let mut parts = vec![der::int(3)];
    let mut certs = Vec::new();
    if let Some(s) = signer {
        let me = s
            .certs
            .first()
            .ok_or_else(|| DerError("no signing certificate".into()))?;
        let alg = s.key.sig_alg();
        let hash = alg.hash();
        let digest_alg = asn1::alg_id(hash.oid(), Some(asn1::null()));
        let attrs = vec![
            der::seq(&[
                asn1::oid_tlv(ATTR_CONTENT_TYPE),
                asn1::set_of(vec![asn1::oid_tlv(content_type)]),
            ]),
            der::seq(&[
                asn1::oid_tlv(ATTR_MESSAGE_DIGEST),
                asn1::set_of(vec![der::octets(&hash.digest(content))]),
            ]),
        ];
        let signed_attrs = asn1::set_of(attrs);
        let sig = s.key.sign(&hash.digest(&signed_attrs))?;
        // The same SET, IMPLICIT [0] in place of the SET tag.
        let mut implicit_attrs = signed_attrs;
        implicit_attrs[0] = der::ctx(0);
        signer_infos.push(der::seq(&[
            der::int(1),
            der::seq(&[me.issuer.clone(), der::tlv(der::INTEGER, &me.serial)]),
            digest_alg.clone(),
            implicit_attrs,
            alg.alg_id(),
            der::octets(&sig),
        ]));
        digest_algs.push(digest_alg);
        certs = s.certs.iter().map(|c| c.der.clone()).collect();
    }
    parts.push(asn1::set_of(digest_algs));
    parts.push(econtent(content_type, content));
    if !certs.is_empty() {
        parts.push(der::cons(der::ctx(0), &certs));
    }
    parts.push(asn1::set_of(signer_infos));
    Ok(der::seq(&[
        asn1::oid_tlv(ID_SIGNED_DATA),
        der::field(0, der::seq(&parts)),
    ]))
}

/// What a verified SignedData carried, and who signed it.
#[derive(Debug)]
pub struct Verified {
    pub content: Vec<u8>,
    pub signer: Cert,
}

/// Check a SignedData ContentInfo of `content_type`: one signer, found
/// among the certificates sent by issuer and serial number, whose
/// signature over the signed attributes verifies, whose attributes name
/// the content type and carry the content's digest, and whose certificate
/// chains to one of `anchors` at `now`, none of it revoked by the CRLs of
/// `revocation` or those sent along.
pub fn verify(
    data: &[u8],
    content_type: &str,
    anchors: &[Cert],
    revocation: crl::Policy<'_>,
    now: i64,
) -> Result<Verified> {
    let sd = open_signed_data(data, content_type)?;
    let si = signer_info(&sd.certs, sd.signer, content_type, &sd.content)?;
    trace("SignerInfo");
    let signer = &sd.certs[si.index];
    let key = signer.public_key()?;
    // MIT's KDC before 1.22 labels ECDSA signatures sha256WithRSAEncryption; OpenSSL goes by the
    // signer's key, and so does this. The signature must still verify under that key.
    let alg = match (&key, si.alg) {
        (PublicKey::Ec(_), SigAlg::Rsa(h)) => SigAlg::Ecdsa(h),
        _ => si.alg,
    };
    let signed = der::tlv(asn1::SET, si.attrs);
    if !key.verify(alg, &si.hash.digest(&signed), &si.signature) {
        return err("SignedData signature does not verify");
    }
    let path = x509::verify_chain(signer, &sd.certs, anchors, now)?;
    crl::check_chain(&path, revocation, &sd.crls, now)?;
    Ok(Verified {
        content: sd.content,
        signer: signer.clone(),
    })
}

/// A `SignedData` opened far enough to know what it signs, who signed it, and what travelled with
/// the signature.
struct SignedData<'a> {
    content: Vec<u8>,
    certs: Vec<Cert>,
    crls: Vec<crl::Crl>,
    /// The single `SignerInfo`, as it arrived: tag and length included.
    signer: &'a [u8],
}

/// Reads the `SignedData` fields in the order the structure gives them.
///
/// `version` and `digestAlgorithms` are read and dropped: every signer names its own digest, so the
/// set at this level says nothing a verifier may rely on — an implementation that trusted it would
/// accept a signature whose digest was never listed.
fn open_signed_data<'a>(data: &'a [u8], content_type: &str) -> Result<SignedData<'a>> {
    let mut sd = Reader::new(signed_data_content(data)?).seq()?;
    sd.int()?; // version
    sd.expect(asn1::SET)?; // digestAlgorithms
    trace("digestAlgorithms");
    let content = encapsulated_content(&mut sd, content_type)?;
    let (certs, crls) = context(&mut sd)?;
    let signer = single_signer(&mut sd)?;
    Ok(SignedData {
        content,
        certs,
        crls,
        signer,
    })
}

/// The certificates and revocation lists that travelled with the signature.
///
/// `crls [1] IMPLICIT SET OF RevocationInfoChoice` also admits `OtherRevocationInfoFormat`, which
/// is skipped on the same terms as the certificate choices: neither can revoke anything here.
fn context<'a>(sd: &mut Reader<'a>) -> Result<(Vec<Cert>, Vec<crl::Crl>)> {
    let certs = match sd.optional(der::ctx(0))? {
        None => Vec::new(),
        Some(set) => certificates(set)?,
    };
    let crls = match sd.optional(der::ctx(1))? {
        None => Vec::new(),
        Some(set) => revocation_lists(set)?,
    };
    trace("certificates and crls");
    Ok((certs, crls))
}

/// The content type a `SignedData` claims and the octets it holds.
fn encapsulated_content(sd: &mut Reader<'_>, content_type: &str) -> Result<Vec<u8>> {
    let mut encap = sd.seq()?;
    if encap.oid()? != asn1::oid(content_type).as_slice() {
        return err("SignedData carries the wrong content type");
    }
    trace("eContentType");
    let content = Reader::new(encap.expect(der::ctx(0))?).octets()?.to_vec();
    encap.done("EncapsulatedContentInfo")?;
    Ok(content)
}

/// The certificates sent with the signature: plain ones only.
///
/// `CertificateChoices` also admits extended and attribute certificates; neither carries a key that
/// can verify a `SignerInfo`, so they are skipped rather than refused.
fn certificates(set: &[u8]) -> Result<Vec<Cert>> {
    let mut certs = Vec::new();
    let mut r = Reader::new(set);
    while !r.is_empty() {
        let (tag, _, raw) = r.next_raw()?;
        if tag == der::SEQUENCE {
            certs.push(Cert::from_der(raw)?);
        }
    }
    Ok(certs)
}

/// The `CertificateList`s sent with the signature, on the same terms as [`certificates`].
fn revocation_lists(set: &[u8]) -> Result<Vec<crl::Crl>> {
    let mut crls = Vec::new();
    let mut r = Reader::new(set);
    while !r.is_empty() {
        let (tag, _, raw) = r.next_raw()?;
        if tag == der::SEQUENCE {
            crls.push(crl::Crl::from_der(raw)?);
        }
    }
    Ok(crls)
}

/// The `signerInfos` set, which must hold exactly one `SignerInfo`.
///
/// One, because this crate verifies one signer: a message with two is refused rather than half
/// verified, and a message with none says who signed it nowhere.
fn single_signer<'a>(sd: &mut Reader<'a>) -> Result<&'a [u8]> {
    let mut infos = Reader::new(sd.expect(asn1::SET)?);
    sd.done("SignedData")?;
    if infos.is_empty() {
        return err("SignedData has no signer");
    }
    let (tag, _, raw) = infos.next_raw()?;
    if tag != der::SEQUENCE {
        return err("SignerInfo is not a SEQUENCE");
    }
    if !infos.is_empty() {
        return err("SignedData with more than one signer");
    }
    Ok(raw)
}

/// What one `SignerInfo` says: which certificate signed, with what, and over which attributes.
struct SignerInfo<'a> {
    /// The index of the signer's certificate in the set the message carried.
    index: usize,
    hash: Hash,
    alg: SigAlg,
    /// The signed attributes, still encoded as a SET OF — the octets the signature covers.
    attrs: &'a [u8],
    signature: Vec<u8>,
}

/// Reads a `SignerInfo` and checks the attributes it states against the content.
///
/// The attribute check lives here rather than after the caller has the parts, because a signature
/// that verifies over attributes which do not name this content proves only that somebody holding
/// the key signed something — not that they signed this.
fn signer_info<'a>(
    certs: &[Cert],
    signer: &'a [u8],
    content_type: &str,
    content: &[u8],
) -> Result<SignerInfo<'a>> {
    let mut si = Reader::new(signer).seq()?;
    si.int()?; // version
    // `SignerIdentifier ::= CHOICE { issuerAndSerialNumber SEQUENCE, subjectKeyIdentifier [0] }`.
    // Heimdal signs with the key identifier and MIT with the issuer and serial — both are legal,
    // and a verifier that knows only one of them interops with only one of them.
    let (sid_tag, sid) = si.next()?;
    let index = signer_of(certs, sid_tag, sid)?;
    trace("sid");
    let (digest_oid, _) = si.alg_id()?;
    let hash = Hash::from_oid(digest_oid)
        .ok_or_else(|| DerError("unsupported SignedData digest algorithm".into()))?;
    let attrs = si
        .optional(der::ctx(0))?
        .ok_or_else(|| DerError("SignedData without signed attributes".into()))?;
    let (sig_oid, _) = si.alg_id()?;
    let alg = signature_alg(sig_oid, hash)?;
    let signature = si.octets()?.to_vec();
    si.optional(der::ctx(1))?; // unsignedAttrs
    si.done("SignerInfo")?;
    signed_attributes(attrs, content_type, content, hash)?;
    Ok(SignerInfo {
        index,
        hash,
        alg,
        attrs,
        signature,
    })
}

/// Which certificate in the set is the signer, by either identifier the RFC allows.
fn signer_of(certs: &[Cert], tag: u8, sid: &[u8]) -> Result<usize> {
    match tag {
        der::SEQUENCE => signer_by_serial(certs, sid),
        t if t == asn1::implicit(0) || t == der::ctx(0) => signer_by_key_id(certs, t, sid),
        _ => err("unsupported SignerIdentifier in SignedData"),
    }
}

/// The signer named by issuer and serial number.
fn signer_by_serial(certs: &[Cert], sid: &[u8]) -> Result<usize> {
    let mut sid = Reader::new(sid);
    // The issuer is compared as the whole `Name` TLV, the serial as the INTEGER's content.
    let issuer = sid.next_raw()?.2;
    let serial = sid.expect(der::INTEGER)?;
    sid.done("IssuerAndSerialNumber")?;
    certs
        .iter()
        .position(|c| c.issuer == issuer && c.serial == serial)
        .ok_or_else(|| DerError("SignedData does not include the signer's certificate".into()))
}

/// The signer named by `SubjectKeyIdentifier`.
///
/// `SubjectKeyIdentifier ::= OCTET STRING`, and a `[0]` choice around it is written either
/// implicitly (primitive, the content is the key) or, as Heimdal writes it, constructed with the
/// OCTET STRING inside.
fn signer_by_key_id(certs: &[Cert], tag: u8, sid: &[u8]) -> Result<usize> {
    let key = if tag == der::ctx(0) {
        Reader::new(sid).octets()?
    } else {
        sid
    };
    certs
        .iter()
        .position(|c| c.subject_key_id() == Some(key))
        .ok_or_else(|| {
            DerError(
                "SignedData does not include the certificate with the signer's key identifier"
                    .into(),
            )
        })
}

/// The signature algorithm, which has to agree with the digest the signer named.
///
/// A signature algorithm naming its own hash and a digest algorithm naming a different one is not a
/// message to reconcile: one of the two is wrong, and verifying with either is guessing.
fn signature_alg(oid: &[u8], hash: Hash) -> Result<SigAlg> {
    match SigAlg::from_oid(oid) {
        Some(a) if a.hash() == hash => Ok(a),
        None if oid == asn1::oid(rsa::RSA_ENCRYPTION).as_slice() => Ok(SigAlg::Rsa(hash)),
        _ => err("unsupported or inconsistent SignedData signature algorithm"),
    }
}

/// Checks the two attributes a signer has to state: the content type it signed, and the digest of
/// that content.
#[derive(Default)]
struct SignedAttrs {
    content_type: bool,
    digest: bool,
}

fn signed_attributes(attrs: &[u8], content_type: &str, content: &[u8], hash: Hash) -> Result<()> {
    let mut check = SignedAttrs::default();
    let mut a = Reader::new(attrs);
    while !a.is_empty() {
        check.take(&mut a, content_type, content, hash)?;
    }
    check.pass()
}

impl SignedAttrs {
    /// Reads one attribute and records what it settles, if anything.
    fn take(
        &mut self,
        a: &mut Reader<'_>,
        content_type: &str,
        content: &[u8],
        hash: Hash,
    ) -> Result<()> {
        let (oid, tag, value) = single_attribute(a)?;
        if oid == asn1::oid(ATTR_CONTENT_TYPE) {
            self.content_type = tag == asn1::OID && value == asn1::oid(content_type);
        } else if oid == asn1::oid(ATTR_MESSAGE_DIGEST) {
            self.digest = tag == der::OCTET_STRING && value == hash.digest(content);
        }
        Ok(())
    }

    /// Both attributes were found and both matched.
    fn pass(self) -> Result<()> {
        if self.content_type && self.digest {
            return Ok(());
        }
        err("SignedData's signed attributes do not match its content")
    }
}

/// One `Attribute`: its type, and the tag and value of its single value.
///
/// One value, because the RFC makes `SET OF AttributeValue` and every attribute this verifier reads
/// is defined with one: an attribute with two would leave which one was signed undecided.
fn single_attribute<'a>(a: &mut Reader<'a>) -> Result<(&'a [u8], u8, &'a [u8])> {
    let mut attr = a.seq()?;
    let oid = attr.oid()?;
    let mut values = Reader::new(attr.expect(asn1::SET)?);
    attr.done("Attribute")?;
    let (tag, value) = values.next()?;
    if !values.is_empty() {
        return err("a signed attribute with more than one value");
    }
    Ok((oid, tag, value))
}

// Test fixtures that a sibling crate builds its own scenarios from. Behind a feature and
// not `cfg(test)`, because `cfg(test)` applies to this crate's build only — a consumer's
// tests compile this crate as a dependency and would not see them.
#[cfg(any(test, feature = "test-support"))]
pub mod tests {
    use super::*;
    use crate::pkcs::pem;
    // `NOW` is used only by the `#[test]` functions below, which are compiled out when this module
    // is built for a consumer through the `test-support` feature — hence the allow, rather than a
    // split of the fixture set into two modules that would then have to be kept in step.
    #[allow(unused_imports)]
    use crate::pkcs::x509::tests::{NOW, fixture};

    pub fn kdc_key() -> PrivateKey {
        PrivateKey::from_pem_blocks(&pem::blocks(include_bytes!("testdata/kdc-key.pem")).unwrap())
            .unwrap()
    }

    /// `sd` with a `crls` field holding `crls`, as a KDC may send them.
    pub fn with_crls(sd: &[u8], crls: &[Vec<u8>]) -> Vec<u8> {
        let mut ci = Reader::new(sd).seq().unwrap();
        let oid = ci.next_raw().unwrap().2.to_vec();
        let mut s = Reader::new(ci.expect(der::ctx(0)).unwrap()).seq().unwrap();
        let mut parts = vec![];
        while !s.is_empty() {
            parts.push(s.next_raw().unwrap().2.to_vec());
        }
        let infos = parts.pop().unwrap();
        parts.push(der::cons(der::ctx(1), crls));
        parts.push(infos);
        der::seq(&[oid, der::field(0, der::seq(&parts))])
    }

    /// The KDC's CRLs count with ours: ca-crl.pem revokes the
    /// intermediate its certificate is under.
    #[test]
    fn crls_the_kdc_sends_are_checked() {
        let ca = [fixture("ca")];
        let crl = pem::blocks(include_bytes!("testdata/ca-crl.pem"))
            .unwrap()
            .remove(0)
            .1;
        let sd = kdc_signed(ID_PKINIT_DHKEY_DATA, b"key info");
        verify(&sd, ID_PKINIT_DHKEY_DATA, &ca, crl::Policy::default(), NOW).unwrap();
        let sent = with_crls(&sd, &[crl]);
        let e = verify(
            &sent,
            ID_PKINIT_DHKEY_DATA,
            &ca,
            crl::Policy::default(),
            NOW,
        )
        .unwrap_err();
        assert!(e.0.contains("depth 1 of the KDC's chain: revoked"), "{e}");
        // Not a CRL: the SignedData is malformed.
        let junk = with_crls(&sd, &[der::seq(&[der::int(1)])]);
        verify(
            &junk,
            ID_PKINIT_DHKEY_DATA,
            &ca,
            crl::Policy::default(),
            NOW,
        )
        .unwrap_err();
        // Required: no CRL from the intermediate for the KDC's certificate.
        let required = crl::Policy {
            local: &[],
            require: true,
        };
        let e = verify(&sd, ID_PKINIT_DHKEY_DATA, &ca, required, NOW).unwrap_err();
        assert!(
            e.0.contains("depth 0") && e.0.contains("pkinit_require_crl_checking"),
            "{e}"
        );
    }

    /// An EnvelopedData made by OpenSSL, not by this crate:
    ///
    /// ```text
    /// printf 'the transport reply key' > content.bin
    /// openssl cms -encrypt -aes256 -binary -in content.bin -outform DER \
    ///     -out openssl-enveloped.der src/pkinit/testdata/kdc.pem
    /// ```
    ///
    /// A CMS envelope is only useful if it opens the ones other implementations write, and this is
    /// the one fixture in the tree that pins that: the recipient is `IssuerAndSerialNumber` of
    /// kdc.pem, the content encryption is aes-256-cbc with the IV in the parameters, and the padding
    /// is PKCS #7.
    #[test]
    fn an_envelope_from_openssl_opens() {
        let cert = fixture("kdc");
        let key = kdc_key().rsa().expect("an RSA test key");
        let (content_type, content) = decrypt_enveloped(
            include_bytes!("testdata/openssl-enveloped.der"),
            &key,
            &cert,
        )
        .unwrap();
        assert_eq!(content_type, asn1::oid("1.2.840.113549.1.7.1"));
        assert_eq!(content, b"the transport reply key");
        // And the same envelope for another certificate is refused rather than attempted.
        let e = decrypt_enveloped(
            include_bytes!("testdata/openssl-enveloped.der"),
            &key,
            &fixture("host"),
        )
        .unwrap_err();
        assert!(e.0.contains("another certificate"), "{e}");
    }

    /// A `SignedData` Heimdal 7.8.0 put inside the `encKeyPack` it answered our PKINIT request
    /// with, taken from a live run of `scripts/live.sh` (`KRB5_STAND=heimdal`). It is here because
    /// it differs from ours in three ways at once, and each one was a refusal until it was handled:
    ///
    /// * it is a **bare** `SignedData`, not a `ContentInfo` around one — CMS asks for the value of
    ///   the encapsulated type, which for `id-signedData` is the `SignedData` itself;
    /// * its `SignerIdentifier` is the **subjectKeyIdentifier** choice, written constructed
    ///   (`a0 16 04 14 …`), while MIT and this crate write `IssuerAndSerialNumber`;
    /// * it is signed with **SHA-1** (`sha1WithRSAEncryption`), whatever `supportedCMSTypes` the
    ///   client offered.
    ///
    /// The signature does not verify against this crate's test CA — the stand's CA signed it, with
    /// dates of the run that made it — so the assertion is about how far the parse gets: an OID,
    /// digest or identifier problem is reported before the chain is looked at, and a chain problem
    /// is the one failure that says the structure was understood.
    #[test]
    fn a_signed_data_heimdal_wrote_is_understood() {
        let e = verify(
            include_bytes!("testdata/heimdal-rkey-signeddata.der"),
            ID_PKINIT_RKEY_DATA,
            &[fixture("ca")],
            crl::Policy::default(),
            NOW,
        )
        .expect_err("another trust anchor");
        // The stand's certificates are dated by the run that made them, so this is the anchor or
        // the clock; both come after the parse, which is the point.
        assert!(e.0.contains("chain") || e.0.contains("anchor"), "{e}");
        // And with the wrong content type it is refused earlier, which shows the OID was read.
        let e = verify(
            include_bytes!("testdata/heimdal-rkey-signeddata.der"),
            ID_PKINIT_DHKEY_DATA,
            &[fixture("ca")],
            crl::Policy::default(),
            NOW,
        )
        .expect_err("the wrong content type");
        assert!(e.0.contains("wrong content type"), "{e}");
    }

    /// What this crate writes is what OpenSSL reads: the reverse of the test above, as a
    /// round trip through the same fixed key.
    #[test]
    fn an_envelope_this_crate_writes_opens_with_our_own_decoder() {
        let cert = fixture("kdc");
        let key = kdc_key().rsa().expect("an RSA test key");
        let content = b"a reply key pack, signed and then enveloped";
        let env = enveloped_data(ID_PKINIT_RKEY_DATA, content, &cert).unwrap();
        let (content_type, got) = decrypt_enveloped(&env, &key, &cert).unwrap();
        assert_eq!(content_type, asn1::oid(ID_PKINIT_RKEY_DATA));
        assert_eq!(got, content);
        // A message tampered with in the ciphertext fails the padding check, not the RSA one.
        let mut bad = env.clone();
        let n = bad.len();
        bad[n - 20] ^= 0xff;
        assert!(decrypt_enveloped(&bad, &key, &cert).is_err());
    }

    /// A SignedData as the test KDC would sign it, with its chain.
    pub fn kdc_signed(content_type: &str, content: &[u8]) -> Vec<u8> {
        let key = kdc_key();
        let certs = [fixture("kdc"), fixture("inter")];
        signed_data(
            content_type,
            content,
            Some(Signer {
                key: &key,
                certs: &certs,
            }),
        )
        .unwrap()
    }

    #[test]
    fn a_signed_data_verifies_to_its_anchor() {
        let sd = kdc_signed(ID_PKINIT_DHKEY_DATA, b"key info");
        let v = verify(
            &sd,
            ID_PKINIT_DHKEY_DATA,
            &[fixture("ca")],
            crl::Policy::default(),
            NOW,
        )
        .unwrap();
        assert_eq!(v.content, b"key info");
        assert_eq!(v.signer, fixture("kdc"));
    }

    #[test]
    fn a_signed_data_is_refused_for_any_flaw() {
        let sd = kdc_signed(ID_PKINIT_DHKEY_DATA, b"key info");
        let ca = [fixture("ca")];
        // The wrong content type expected; an untrusted anchor.
        assert!(verify(&sd, ID_PKINIT_AUTH_DATA, &ca, crl::Policy::default(), NOW).is_err());
        assert!(
            verify(
                &sd,
                ID_PKINIT_DHKEY_DATA,
                &[fixture("other-ca")],
                crl::Policy::default(),
                NOW
            )
            .is_err()
        );
        // The content altered after signing: the digest no longer matches.
        let mut bad = sd.clone();
        let at = bad.windows(8).position(|w| w == b"key info").unwrap();
        bad[at] = b'K';
        let e = verify(&bad, ID_PKINIT_DHKEY_DATA, &ca, crl::Policy::default(), NOW).unwrap_err();
        assert!(e.0.contains("signed attributes"), "{e}");
        // The signature altered: its last octet sits at the very end.
        let mut bad = sd.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        let e = verify(&bad, ID_PKINIT_DHKEY_DATA, &ca, crl::Policy::default(), NOW).unwrap_err();
        assert!(e.0.contains("signature"), "{e}");
        // No signer at all, as an anonymous client sends.
        let unsigned = signed_data(ID_PKINIT_DHKEY_DATA, b"key info", None).unwrap();
        assert!(
            verify(
                &unsigned,
                ID_PKINIT_DHKEY_DATA,
                &ca,
                crl::Policy::default(),
                NOW
            )
            .is_err()
        );
        // Without the intermediate the chain is incomplete; naming a
        // signer whose key did not sign fails the signature.
        let key = kdc_key();
        let sign = |certs: &[Cert]| {
            signed_data(
                ID_PKINIT_DHKEY_DATA,
                b"key info",
                Some(Signer { key: &key, certs }),
            )
            .unwrap()
        };
        let e = verify(
            &sign(&[fixture("kdc")]),
            ID_PKINIT_DHKEY_DATA,
            &ca,
            crl::Policy::default(),
            NOW,
        )
        .unwrap_err();
        assert!(e.0.contains("anchor"), "{e}");
        let e = verify(
            &sign(&[fixture("inter"), fixture("kdc")]),
            ID_PKINIT_DHKEY_DATA,
            &ca,
            crl::Policy::default(),
            NOW,
        )
        .unwrap_err();
        assert!(e.0.contains("signature"), "{e}");
        for cut in [0, 10, sd.len() / 2, sd.len() - 1] {
            assert!(
                verify(
                    &sd[..cut],
                    ID_PKINIT_DHKEY_DATA,
                    &ca,
                    crl::Policy::default(),
                    NOW
                )
                .is_err()
            );
        }
    }

    /// A reply recorded from MIT 1.21's KDC with a P-256 key: ECDSA
    /// signed, but labelled sha256WithRSAEncryption, as MIT's KDC labels
    /// every signature before 1.22. Checked at a time its 2026–2027
    /// certificate is valid.
    #[test]
    fn mit_1_21s_mislabelled_ecdsa_signature_verifies_as_openssl_verifies_it() {
        let sd = include_bytes!("testdata/mit121-ec-kdc-signeddata.der");
        let ca = crate::pkcs::x509::parse_certs(include_bytes!("testdata/mit121-ca.pem")).unwrap();
        let rsa_label = der::tlv(asn1::OID, &asn1::oid("1.2.840.113549.1.1.11"));
        assert!(sd.windows(rsa_label.len()).any(|w| w == rsa_label));
        let v = verify(
            sd,
            ID_PKINIT_DHKEY_DATA,
            &ca,
            crl::Policy::default(),
            1_792_100_000,
        )
        .unwrap();
        assert!(matches!(v.signer.public_key().unwrap(), PublicKey::Ec(_)));
        // Any alteration of the signed content still fails.
        let mut bad = sd.to_vec();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(
            verify(
                &bad,
                ID_PKINIT_DHKEY_DATA,
                &ca,
                crl::Policy::default(),
                1_792_100_000
            )
            .is_err()
        );
    }

    #[test]
    fn the_anonymous_content_info_holds_the_auth_pack() {
        let ci = content_info(ID_PKINIT_AUTH_DATA, b"auth pack");
        let mut r = Reader::new(&ci);
        let mut s = r.seq().unwrap();
        assert_eq!(s.oid().unwrap(), asn1::oid(ID_PKINIT_AUTH_DATA));
        let mut c = Reader::new(s.expect(der::ctx(0)).unwrap());
        assert_eq!(c.octets().unwrap(), b"auth pack");
    }
}
