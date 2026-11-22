//! Just enough X.509 (RFC 5280) for PKINIT: parse a certificate, build
//! and check its chain to a trust anchor, and read its subjectAltName and
//! extendedKeyUsage.
//!
//! Chain building follows issuer names (compared as DER octets) through
//! the certificates at hand, checking each signature, validity period,
//! CA flag, `keyCertSign` and path length on the way. A critical
//! extension this module does not understand fails the chain, as RFC 5280
//! §4.2 requires. Revocation is the CRL module's (`super::crl`), over the
//! path [`verify_chain`] returns.
//!
//! Nothing here knows what a Kerberos principal is: `id-pkinit-san` names one, and the payload is
//! handed out as raw DER for the crate that has the type (see [`Cert::kerberos_alt_names`]).

use super::asn1::{self, ReaderExt, implicit};
use super::keys::{PublicKey, SigAlg};
use crate::der::{self, DerError, Fields, Reader};

type Result<T> = std::result::Result<T, DerError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";
const EXT_KEY_USAGE: &str = "2.5.29.37";
const SUBJECT_KEY_ID: &str = "2.5.29.14";
const SUBJECT_ALT_NAME: &str = "2.5.29.17";
/// Extensions that may be critical without failing the chain: the ones
/// read here, and the key identifiers, which only help chain building.
const UNDERSTOOD: [&str; 6] = [
    BASIC_CONSTRAINTS,
    KEY_USAGE,
    EXT_KEY_USAGE,
    SUBJECT_ALT_NAME,
    SUBJECT_KEY_ID,
    "2.5.29.35", // authorityKeyIdentifier
];

/// `id-pkinit-san` (RFC 4556 §3.2.2): a KRB5PrincipalName otherName.
pub const ID_PKINIT_SAN: &str = "1.3.6.1.5.2.2";
/// `id-pkinit-KPKdc` and `id-pkinit-KPClientAuth` (RFC 4556 §3.2.4, §3.2.2).
pub const ID_PKINIT_KP_KDC: &str = "1.3.6.1.5.2.3.5";

/// keyUsage bits (RFC 5280 §4.2.1.3), numbered from the MSB.
pub const KU_DIGITAL_SIGNATURE: u32 = 0;
const KU_KEY_CERT_SIGN: u32 = 5;

/// How many CA certificates a chain may pass through.
const MAX_DEPTH: usize = 8;

/// A parsed certificate. The raw parts are kept as DER for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    pub der: Vec<u8>,
    tbs: Vec<u8>,
    sig_alg: Vec<u8>,
    signature: Vec<u8>,
    /// The serial number INTEGER's content octets.
    pub serial: Vec<u8>,
    /// The issuer and subject Names, whole TLVs.
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    not_before: i64,
    not_after: i64,
    /// SubjectPublicKeyInfo: the algorithm OID, its parameters and the
    /// BIT STRING content.
    key_alg: Vec<u8>,
    key_params: Option<Vec<u8>>,
    key: Vec<u8>,
    extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Extension {
    pub(super) oid: Vec<u8>,
    pub(super) critical: bool,
    pub(super) value: Vec<u8>,
}

/// `Extensions ::= SEQUENCE OF Extension`, from the SEQUENCE's encoding.
/// An extension may appear only once (RFC 5280 §4.2, §5.2).
pub(super) fn read_extensions(exts: &[u8]) -> Result<Vec<Extension>> {
    let mut extensions: Vec<Extension> = Vec::new();
    let mut seq = Reader::new(exts).seq()?;
    while !seq.is_empty() {
        let x = read_extension(&mut seq)?;
        // RFC 5280: an extension appears at most once, and a second copy is not a repeated
        // statement but a file that says two different things.
        if extensions.iter().any(|e| e.oid == x.oid) {
            return err("an extension appears twice");
        }
        extensions.push(x);
    }
    Ok(extensions)
}

/// One `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`.
fn read_extension(seq: &mut Reader<'_>) -> Result<Extension> {
    let mut e = seq.seq()?;
    let oid = e.oid()?.to_vec();
    let critical = critical_of(&mut e)?;
    let value = e.octets()?.to_vec();
    e.done("Extension")?;
    Ok(Extension {
        oid,
        critical,
        value,
    })
}

/// The `critical` flag, which DER leaves out when it is false.
///
/// An explicit `FALSE` is refused rather than read as false: DER says a default value is never
/// encoded, so a file that writes it was produced by something that does not follow DER, and the
/// rest of its encoding cannot be trusted either.
fn critical_of(e: &mut Reader<'_>) -> Result<bool> {
    match e.optional(asn1::BOOLEAN)? {
        Some([0xFF]) => Ok(true),
        Some([0x00]) => err("DEFAULT FALSE encoded (not DER)"),
        Some(_) => err("bad BOOLEAN"),
        None => Ok(false),
    }
}

/// The two fields that come before the names: the version, which the extensions are gated on, and
/// the serial, which is what a CRL revokes.
struct Head {
    version: i64,
    serial: Vec<u8>,
}

fn head(t: &mut Reader<'_>, sig_alg: &[u8]) -> Result<Head> {
    let version = version(t)?;
    let serial = t.expect(der::INTEGER)?.to_vec();
    same_algorithm(t, sig_alg)?;
    Ok(Head { version, serial })
}

/// Everything from the issuer's name to the extensions.
struct Body {
    issuer: Vec<u8>,
    subject: Vec<u8>,
    not_before: i64,
    not_after: i64,
    key: Spki,
    extensions: Vec<Extension>,
}

fn body(t: &mut Reader<'_>, version: i64) -> Result<Body> {
    let issuer = t.next_raw()?.2.to_vec();
    let (not_before, not_after) = validity(t)?;
    let subject = t.next_raw()?.2.to_vec();
    let key = public_key(t)?;
    skip_unique_ids(t)?;
    let extensions = read_cert_extensions(t, version)?;
    t.done("TBSCertificate")?;
    Ok(Body {
        issuer,
        subject,
        not_before,
        not_after,
        key,
        extensions,
    })
}

/// The three parts a certificate is signed over, and the signature itself.
struct SignedPart<'a> {
    /// The content of `tbsCertificate`.
    tbs_content: &'a [u8],
    /// `tbsCertificate` whole, tag and length included: what a verifier hashes.
    tbs: &'a [u8],
    sig_alg: &'a [u8],
    signature: Vec<u8>,
}

/// Splits a `Certificate` into the signed part and the signature around it.
fn signed_part(der: &[u8]) -> Result<SignedPart<'_>> {
    let mut outer = Reader::new(der);
    let mut c = outer.seq()?;
    outer.done("Certificate")?;
    let (_, tbs_content, tbs) = c.next_raw()?;
    let (sig_alg, _) = c.alg_id()?;
    let signature = c.bits()?.to_vec();
    c.done("Certificate")?;
    Ok(SignedPart {
        tbs_content,
        tbs,
        sig_alg,
        signature,
    })
}

/// The version, which is `[0] EXPLICIT INTEGER` and absent in a v1 certificate.
fn version(t: &mut Reader<'_>) -> Result<i64> {
    match t.optional(der::ctx(0))? {
        Some(v) => Reader::new(v).int(),
        None => Ok(0),
    }
}

/// A certificate states its signature algorithm twice, and the two are one statement: a
/// certificate where they differ is one nobody can check, so it is refused rather than guessed at.
fn same_algorithm(t: &mut Reader<'_>, sig_alg: &[u8]) -> Result<()> {
    let (inner, _) = t.alg_id()?;
    if inner == sig_alg {
        return Ok(());
    }
    err("certificate signature algorithms disagree")
}

/// `Validity ::= SEQUENCE { notBefore, notAfter }`.
fn validity(t: &mut Reader<'_>) -> Result<(i64, i64)> {
    let mut v = t.seq()?;
    let not_before = read_time(&mut v)?;
    let not_after = read_time(&mut v)?;
    v.done("Validity")?;
    Ok((not_before, not_after))
}

/// The subject's public key, as `SubjectPublicKeyInfo` states it.
struct Spki {
    alg: Vec<u8>,
    params: Option<Vec<u8>>,
    key: Vec<u8>,
}

fn public_key(t: &mut Reader<'_>) -> Result<Spki> {
    let mut spki = t.seq()?;
    let (alg, params) = spki.alg_id()?;
    let key = spki.bits()?.to_vec();
    spki.done("SubjectPublicKeyInfo")?;
    Ok(Spki {
        alg: alg.to_vec(),
        params: params.map(<[u8]>::to_vec),
        key,
    })
}

/// `issuerUniqueID` and `subjectUniqueID`, which nothing here reads and which RFC 5280 retired.
fn skip_unique_ids(t: &mut Reader<'_>) -> Result<()> {
    t.optional(implicit(1))?;
    t.optional(implicit(2))?;
    Ok(())
}

/// The certificate's extensions, which only a v3 certificate may carry.
fn read_cert_extensions(t: &mut Reader<'_>, version: i64) -> Result<Vec<Extension>> {
    let Some(exts) = t.optional(der::ctx(3))? else {
        return Ok(Vec::new());
    };
    if version != 2 {
        return err("extensions in a certificate before v3");
    }
    read_extensions(exts)
}

impl Cert {
    /// ```text
    /// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature BIT STRING }
    /// TBSCertificate ::= SEQUENCE {
    ///     version [0] EXPLICIT DEFAULT v1, serialNumber, signature AlgorithmIdentifier,
    ///     issuer Name, validity SEQUENCE { notBefore, notAfter }, subject Name,
    ///     subjectPublicKeyInfo, issuerUniqueID [1] IMPLICIT OPTIONAL,
    ///     subjectUniqueID [2] IMPLICIT OPTIONAL, extensions [3] EXPLICIT OPTIONAL }
    /// ```
    pub fn from_der(der: &[u8]) -> Result<Cert> {
        let part = signed_part(der)?;
        let mut t = Reader::new(part.tbs_content);
        let head = head(&mut t, part.sig_alg)?;
        let body = body(&mut t, head.version)?;
        Ok(Cert {
            der: der.to_vec(),
            tbs: part.tbs.to_vec(),
            sig_alg: part.sig_alg.to_vec(),
            signature: part.signature,
            serial: head.serial,
            issuer: body.issuer,
            subject: body.subject,
            not_before: body.not_before,
            not_after: body.not_after,
            key_alg: body.key.alg,
            key_params: body.key.params,
            key: body.key.key,
            extensions: body.extensions,
        })
    }

    pub(super) fn extension(&self, dotted: &str) -> Option<&Extension> {
        let oid = asn1::oid(dotted);
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// The subject's public key, RSA or EC.
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki(&self.key_alg, self.key_params.as_deref(), &self.key)
    }

    /// Whether `issuer`'s key made this certificate's signature.
    fn signed_by(&self, issuer: &Cert) -> bool {
        issuer.made(&self.sig_alg, &self.tbs, &self.signature)
    }

    /// Whether this certificate's key made `signature` over `tbs` with
    /// `sig_alg`.
    pub(super) fn made(&self, sig_alg: &[u8], tbs: &[u8], signature: &[u8]) -> bool {
        let Some(alg) = SigAlg::from_oid(sig_alg) else {
            return false;
        };
        self.public_key()
            .is_ok_and(|k| k.verify(alg, &alg.hash().digest(tbs), signature))
    }

    /// Whether basicConstraints makes this a CA.
    pub(super) fn is_ca(&self) -> bool {
        self.basic_constraints().is_ok_and(|(ca, _)| ca)
    }

    /// `basicConstraints`: (cA, pathLenConstraint).
    fn basic_constraints(&self) -> Result<(bool, Option<i64>)> {
        let Some(e) = self.extension(BASIC_CONSTRAINTS) else {
            return Ok((false, None));
        };
        let mut r = Reader::new(&e.value);
        let mut s = r.seq()?;
        let ca = matches!(s.optional(asn1::BOOLEAN)?, Some([0xFF]));
        let len = if s.is_empty() { None } else { Some(s.int()?) };
        Ok((ca, len))
    }

    /// Whether keyUsage is present and asserts bit `bit`.
    pub fn key_usage(&self, bit: u32) -> Result<Option<bool>> {
        let Some(e) = self.extension(KEY_USAGE) else {
            return Ok(None);
        };
        let c = Reader::new(&e.value).expect(der::BIT_STRING)?;
        let byte = 1 + (bit / 8) as usize;
        Ok(Some(
            c.get(byte).is_some_and(|b| b & (0x80 >> (bit % 8)) != 0),
        ))
    }

    /// The subjectKeyIdentifier extension's key, if it has one: what a CMS
    /// `SignerIdentifier` names the signer by when it uses the `[0]` choice.
    pub fn subject_key_id(&self) -> Option<&[u8]> {
        let e = self.extension(SUBJECT_KEY_ID)?;
        let mut r = Reader::new(&e.value);
        r.octets().ok()
    }

    /// Whether extendedKeyUsage lists `dotted`.
    pub fn has_eku(&self, dotted: &str) -> Result<bool> {
        let Some(e) = self.extension(EXT_KEY_USAGE) else {
            return Ok(false);
        };
        let want = asn1::oid(dotted);
        let mut s = Reader::new(&e.value).seq()?;
        while !s.is_empty() {
            if s.oid()? == want {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The subjectAltName's Kerberos-relevant entries: the payload of every `id-pkinit-san`
    /// otherName as raw DER, and the dNSNames as text.
    ///
    /// ```text
    /// GeneralName ::= CHOICE { otherName [0] IMPLICIT SEQUENCE {
    ///     type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }, ...,
    ///     dNSName [2] IMPLICIT IA5String, ... }
    /// KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }
    /// ```
    ///
    /// The payload is handed out untouched because a `KRB5PrincipalName` names a principal, and a
    /// principal is not a thing this crate has: the decode lives beside the type. Everything else
    /// about a certificate — the chain, the validity, the usage bits — needs no such knowledge and
    /// is checked here.
    pub fn kerberos_alt_names(&self) -> Result<(Vec<Vec<u8>>, Vec<String>)> {
        let (mut principals, mut dns) = (Vec::new(), Vec::new());
        let Some(e) = self.extension(SUBJECT_ALT_NAME) else {
            return Ok((principals, dns));
        };
        let mut names = Reader::new(&e.value).seq()?;
        while !names.is_empty() {
            match names.next()? {
                (t, c) if is_other_name(t) => {
                    if let Some(p) = principal_of(c)? {
                        principals.push(p);
                    }
                }
                (t, c) if t == implicit(2) => dns.push(String::from_utf8_lossy(c).into_owned()),
                // RFC 4556 §3.2.2 defines one otherName; every other GeneralName is somebody
                // else's and is skipped rather than refused.
                _ => {}
            }
        }
        Ok((principals, dns))
    }
}

/// Whether this `GeneralName` tag is an `otherName`.
///
/// `[0] IMPLICIT OtherName`, and `OtherName` is a SEQUENCE — so the tag is constructed, `0xA0`.
/// A primitive `0x80` would be an encoding no writer produces for this field, and reading it would
/// mean parsing a SEQUENCE's content as if it were one.
fn is_other_name(tag: u8) -> bool {
    tag == der::ctx(0)
}

/// The `KRB5PrincipalName` this `otherName` holds, as the content of its SEQUENCE.
///
/// `otherName.value` is `[0] EXPLICIT`, and what it wraps is the `KRB5PrincipalName` SEQUENCE. What
/// is handed out is that SEQUENCE's content — the two fields, without tag and length — because that
/// is the shape the decoder beside `Principal` takes (`Fields::parse`). It is parsed here once so
/// that a malformed one does not travel to whoever asked.
///
/// An `otherName` naming another OID is not a Kerberos principal and yields nothing.
fn principal_of(other_name: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut on = Reader::new(other_name);
    if on.oid()? != asn1::oid(ID_PKINIT_SAN) {
        return Ok(None);
    }
    let mut v = Reader::new(on.expect(der::ctx(0))?);
    let content = v.expect(der::SEQUENCE)?;
    Fields::parse("KRB5PrincipalName", content)?;
    Ok(Some(content.to_vec()))
}

/// UTCTime (`YYMMDDHHMMSSZ`, years 1950–2049) or GeneralizedTime
/// (`YYYYMMDDHHMMSSZ`), as RFC 5280 §4.1.2.5 allows them.
pub(super) fn read_time(r: &mut Reader<'_>) -> Result<i64> {
    let (tag, c) = r.next()?;
    let s = std::str::from_utf8(c)
        .ok()
        .filter(|s| s.is_ascii())
        .ok_or_else(|| DerError("time is not ASCII".into()))?;
    let full = match (tag, s.len()) {
        (asn1::UTC_TIME, 13) => {
            let yy: u32 = s[..2].parse().map_err(|_| DerError("bad UTCTime".into()))?;
            format!("{}{s}", if yy >= 50 { "19" } else { "20" })
        }
        (der::GENERALIZED_TIME, 15) => s.to_string(),
        _ => return err(format!("unsupported time {s:?}")),
    };
    // The crate's own GeneralizedTime reader, not `chrono`: the same octets appear in a ticket's
    // `KerberosTime`, and two parsers would be two answers to what a certificate's validity means.
    crate::time::parse_generalized_time(&full)
        .ok_or_else(|| DerError(format!("time {s:?} is not a GeneralisedTime")))
}

/// The certificates read from PEM `CERTIFICATE` blocks or, failing any,
/// one DER certificate.
pub fn parse_certs(data: &[u8]) -> std::result::Result<Vec<Cert>, String> {
    if data.first() == Some(&der::SEQUENCE) {
        return Cert::from_der(data).map(|c| vec![c]).map_err(|e| e.0);
    }
    super::pem::blocks(data)?
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE" || label == "TRUSTED CERTIFICATE")
        .map(|(_, d)| Cert::from_der(&d).map_err(|e| e.0))
        .collect()
}

/// Check that `leaf` chains to one of `anchors` through `pool`, at `now`.
/// Each certificate must be within its validity period (anchors too, as
/// OpenSSL checks them), each issuer below the anchor a CA allowed to sign
/// certificates at that depth. A certificate that is itself an anchor is
/// trusted as is.
///
/// Returns the path, `leaf` first and the anchor last.
pub fn verify_chain<'a>(
    leaf: &'a Cert,
    pool: &'a [Cert],
    anchors: &'a [Cert],
    now: i64,
) -> Result<Vec<&'a Cert>> {
    let mut path = vec![leaf];
    let mut cur = leaf;
    // CA certificates passed below the current one, for pathLenConstraint.
    let mut below = 0i64;
    for _ in 0..=MAX_DEPTH {
        if cur.der != leaf.der {
            below += 1;
        }
        check_current(cur, now)?;
        if anchors.iter().any(|a| a.der == cur.der) {
            return Ok(path);
        }
        if let Some(a) = anchors
            .iter()
            .find(|a| a.subject == cur.issuer && cur.signed_by(a))
        {
            check_current(a, now)?;
            check_issuer(a, below)?;
            path.push(a);
            return Ok(path);
        }
        let Some(next) = pool
            .iter()
            .find(|c| c.subject == cur.issuer && c.der != cur.der && cur.signed_by(c))
        else {
            return err("the certificate does not chain to a trusted anchor (pkinit_anchors)");
        };
        check_issuer(next, below)?;
        path.push(next);
        cur = next;
    }
    err("certificate chain too long")
}

fn check_current(c: &Cert, now: i64) -> Result<()> {
    if now < c.not_before || now > c.not_after {
        return err("a certificate in the chain is not within its validity period");
    }
    let understood: Vec<Vec<u8>> = UNDERSTOOD.iter().map(|o| asn1::oid(o)).collect();
    if c.extensions
        .iter()
        .any(|e| e.critical && !understood.contains(&e.oid))
    {
        return err("a certificate in the chain has an unsupported critical extension");
    }
    Ok(())
}

/// May `issuer` sign a certificate with `below` CA certificates under it?
fn check_issuer(issuer: &Cert, below: i64) -> Result<()> {
    let (ca, path_len) = issuer.basic_constraints()?;
    if !ca {
        return err("an issuing certificate is not a CA");
    }
    if issuer.key_usage(KU_KEY_CERT_SIGN)? == Some(false) {
        return err("an issuing certificate may not sign certificates (keyUsage)");
    }
    if path_len.is_some_and(|l| below > l) {
        return err("the chain exceeds a CA's pathLenConstraint");
    }
    Ok(())
}

// Test fixtures that a sibling crate builds its own scenarios from. Behind a feature and
// not `cfg(test)`, because `cfg(test)` applies to this crate's build only — a consumer's
// tests compile this crate as a dependency and would not see them.
#[cfg(any(test, feature = "test-support"))]
pub mod tests {
    use super::*;

    /// Inside every fixture's validity (made 2026, for a century).
    pub const NOW: i64 = 1_900_000_000;

    /// The PEM of every certificate the tests share, by the name they call it.
    ///
    /// A table rather than a `match`: the names are data, and ten match arms are ten branches a
    /// reader has to count to know how many fixtures exist.
    const FIXTURES: &[(&str, &str)] = &[
        ("ca", include_str!("testdata/ca.pem")),
        ("inter", include_str!("testdata/inter.pem")),
        ("kdc", include_str!("testdata/kdc.pem")),
        ("host", include_str!("testdata/host.pem")),
        ("leafsigned", include_str!("testdata/leafsigned.pem")),
        ("sub", include_str!("testdata/sub.pem")),
        ("subleaf", include_str!("testdata/subleaf.pem")),
        ("other-ca", include_str!("testdata/other-ca.pem")),
        ("ec-ca", include_str!("testdata/ec-ca.pem")),
        ("ec-kdc", include_str!("testdata/ec-kdc.pem")),
    ];

    pub fn fixture(name: &str) -> Cert {
        let pem = FIXTURES
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no fixture named {name}"))
            .1;
        parse_certs(pem.as_bytes()).unwrap().remove(0)
    }

    /// A 13-octet UTCTime whose second character is not ASCII: refused,
    /// where slicing out the two-digit year would split the character.
    #[test]
    fn a_non_ascii_time_is_refused() {
        for (tag, t) in [
            (asn1::UTC_TIME, "1\u{e9}010100000Z"),
            (der::GENERALIZED_TIME, "20\u{e9}0101000000Z"),
        ] {
            let mut d = vec![tag, t.len() as u8];
            d.extend_from_slice(t.as_bytes());
            assert!(read_time(&mut Reader::new(&d)).is_err(), "{t}");
        }
    }

    #[test]
    fn a_kdc_certificate_is_read_as_openssl_wrote_it() {
        let kdc = fixture("kdc");
        let (principals, dns) = kdc.kerberos_alt_names().unwrap();
        // The payload is a KRB5PrincipalName and is handed out as DER: decoding it into a principal
        // belongs to the crate that has the type, and this asserts only that the right otherName
        // was picked out of the extension.
        assert_eq!(principals.len(), 1);
        let f = Fields::parse("KRB5PrincipalName", &principals[0]).expect("a KRB5PrincipalName");
        assert_eq!(f.get(0).unwrap().string().unwrap(), "TEST.REALM");
        assert!(dns.is_empty());
        assert!(kdc.has_eku(ID_PKINIT_KP_KDC).unwrap());
        assert!(!kdc.has_eku("1.3.6.1.5.5.7.3.1").unwrap());
        assert_eq!(kdc.key_usage(KU_DIGITAL_SIGNATURE).unwrap(), Some(true));
        assert_eq!(kdc.key_usage(KU_KEY_CERT_SIGN).unwrap(), Some(false));
        assert_eq!(kdc.basic_constraints().unwrap(), (false, None));
        assert_eq!(kdc.serial, [3]);
        assert_eq!(
            fixture("inter").basic_constraints().unwrap(),
            (true, Some(0))
        );
        let (p, dns) = fixture("host").kerberos_alt_names().unwrap();
        assert!(p.is_empty());
        assert_eq!(dns, ["kdc.test.realm"]);
        // GeneralizedTime past 2049, UTCTime before.
        assert!(kdc.not_after > 4_102_444_800 && kdc.not_before < 4_102_444_800);
    }

    #[test]
    fn a_chain_through_an_intermediate_to_the_anchor_verifies() {
        let kdc = fixture("kdc");
        let (inter, ca) = ([fixture("inter")], [fixture("ca")]);
        verify_chain(&kdc, &[kdc.clone(), inter[0].clone()], &ca, NOW).unwrap();
        // The pool's order and extra certificates do not matter.
        let pool = [fixture("host"), inter[0].clone(), kdc.clone()];
        verify_chain(&kdc, &pool, &ca, NOW).unwrap();
        // A certificate that is itself an anchor is trusted, and so is
        // one issued by an anchor that is an intermediate.
        verify_chain(&kdc, &[], std::slice::from_ref(&kdc), NOW).unwrap();
        verify_chain(&kdc, &[], &inter, NOW).unwrap();
    }

    #[test]
    fn chains_that_openssl_refuses_are_refused() {
        let kdc = fixture("kdc");
        let (inter, ca) = ([fixture("inter")], [fixture("ca")]);
        let fails = |leaf: &Cert, pool: &[Cert], anchors: &[Cert], now| {
            verify_chain(leaf, pool, anchors, now).unwrap_err().0
        };
        // No anchors; a missing intermediate.
        assert!(fails(&kdc, &inter, &[], NOW).contains("trusted anchor"));
        assert!(fails(&kdc, &[], &ca, NOW).contains("trusted anchor"));
        // An anchor with the right name and the wrong key.
        assert!(fails(&kdc, &inter, &[fixture("other-ca")], NOW).contains("anchor"));
        // Outside the validity period (2023, and 2128).
        assert!(fails(&kdc, &inter, &ca, 1_700_000_000).contains("validity"));
        assert!(fails(&kdc, &inter, &ca, 5_000_000_000).contains("validity"));
        // Issued by a certificate that is not a CA.
        let pool = [kdc.clone(), inter[0].clone()];
        assert!(fails(&fixture("leafsigned"), &pool, &ca, NOW).contains("not a CA"));
        // One CA too many under inter's pathlen:0.
        let pool = [fixture("sub"), inter[0].clone()];
        assert!(fails(&fixture("subleaf"), &pool, &ca, NOW).contains("pathLen"));
        // A tampered certificate (its subject's CN) no longer verifies.
        let mut der = kdc.der.clone();
        let at = der.windows(3).position(|w| w == b"kdc").unwrap();
        der[at] = b'K';
        let forged = Cert::from_der(&der).unwrap();
        assert!(fails(&forged, &inter, &ca, NOW).contains("anchor"));
        // A critical extension nobody here understands.
        let mut odd = kdc.clone();
        odd.extensions.push(Extension {
            oid: asn1::oid("1.2.3.4"),
            critical: true,
            value: vec![5, 0],
        });
        assert!(fails(&odd, &inter, &ca, NOW).contains("critical"));
    }

    #[test]
    fn malformed_certificates_are_refused() {
        let der = fixture("kdc").der;
        for cut in [0, 1, 4, der.len() / 2, der.len() - 1] {
            assert!(Cert::from_der(&der[..cut]).is_err(), "cut {cut}");
        }
        let mut extra = der.clone();
        extra.push(0);
        assert!(Cert::from_der(&extra).is_err());
        assert!(parse_certs(b"no certificates here").unwrap().is_empty());
        assert_eq!(parse_certs(&der).unwrap().len(), 1);
    }
}
