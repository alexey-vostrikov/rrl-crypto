//! Certificate revocation lists (RFC 5280 §5) for the KDC's certificate
//! chain, checked as MIT's client has OpenSSL check them
//! (`X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`):
//!
//! * every certificate below the trust anchor is looked up in a CRL from
//!   its issuer, the anchor itself in none;
//! * CRLs come from `pkinit_revoke` (only the first from each issuer is
//!   kept, as MIT's loader keeps them) and from the KDC's SignedData;
//! * of a certificate's candidate CRLs, OpenSSL's choice: one without
//!   unhandled critical extensions, in scope, then current, the later
//!   `thisUpdate` breaking a tie;
//! * no CRL for an issuer fails only with `pkinit_require_crl_checking`;
//!   a CRL that is out of date, out of scope, badly signed, from an issuer
//!   without `cRLSign`, or has an unhandled critical extension fails
//!   always, as does a listed serial number.
//!
//! Not supported, as OpenSSL does not without extended CRL support: delta
//! CRLs, indirect CRLs and CRLs partitioned by reason; such a CRL is no
//! CRL for the certificate. Nor is OCSP, which MIT does not do.

use super::asn1::{self, ReaderExt, implicit};
use super::x509::{self, Cert, Extension};
use crate::der::{self, DerError, Reader};

type Result<T> = std::result::Result<T, DerError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(DerError(msg.into()))
}

const REASON_CODE: &str = "2.5.29.21";
const DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
const CERTIFICATE_ISSUER: &str = "2.5.29.29";
const CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
/// keyUsage `cRLSign` (RFC 5280 §4.2.1.3).
const KU_CRL_SIGN: u32 = 6;
/// CRLReason `removeFromCRL`: an entry that does not revoke.
const REMOVE_FROM_CRL: u8 = 8;

/// A parsed CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crl {
    tbs: Vec<u8>,
    sig_alg: Vec<u8>,
    signature: Vec<u8>,
    /// The issuer Name, whole TLV, as [`Cert::issuer`] holds it.
    pub issuer: Vec<u8>,
    this_update: i64,
    next_update: Option<i64>,
    /// The revoked serial numbers (INTEGER content octets), less those
    /// marked `removeFromCRL`.
    revoked: Vec<Vec<u8>>,
    /// A critical extension, of the CRL or of an entry, that OpenSSL does
    /// not handle.
    unhandled_critical: bool,
    /// A delta CRL, an indirect CRL, one partitioned by reason, or one
    /// whose issuingDistributionPoint is invalid: never a certificate's
    /// CRL here.
    unusable: bool,
    idp: Option<Idp>,
    /// authorityKeyIdentifier's keyIdentifier.
    akid: Option<Vec<u8>>,
}

/// What issuingDistributionPoint limits the CRL to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Idp {
    /// The DistributionPointName, whole TLV.
    point: Option<Vec<u8>>,
    only_user: bool,
    only_ca: bool,
    only_attribute: bool,
}

/// The three parts a `CertificateList` is signed over, and the signature itself.
struct SignedPart<'a> {
    /// The content of `tbsCertList`, whose length the signature covers as a SEQUENCE.
    tbs_content: &'a [u8],
    /// `tbsCertList` whole, tag and length included: what a verifier hashes.
    tbs: &'a [u8],
    sig_alg: &'a [u8],
    signature: Vec<u8>,
}

/// Splits a `CertificateList` into the signed part and the signature around it.
fn signed_part(der: &[u8]) -> Result<SignedPart<'_>> {
    let mut outer = Reader::new(der);
    let mut c = outer.seq()?;
    outer.done("CertificateList")?;
    let (_, tbs_content, tbs) = c.next_raw()?;
    let (sig_alg, _) = c.alg_id()?;
    let signature = c.bits()?.to_vec();
    c.done("CertificateList")?;
    Ok(SignedPart {
        tbs_content,
        tbs,
        sig_alg,
        signature,
    })
}

/// What `tbsCertList` says before the revoked entries: its version, issuer and two dates.
struct Header {
    version: i64,
    issuer: Vec<u8>,
    this_update: i64,
    next_update: Option<i64>,
}

/// Reads the head of `tbsCertList`, refusing a signature algorithm that disagrees with the outer
/// one: the two are the same statement, and a list where they differ is one nobody can check.
fn header(t: &mut Reader<'_>, sig_alg: &[u8]) -> Result<Header> {
    let version = match t.rest().first() {
        Some(&der::INTEGER) => t.int()?,
        _ => 0,
    };
    let (inner_alg, _) = t.alg_id()?;
    if inner_alg != sig_alg {
        return err("CRL signature algorithms disagree");
    }
    let issuer = t.next_raw()?.2.to_vec();
    let this_update = x509::read_time(t)?;
    Ok(Header {
        version,
        issuer,
        this_update,
        next_update: optional_time(t)?,
    })
}

/// `nextUpdate`, when the list carries one.
fn optional_time(t: &mut Reader<'_>) -> Result<Option<i64>> {
    match t.rest().first() {
        Some(&tag) if tag == asn1::UTC_TIME || tag == der::GENERALIZED_TIME => {
            Ok(Some(x509::read_time(t)?))
        }
        _ => Ok(None),
    }
}

/// One `revokedCertificate`.
struct Entry {
    serial: Vec<u8>,
    /// The entry says the certificate is back: `removeFromCRL`.
    removed: bool,
    /// A critical extension this crate does not interpret travelled with the entry.
    unhandled_critical: bool,
}

impl Entry {
    /// Reads the extensions that say a certificate is back, or that go unhandled.
    ///
    /// `reasonCode`'s `removeFromCRL` is the one reason that changes the verdict: an entry is
    /// otherwise a revocation, and the date in it says when. A critical extension this crate does
    /// not interpret is remembered rather than refused here — the refusal belongs to whoever judges
    /// the certificate, where it can name the depth.
    fn read_extensions(&mut self, extensions: Vec<x509::Extension>) -> Result<()> {
        for x in extensions {
            if x.oid == asn1::oid(REASON_CODE) {
                self.removed = Reader::new(&x.value).expect(ENUMERATED)? == [REMOVE_FROM_CRL];
            }
            // OpenSSL handles a critical certificateIssuer (it matters only to indirect CRLs) and
            // no other.
            if x.critical && x.oid != asn1::oid(CERTIFICATE_ISSUER) {
                self.unhandled_critical = true;
            }
        }
        Ok(())
    }
}

/// The `SEQUENCE OF` revoked entries.
fn revoked_entries(t: &mut Reader<'_>, version: i64) -> Result<Vec<Entry>> {
    let mut entries = t.seq()?;
    let mut out = Vec::new();
    while !entries.is_empty() {
        out.push(entry(&mut entries, version)?);
    }
    Ok(out)
}

/// One entry: its serial, its date, and the extensions that may say it is back.
fn entry(entries: &mut Reader<'_>, version: i64) -> Result<Entry> {
    let mut e = entries.seq()?;
    let serial = e.expect(der::INTEGER)?.to_vec();
    x509::read_time(&mut e)?;
    let mut out = Entry {
        serial,
        removed: false,
        unhandled_critical: false,
    };
    if e.is_empty() {
        e.done("revokedCertificate")?;
        return Ok(out);
    }
    if version != 1 {
        return err("entry extensions in a CRL before v2");
    }
    let (_, _, raw) = e.next_raw()?;
    out.read_extensions(x509::read_extensions(raw)?)?;
    e.done("revokedCertificate")?;
    Ok(out)
}

impl Crl {
    /// ```text
    /// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue BIT STRING }
    /// TBSCertList ::= SEQUENCE {
    ///     version INTEGER OPTIONAL, signature AlgorithmIdentifier, issuer Name,
    ///     thisUpdate Time, nextUpdate Time OPTIONAL,
    ///     revokedCertificates SEQUENCE OF SEQUENCE {
    ///         userCertificate INTEGER, revocationDate Time,
    ///         crlEntryExtensions Extensions OPTIONAL } OPTIONAL,
    ///     crlExtensions [0] EXPLICIT Extensions OPTIONAL }
    /// ```
    pub fn from_der(der: &[u8]) -> Result<Crl> {
        let part = signed_part(der)?;
        let mut t = Reader::new(part.tbs_content);
        let h = header(&mut t, part.sig_alg)?;
        let mut crl = Crl {
            tbs: part.tbs.to_vec(),
            sig_alg: part.sig_alg.to_vec(),
            signature: part.signature,
            issuer: h.issuer,
            this_update: h.this_update,
            next_update: h.next_update,
            revoked: Vec::new(),
            unhandled_critical: false,
            unusable: false,
            idp: None,
            akid: None,
        };
        if t.rest().first() == Some(&der::SEQUENCE) {
            for entry in revoked_entries(&mut t, h.version)? {
                crl.unhandled_critical |= entry.unhandled_critical;
                if !entry.removed {
                    crl.revoked.push(entry.serial);
                }
            }
        }
        crl.read_extensions(&mut t, h.version)?;
        t.done("TBSCertList")?;
        Ok(crl)
    }

    /// The extensions at the end of the list, which are the CRL's own and not an entry's.
    fn read_extensions(&mut self, t: &mut Reader<'_>, version: i64) -> Result<()> {
        let Some(exts) = t.optional(der::ctx(0))? else {
            return Ok(());
        };
        if version != 1 {
            return err("extensions in a CRL before v2");
        }
        for x in x509::read_extensions(exts)? {
            self.extension(&x)?;
        }
        Ok(())
    }

    fn extension(&mut self, x: &Extension) -> Result<()> {
        let is = |dotted| x.oid == asn1::oid(dotted);
        if is(DELTA_CRL_INDICATOR) {
            self.unusable = true;
        } else if is(AUTHORITY_KEY_IDENTIFIER) {
            // SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
            let mut s = Reader::new(&x.value).seq()?;
            self.akid = s.optional(implicit(0))?.map(<[u8]>::to_vec);
        } else if is(ISSUING_DISTRIBUTION_POINT) {
            self.idp = Some(self.read_idp(&x.value)?);
        } else if x.critical {
            // OpenSSL handles a critical IDP, AKI or delta indicator, and
            // no other: not even the CRL number.
            self.unhandled_critical = true;
        }
        Ok(())
    }

    /// ```text
    /// IssuingDistributionPoint ::= SEQUENCE {
    ///     distributionPoint [0] DistributionPointName OPTIONAL,
    ///     onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE,
    ///     onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE,
    ///     onlySomeReasons [3] ReasonFlags OPTIONAL,
    ///     indirectCRL [4] BOOLEAN DEFAULT FALSE,
    ///     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
    /// ```
    fn read_idp(&mut self, value: &[u8]) -> Result<Idp> {
        let flags = IdpFlags::read(value)?;
        // OpenSSL's IDP_INVALID: more than one "only", or a CRL that is partial in a way this
        // crate does not follow.
        if flags.invalid() {
            self.unusable = true;
        }
        Ok(flags.into_idp())
    }

    fn current(&self, now: i64) -> bool {
        self.this_update <= now && self.next_update.is_none_or(|n| now <= n)
    }
}

/// The flags of an `IssuingDistributionPoint`, read in the order the RFC lays them out.
struct IdpFlags {
    point: Option<Vec<u8>>,
    only_user: bool,
    only_ca: bool,
    some_reasons: bool,
    indirect: bool,
    only_attribute: bool,
}

impl IdpFlags {
    fn read(value: &[u8]) -> Result<IdpFlags> {
        let mut s = Reader::new(value).seq()?;
        let point = match s.rest().first() {
            Some(&t) if t == der::ctx(0) => Some(s.next_raw()?.2.to_vec()),
            _ => None,
        };
        let flags = IdpFlags {
            point,
            only_user: flag(&mut s, 1)?,
            only_ca: flag(&mut s, 2)?,
            some_reasons: s.optional(implicit(3))?.is_some(),
            indirect: flag(&mut s, 4)?,
            only_attribute: flag(&mut s, 5)?,
        };
        s.done("IssuingDistributionPoint")?;
        Ok(flags)
    }

    /// OpenSSL's `IDP_INVALID`: more than one "only", or a reason subset, or an indirect CRL. None
    /// of the three can be judged by this crate, so the list carrying one is set aside rather than
    /// read as if it said something narrower than it does.
    fn invalid(&self) -> bool {
        let onlies =
            u8::from(self.only_user) + u8::from(self.only_ca) + u8::from(self.only_attribute);
        onlies > 1 || self.some_reasons || self.indirect
    }

    fn into_idp(self) -> Idp {
        Idp {
            point: self.point,
            only_user: self.only_user,
            only_ca: self.only_ca,
            only_attribute: self.only_attribute,
        }
    }
}

/// One `[n] BOOLEAN DEFAULT FALSE`, which DER writes as a single octet: `ff` or nothing.
fn flag(s: &mut Reader<'_>, n: u8) -> Result<bool> {
    match s.optional(implicit(n))? {
        Some([0xFF]) => Ok(true),
        Some(_) => err("bad BOOLEAN in issuingDistributionPoint"),
        None => Ok(false),
    }
}

const ENUMERATED: u8 = 0x0A;

/// The CRLs MIT's client has: the first from each issuer, in order.
pub fn add_local(into: &mut Vec<Crl>, crl: Crl) {
    if !into.iter().any(|c| c.issuer == crl.issuer) {
        into.push(crl);
    }
}

/// The CRLs in a PEM file's `X509 CRL` blocks. Other blocks and text
/// outside blocks are ignored (a file of certificates, a DER CRL); a CRL
/// block that does not parse is an error, as with OpenSSL's
/// `PEM_X509_INFO_read_bio`.
pub fn from_pem(data: &[u8]) -> std::result::Result<Vec<Crl>, String> {
    super::pem::blocks(data)?
        .into_iter()
        .filter(|(label, _)| label == "X509 CRL")
        .map(|(_, d)| Crl::from_der(&d).map_err(|e| format!("CRL: {}", e.0)))
        .collect()
}

/// Revocation policy for one chain check.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy<'a> {
    /// `pkinit_revoke`'s CRLs.
    pub local: &'a [Crl],
    /// `pkinit_require_crl_checking`.
    pub require: bool,
}

/// Check each certificate of `path` (leaf first, anchor last) but the
/// anchor against the CRLs of `policy` and those `sent` with it.
pub fn check_chain(path: &[&Cert], policy: Policy<'_>, sent: &[Crl], now: i64) -> Result<()> {
    for (depth, pair) in path.windows(2).enumerate() {
        check_cert(pair[0], pair[1], depth, policy, sent, now)?;
    }
    Ok(())
}

// OpenSSL's get_crl_score bits, in its order of preference.
const SCORE_NOCRITICAL: u32 = 0x100;
const SCORE_SCOPE: u32 = 0x080;
const SCORE_TIME: u32 = 0x040;

fn check_cert(
    cert: &Cert,
    issuer: &Cert,
    depth: usize,
    policy: Policy<'_>,
    sent: &[Crl],
    now: i64,
) -> Result<()> {
    let Some((score, crl)) = best_crl(cert, issuer, policy, sent, now) else {
        // No CRL at all is only a failure when the configuration asks for one: an unreachable
        // distribution point is how most realms run.
        return match policy.require {
            true => at(
                depth,
                "no CRL from its issuer (pkinit_require_crl_checking)",
            ),
            false => Ok(()),
        };
    };
    check_selected(cert, issuer, depth, score, crl, now)
}

/// A refusal naming where in the chain it happened.
fn at<T>(depth: usize, what: &str) -> Result<T> {
    Err(DerError(format!(
        "certificate at depth {depth} of the KDC's chain: {what}"
    )))
}

/// The CRL to judge `cert` by: OpenSSL's `get_crl_sk`, the best score with a later `thisUpdate`
/// taking a tie.
fn best_crl<'a>(
    cert: &Cert,
    issuer: &Cert,
    policy: Policy<'a>,
    sent: &'a [Crl],
    now: i64,
) -> Option<(u32, &'a Crl)> {
    let ski = issuer
        .extension(SUBJECT_KEY_IDENTIFIER)
        .and_then(|e| Reader::new(&e.value).octets().ok());
    let mut best: Option<(u32, &Crl)> = None;
    for crl in policy.local.iter().chain(sent) {
        if !usable_for(crl, cert, ski) {
            continue;
        }
        let score = score_of(cert, crl, now);
        best = match best {
            Some((b, c)) if score < b || (score == b && crl.this_update <= c.this_update) => {
                Some((b, c))
            }
            _ => Some((score, crl)),
        };
    }
    best
}

/// Whether this CRL could be the one for `cert`: from its issuer, not superseded, and not naming
/// another key.
///
/// An `authorityKeyIdentifier` that names a different key is some other issuer's CRL — a CA that
/// re-keyed — rather than this one's, and judging a certificate by it would report a revocation
/// that never happened.
fn usable_for(crl: &Crl, cert: &Cert, ski: Option<&[u8]>) -> bool {
    if crl.unusable || crl.issuer != cert.issuer {
        return false;
    }
    match (&crl.akid, ski) {
        (Some(a), Some(s)) => a.as_slice() == s,
        _ => true,
    }
}

/// OpenSSL's score for a candidate: the bits, in its order of preference.
fn score_of(cert: &Cert, crl: &Crl, now: i64) -> u32 {
    let mut score = 0;
    if !crl.unhandled_critical {
        score |= SCORE_NOCRITICAL;
    }
    if in_scope(cert, crl) {
        score |= SCORE_SCOPE;
    }
    if crl.current(now) {
        score |= SCORE_TIME;
    }
    score
}

/// OpenSSL's `check_crl` and then `cert_crl`, in the order it makes its refusals.
fn check_selected(
    cert: &Cert,
    issuer: &Cert,
    depth: usize,
    score: u32,
    crl: &Crl,
    now: i64,
) -> Result<()> {
    if issuer.key_usage(KU_CRL_SIGN)? == Some(false) {
        return at(depth, "its CRL's issuer may not sign CRLs (keyUsage)");
    }
    if score & SCORE_SCOPE == 0 {
        return at(
            depth,
            "its issuer's CRL does not cover it (issuingDistributionPoint)",
        );
    }
    if crl.this_update > now {
        return at(depth, "its issuer's CRL is not yet valid");
    }
    if crl.next_update.is_some_and(|n| now > n) {
        return at(depth, "its issuer's CRL has expired");
    }
    if !issuer.made(&crl.sig_alg, &crl.tbs, &crl.signature) {
        return at(depth, "its issuer's CRL is not signed by the issuer");
    }
    if crl.unhandled_critical {
        return at(
            depth,
            "its issuer's CRL has an unhandled critical extension",
        );
    }
    if crl.revoked.contains(&cert.serial) {
        return at(depth, "revoked");
    }
    Ok(())
}

/// OpenSSL's crl_crldp_check: whether `crl`'s issuingDistributionPoint
/// covers `cert`.
fn in_scope(cert: &Cert, crl: &Crl) -> bool {
    let Some(idp) = &crl.idp else {
        return true;
    };
    if idp.only_attribute || (cert.is_ca() && idp.only_user) || (!cert.is_ca() && idp.only_ca) {
        return false;
    }
    let Some(point) = &idp.point else {
        return true;
    };
    // The certificate's cRLDistributionPoints: one without a cRLIssuer
    // whose name is absent or shares a GeneralName with the CRL's.
    let Some(e) = cert.extension(CRL_DISTRIBUTION_POINTS) else {
        return false;
    };
    let Ok(mut dps) = Reader::new(&e.value).seq() else {
        return false;
    };
    while let Ok(mut dp) = dps.seq() {
        let mut name = None;
        let mut has_crl_issuer = false;
        while let Ok((tag, _, raw)) = dp.next_raw() {
            if tag == der::ctx(0) {
                name = Some(raw);
            } else if tag == der::ctx(2) {
                has_crl_issuer = true;
            }
        }
        if !has_crl_issuer && name.is_none_or(|n| same_point(n, point)) {
            return true;
        }
    }
    false
}

/// Whether two DistributionPointNames (whole `[0]` TLVs) name the same
/// point: equal, or full names sharing a GeneralName.
fn same_point(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    let full_names = |dp: &[u8]| -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Ok(c) = Reader::new(dp).expect(der::ctx(0)) else {
            return out;
        };
        let mut r = Reader::new(c);
        // fullName [0] IMPLICIT GeneralNames
        if let Ok(names) = r.expect(implicit(0) | 0x20) {
            let mut n = Reader::new(names);
            while let Ok((_, _, raw)) = n.next_raw() {
                out.push(raw.to_vec());
            }
        }
        out
    };
    let (a, b) = (full_names(a), full_names(b));
    a.iter().any(|x| b.contains(x))
}

#[cfg(test)]
mod tests;
