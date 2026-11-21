//! Certificates, CMS and PKCS#12: the envelopes a PKINIT exchange, and any mTLS deployment,
//! passes keys and identities in.
//!
//! # Why this is in the crypto layer
//!
//! RRL-7.8. These are not Kerberos: RFC 5280, RFC 5652 and RFC 7292 describe them without ever
//! mentioning a realm, and the same code reads a certificate for an LDAP server's StartTLS or for a
//! service's mTLS identity. What they do share with the primitives next door is the property that
//! made them move: the octets here are what a signature covers. A certificate's `tbsCertificate`
//! signed with the wrong DER length verifies nowhere, and a CMS `SignedData` whose attributes are
//! ordered differently is a different signature over the same content.
//!
//! # What stayed behind
//!
//! One thing, and it is Kerberos' own: the `id-pkinit-san` name inside a certificate's
//! `subjectAltName` is a `KRB5PrincipalName`, and reading it needs `Principal`. The certificate
//! reader therefore hands out the other-name payloads as raw DER (`Cert::other_names`), and the
//! principal decoding lives in the crate that knows what a principal is.
//!
//! # Layout
//!
//! `asn1` is the small vocabulary on top of `crate::der` that these structures use — implicit tags,
//! `ReaderExt` for the shapes they repeat. `keys` holds the private and public key forms, with
//! `rsa` and `ec` doing the arithmetic. `x509`, `crl`, `cms` and `pkcs12` are the envelopes
//! themselves, each building on the one before.

pub mod asn1;
pub mod bigint;
pub mod cms;
pub mod crl;
pub mod ec;
pub mod keys;
pub mod pem;
pub mod pkcs12;
pub mod rsa;
pub mod x509;

// No re-exports at this level: the items inside are `pub(crate)` where the family needs them and
// public where a consumer does, and flattening them here would either widen a private type into the
// public API or fail to compile at all.
