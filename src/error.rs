//! The errors a cryptographic layer can produce.
//!
//! Deliberately small and closed: a caller that gets one of these has either supplied something
//! malformed (a key of the wrong length, an enctype this build does not implement) or a
//! operation failed its integrity check. There is no "unknown" variant, because a crypto layer
//! that cannot say what went wrong is a crypto layer whose failures cannot be told apart.
//!
//! The protocol layer above has a much larger error type — `KDC_ERR_*` codes, principals,
//! expiration — and it converts from these with `From`, so nothing here needs to know a KDC
//! exists.

use std::fmt;

/// What went wrong, in the terms of this layer only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An enctype number this build does not implement.
    UnsupportedEnctype(i32),
    /// A key of the wrong size for its enctype.
    KeyLength {
        /// The enctype the key was built for.
        enctype: crate::Enctype,
        /// The size that enctype requires.
        want: usize,
        /// The size that arrived.
        got: usize,
    },
    /// A cryptographic operation failed: bad tag, short ciphertext, missing key.
    Crypto(String),
    /// A configuration value this layer cannot use.
    Config(String),
}

impl Error {
    /// A failure with a description; the constructor that most call sites want.
    pub fn crypto(what: impl fmt::Display) -> Self {
        Error::Crypto(what.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedEnctype(id) => {
                write!(f, "enctype {id} is not one this build implements")
            }
            Error::KeyLength { enctype, want, got } => {
                write!(f, "enctype {enctype:?} takes a {want}-octet key, got {got}")
            }
            Error::Crypto(text) => write!(f, "crypto: {text}"),
            Error::Config(text) => write!(f, "configuration: {text}"),
        }
    }
}

impl std::error::Error for Error {}

/// The result type of this layer.
pub type Result<T> = std::result::Result<T, Error>;
