//! Typed Nix hashes and content addresses used by derivations.

use base64::Engine as _;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Hash algorithms understood by Nix derivations and store paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithm {
    /// MD5.
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Return Nix's canonical lowercase algorithm name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    pub(crate) fn parse_bytes(value: &[u8]) -> Result<Self, Error> {
        match value {
            b"md5" => Ok(Self::Md5),
            b"sha1" => Ok(Self::Sha1),
            b"sha256" => Ok(Self::Sha256),
            b"sha512" => Ok(Self::Sha512),
            _ => Err(Error::UnknownAlgorithm(
                String::from_utf8_lossy(value).into_owned(),
            )),
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_bytes(input.as_bytes())
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How content is ingested before hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContentAddressMethod {
    /// Hash the bytes of a single non-executable file.
    Flat,
    /// Hash the NAR serialization of a filesystem object.
    Nar,
    /// Hash text bytes using Nix's text-addressed path rules.
    Text,
    /// Hash a canonical Git tree.
    Git,
}

impl ContentAddressMethod {
    /// Return Nix's descriptive name for this ingestion method.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flat => "flat",
            Self::Nar => "nar",
            Self::Text => "text",
            Self::Git => "git",
        }
    }

    pub(crate) fn parse_prefix(value: &[u8]) -> (Self, &[u8]) {
        if let Some(rest) = value.strip_prefix(b"r:") {
            (Self::Nar, rest)
        } else if let Some(rest) = value.strip_prefix(b"text:") {
            (Self::Text, rest)
        } else if let Some(rest) = value.strip_prefix(b"git:") {
            (Self::Git, rest)
        } else {
            (Self::Flat, value)
        }
    }

    pub(crate) const fn prefix(self) -> &'static str {
        match self {
            Self::Flat => "",
            Self::Nar => "r:",
            Self::Text => "text:",
            Self::Git => "git:",
        }
    }
}

impl FromStr for ContentAddressMethod {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "flat" => Ok(Self::Flat),
            "nar" => Ok(Self::Nar),
            "text" => Ok(Self::Text),
            "git" => Ok(Self::Git),
            _ => Err(Error::UnknownContentAddressMethod(input.to_owned())),
        }
    }
}

impl fmt::Display for ContentAddressMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A malformed or unsupported hash.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The algorithm name is not supported by Nix derivations.
    #[error("unknown hash algorithm {0:?}")]
    UnknownAlgorithm(String),
    /// The content-address method name is not supported by Nix derivations.
    #[error("unknown content-address method {0:?}")]
    UnknownContentAddressMethod(String),
    /// The digest length does not match its declared algorithm.
    #[error("digest has wrong length for {algo}: expected {expected}, got {got}")]
    WrongLength {
        /// Nix name of the declared algorithm.
        algo: HashAlgorithm,
        /// Required digest length in bytes.
        expected: usize,
        /// Supplied digest length in bytes.
        got: usize,
    },
    /// The encoded hash does not use a recognized Nix or SRI form.
    #[error("could not parse hash {0:?}")]
    Unparseable(String),
    /// Text content addressing was paired with an algorithm other than SHA-256.
    #[error("text content addressing requires SHA-256, got {0}")]
    InvalidTextHashAlgorithm(HashAlgorithm),
    /// Git content addressing was paired with an unsupported hash algorithm.
    #[error("Git content addressing requires SHA-1 or SHA-256, got {0}")]
    InvalidGitHashAlgorithm(HashAlgorithm),
}

/// A digest tagged with the algorithm that produced it.
///
/// Each variant fixes the digest size at the type level, so an invalid
/// algorithm/digest combination cannot be represented.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NixHash {
    /// An MD5 digest.
    Md5([u8; 16]),
    /// A SHA-1 digest.
    Sha1([u8; 20]),
    /// A SHA-256 digest.
    Sha256([u8; 32]),
    /// A boxed SHA-512 digest, keeping the enum compact.
    Sha512(Box<[u8; 64]>),
}

impl NixHash {
    /// Build from a hash algorithm and raw digest bytes.
    pub fn from_algorithm_and_digest(
        algorithm: HashAlgorithm,
        digest: &[u8],
    ) -> Result<Self, Error> {
        fn fit<const N: usize>(algo: HashAlgorithm, digest: &[u8]) -> Result<[u8; N], Error> {
            digest.try_into().map_err(|_| Error::WrongLength {
                algo,
                expected: N,
                got: digest.len(),
            })
        }

        match algorithm {
            HashAlgorithm::Md5 => Ok(Self::Md5(fit(HashAlgorithm::Md5, digest)?)),
            HashAlgorithm::Sha1 => Ok(Self::Sha1(fit(HashAlgorithm::Sha1, digest)?)),
            HashAlgorithm::Sha256 => Ok(Self::Sha256(fit(HashAlgorithm::Sha256, digest)?)),
            HashAlgorithm::Sha512 => {
                Ok(Self::Sha512(Box::new(fit(HashAlgorithm::Sha512, digest)?)))
            }
        }
    }

    /// Return the algorithm that produced this digest.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Md5(_) => HashAlgorithm::Md5,
            Self::Sha1(_) => HashAlgorithm::Sha1,
            Self::Sha256(_) => HashAlgorithm::Sha256,
            Self::Sha512(_) => HashAlgorithm::Sha512,
        }
    }

    #[must_use]
    /// Return the unencoded digest bytes.
    pub fn digest_as_bytes(&self) -> &[u8] {
        match self {
            Self::Md5(digest) => digest,
            Self::Sha1(digest) => digest,
            Self::Sha256(digest) => digest,
            Self::Sha512(digest) => digest.as_ref(),
        }
    }

    /// `algo-base64`, as used for Nix `narHash` values.
    #[must_use]
    pub fn to_sri_string(&self) -> String {
        let digest = base64::engine::general_purpose::STANDARD.encode(self.digest_as_bytes());
        format!("{}-{digest}", self.algorithm())
    }

    /// `algo:nixbase32`, as used by Nix's traditional hash format.
    #[must_use]
    pub fn to_nix_nixbase32_string(&self) -> String {
        format!(
            "{}:{}",
            self.algorithm(),
            crate::nixbase32::encode(self.digest_as_bytes())
        )
    }

    /// `algo:base16`, as used inside store-path fingerprints.
    #[must_use]
    pub fn to_nix_base16_string(&self) -> String {
        format!(
            "{}:{}",
            self.algorithm(),
            encode_hex(self.digest_as_bytes())
        )
    }

    /// Parse SRI or `algo:` followed by Nix base32, base16, or base64.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if let Some((algo, encoded)) = input.split_once('-') {
            let expected = digest_len(algo)?;
            let digest = decode_base64(encoded)
                .filter(|digest| digest.len() == expected)
                .ok_or_else(|| Error::Unparseable(input.to_owned()))?;
            return Self::from_algorithm_and_digest(algo.parse()?, &digest);
        }

        let (algo, encoded) = input
            .split_once(':')
            .ok_or_else(|| Error::Unparseable(input.to_owned()))?;
        let expected = digest_len(algo)?;
        let digest = if encoded.len() == expected * 2 {
            decode_hex(encoded).ok_or_else(|| Error::Unparseable(input.to_owned()))?
        } else if encoded.len() == crate::nixbase32::encoded_len(expected) {
            crate::nixbase32::decode(encoded.as_bytes())
                .map_err(|_| Error::Unparseable(input.to_owned()))?
        } else {
            decode_base64(encoded).ok_or_else(|| Error::Unparseable(input.to_owned()))?
        };
        Self::from_algorithm_and_digest(algo.parse()?, &digest)
    }
}

impl FromStr for NixHash {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

fn digest_len(algo: &str) -> Result<usize, Error> {
    match algo.parse()? {
        HashAlgorithm::Md5 => Ok(16),
        HashAlgorithm::Sha1 => Ok(20),
        HashAlgorithm::Sha256 => Ok(32),
        HashAlgorithm::Sha512 => Ok(64),
    }
}

fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .ok()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0xf) as usize] as char);
    }
    encoded
}

fn decode_hex(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() & 1 != 0 {
        return None;
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?))
        .collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// How a path's content address was computed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CAHash {
    /// Hash of a single non-executable file's bytes.
    Flat(NixHash),
    /// Hash of the path's NAR serialization.
    Nar(NixHash),
    /// Hash of text bytes. Nix restricts this method to SHA-256.
    Text([u8; 32]),
    /// Hash of a canonical Git tree. Nix permits SHA-1 and SHA-256.
    Git(NixHash),
}

impl CAHash {
    #[must_use]
    /// Return the tagged digest used by this content address.
    pub fn hash(&self) -> NixHash {
        match self {
            Self::Flat(hash) | Self::Nar(hash) | Self::Git(hash) => hash.clone(),
            Self::Text(digest) => NixHash::Sha256(*digest),
        }
    }

    /// Return the ingestion method used by this content address.
    #[must_use]
    pub const fn method(&self) -> ContentAddressMethod {
        match self {
            Self::Flat(_) => ContentAddressMethod::Flat,
            Self::Nar(_) => ContentAddressMethod::Nar,
            Self::Text(_) => ContentAddressMethod::Text,
            Self::Git(_) => ContentAddressMethod::Git,
        }
    }

    /// Construct a content address from its method, algorithm, and raw digest bytes.
    pub fn from_parts(
        method: ContentAddressMethod,
        algorithm: HashAlgorithm,
        digest: &[u8],
    ) -> Result<Self, Error> {
        match method {
            ContentAddressMethod::Flat => Ok(Self::Flat(NixHash::from_algorithm_and_digest(
                algorithm, digest,
            )?)),
            ContentAddressMethod::Nar => Ok(Self::Nar(NixHash::from_algorithm_and_digest(
                algorithm, digest,
            )?)),
            ContentAddressMethod::Text => {
                match NixHash::from_algorithm_and_digest(algorithm, digest)? {
                    NixHash::Sha256(digest) => Ok(Self::Text(digest)),
                    other => Err(Error::InvalidTextHashAlgorithm(other.algorithm())),
                }
            }
            ContentAddressMethod::Git => {
                match NixHash::from_algorithm_and_digest(algorithm, digest)? {
                    hash @ (NixHash::Sha1(_) | NixHash::Sha256(_)) => Ok(Self::Git(hash)),
                    other => Err(Error::InvalidGitHashAlgorithm(other.algorithm())),
                }
            }
        }
    }

    /// Parse the value of a Nix `ca` field.
    ///
    /// This accepts the canonical strings emitted by [`Self::to_nix_string`].
    pub fn parse(input: &str) -> Result<Self, Error> {
        let (method, encoded_hash) = if let Some(encoded) = input.strip_prefix("fixed:r:") {
            (ContentAddressMethod::Nar, encoded)
        } else if let Some(encoded) = input.strip_prefix("fixed:git:") {
            (ContentAddressMethod::Git, encoded)
        } else if let Some(encoded) = input.strip_prefix("fixed:") {
            (ContentAddressMethod::Flat, encoded)
        } else if let Some(encoded) = input.strip_prefix("text:") {
            (ContentAddressMethod::Text, encoded)
        } else {
            return Err(Error::Unparseable(input.to_owned()));
        };

        let hash = NixHash::parse(encoded_hash)?;
        Self::from_parts(method, hash.algorithm(), hash.digest_as_bytes())
    }

    /// The `ca` field Nix prints, such as `fixed:r:sha256:<nixbase32>`.
    #[must_use]
    pub fn to_nix_string(&self) -> String {
        match self {
            Self::Flat(hash) => format!("fixed:{}", hash.to_nix_nixbase32_string()),
            Self::Nar(hash) => format!("fixed:r:{}", hash.to_nix_nixbase32_string()),
            Self::Text(digest) => {
                format!(
                    "text:{}",
                    NixHash::Sha256(*digest).to_nix_nixbase32_string()
                )
            }
            Self::Git(hash) => format!("fixed:git:{}", hash.to_nix_nixbase32_string()),
        }
    }
}

impl FromStr for CAHash {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl fmt::Display for CAHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_nix_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256() -> NixHash {
        NixHash::Sha256(std::array::from_fn(|i| i as u8))
    }

    #[test]
    fn parses_every_supported_hash_format() {
        let hash = sha256();
        let hex = hash.to_nix_base16_string();
        let nix32 = hash.to_nix_nixbase32_string();
        let sri = hash.to_sri_string();
        let base64 = format!(
            "sha256:{}",
            base64::engine::general_purpose::STANDARD.encode(hash.digest_as_bytes())
        );

        for encoded in [&hex, &nix32, &sri, &base64] {
            assert_eq!(encoded.parse(), Ok(hash.clone()), "{encoded}");
        }
    }

    #[test]
    fn rejects_wrong_digest_length() {
        assert!(matches!(
            NixHash::parse("sha256-AA=="),
            Err(Error::Unparseable(_))
        ));
        assert!(matches!(
            NixHash::from_algorithm_and_digest(HashAlgorithm::Sha1, &[0; 19]),
            Err(Error::WrongLength { .. })
        ));
    }

    #[test]
    fn content_address_rendering_matches_nix() {
        let ca = CAHash::Nar(sha256());
        assert_eq!(
            ca.to_nix_string(),
            format!("fixed:r:{}", ca.hash().to_nix_nixbase32_string())
        );
        assert_eq!(ca.to_nix_string().parse(), Ok(ca.clone()));
        assert_eq!(ca.to_string(), ca.to_nix_string());

        let git =
            CAHash::from_parts(ContentAddressMethod::Git, HashAlgorithm::Sha1, &[0; 20]).unwrap();
        assert_eq!(
            git.to_nix_string(),
            format!("fixed:git:{}", git.hash().to_nix_nixbase32_string())
        );
        assert_eq!(git.to_nix_string().parse(), Ok(git));

        let text = CAHash::Text([1; 32]);
        assert_eq!(text.to_nix_string().parse(), Ok(text));

        let flat = CAHash::Flat(NixHash::Md5([2; 16]));
        assert_eq!(flat.to_nix_string().parse(), Ok(flat));

        assert!(matches!(
            CAHash::from_parts(ContentAddressMethod::Git, HashAlgorithm::Md5, &[0; 16]),
            Err(Error::InvalidGitHashAlgorithm(_))
        ));
    }
}
