//! Typed Nix hashes and content addresses used by derivations.

use base64::Engine as _;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Hash algorithms understood by Nix derivations and store paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithm {
    /// BLAKE3.
    Blake3,
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
            Self::Blake3 => "blake3",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    pub(crate) fn parse_bytes(value: &[u8]) -> Result<Self, Error> {
        match value {
            b"blake3" => Ok(Self::Blake3),
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
    /// A BLAKE3 digest.
    Blake3([u8; 32]),
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
            HashAlgorithm::Blake3 => Ok(Self::Blake3(fit(HashAlgorithm::Blake3, digest)?)),
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
            Self::Blake3(_) => HashAlgorithm::Blake3,
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
            Self::Blake3(digest) => digest,
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
        if input.contains('-') {
            return Self::parse_sri(input);
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

    /// Parse an SRI `algo-base64` hash without accepting legacy Nix encodings.
    pub(crate) fn parse_sri(input: &str) -> Result<Self, Error> {
        let (algo, encoded) = input
            .split_once('-')
            .ok_or_else(|| Error::Unparseable(input.to_owned()))?;
        let expected = digest_len(algo)?;
        let digest = decode_base64(encoded)
            .filter(|digest| digest.len() == expected)
            .ok_or_else(|| Error::Unparseable(input.to_owned()))?;
        Self::from_algorithm_and_digest(algo.parse()?, &digest)
    }
}

impl FromStr for NixHash {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

enum HasherInner {
    Blake3(Box<blake3::Hasher>),
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

/// An incremental hasher for every digest algorithm understood by Nix.
///
/// This type computes raw content digests. The caller remains responsible for
/// applying flat, NAR, text, or Git content-address framing before feeding
/// bytes to it.
pub struct NixHasher {
    algorithm: HashAlgorithm,
    inner: HasherInner,
}

impl fmt::Debug for NixHasher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NixHasher")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl NixHasher {
    /// Start an incremental digest using `algorithm`.
    #[must_use]
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let inner = match algorithm {
            HashAlgorithm::Blake3 => HasherInner::Blake3(Box::new(blake3::Hasher::new())),
            HashAlgorithm::Md5 => HasherInner::Md5(Md5::new()),
            HashAlgorithm::Sha1 => HasherInner::Sha1(Sha1::new()),
            HashAlgorithm::Sha256 => HasherInner::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => HasherInner::Sha512(Sha512::new()),
        };
        Self { algorithm, inner }
    }

    /// Return the selected digest algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Feed another byte slice into the digest.
    pub fn update(&mut self, bytes: &[u8]) {
        match &mut self.inner {
            HasherInner::Blake3(hasher) => {
                hasher.update(bytes);
            }
            HasherInner::Md5(hasher) => hasher.update(bytes),
            HasherInner::Sha1(hasher) => hasher.update(bytes),
            HasherInner::Sha256(hasher) => hasher.update(bytes),
            HasherInner::Sha512(hasher) => hasher.update(bytes),
        }
    }

    /// Finish the digest and return a correctly tagged, fixed-size value.
    #[must_use]
    pub fn finalize(self) -> NixHash {
        match self.inner {
            HasherInner::Blake3(hasher) => NixHash::Blake3(*hasher.finalize().as_bytes()),
            HasherInner::Md5(hasher) => NixHash::Md5(hasher.finalize().into()),
            HasherInner::Sha1(hasher) => NixHash::Sha1(hasher.finalize().into()),
            HasherInner::Sha256(hasher) => NixHash::Sha256(hasher.finalize().into()),
            HasherInner::Sha512(hasher) => NixHash::Sha512(Box::new(hasher.finalize().into())),
        }
    }
}

/// Hash one byte slice with any digest algorithm understood by Nix.
#[must_use]
pub fn hash_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> NixHash {
    let mut hasher = NixHasher::new(algorithm);
    hasher.update(bytes);
    hasher.finalize()
}

fn digest_len(algo: &str) -> Result<usize, Error> {
    match algo.parse()? {
        HashAlgorithm::Blake3 => Ok(32),
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
    fn sri_parser_rejects_legacy_nix_hash_formats() {
        let hash = sha256();
        assert_eq!(NixHash::parse_sri(&hash.to_sri_string()), Ok(hash.clone()));

        for encoded in [
            hash.to_nix_base16_string(),
            hash.to_nix_nixbase32_string(),
            format!(
                "sha256:{}",
                base64::engine::general_purpose::STANDARD.encode(hash.digest_as_bytes())
            ),
        ] {
            assert!(matches!(
                NixHash::parse_sri(&encoded),
                Err(Error::Unparseable(_))
            ));
        }
    }

    #[test]
    fn blake3_hashes_round_trip_in_nix_and_sri_formats() {
        let hash = NixHash::Blake3(std::array::from_fn(|i| i as u8));

        for encoded in [
            hash.to_nix_base16_string(),
            hash.to_nix_nixbase32_string(),
            hash.to_sri_string(),
        ] {
            assert_eq!(NixHash::parse(&encoded), Ok(hash.clone()), "{encoded}");
        }
    }

    #[test]
    fn incremental_hashing_matches_known_vectors() {
        let vectors = [
            (
                HashAlgorithm::Blake3,
                "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            ),
            (HashAlgorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            (
                HashAlgorithm::Sha1,
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                HashAlgorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                HashAlgorithm::Sha512,
                concat!(
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                ),
            ),
        ];

        for (algorithm, expected) in vectors {
            let mut incremental = NixHasher::new(algorithm);
            assert_eq!(incremental.algorithm(), algorithm);
            incremental.update(b"a");
            incremental.update(b"bc");
            let incremental = incremental.finalize();
            assert_eq!(encode_hex(incremental.digest_as_bytes()), expected);
            assert_eq!(hash_bytes(algorithm, b"abc"), incremental);
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
        assert!(matches!(
            CAHash::from_parts(ContentAddressMethod::Git, HashAlgorithm::Blake3, &[0; 32]),
            Err(Error::InvalidGitHashAlgorithm(_))
        ));
    }
}
