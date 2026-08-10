//! Typed Nix hashes and content addresses used by derivations.

use base64::Engine as _;
use thiserror::Error;

/// A malformed or unsupported hash.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("unknown hash algorithm {0:?}")]
    UnknownAlgo(String),
    #[error("digest has wrong length for {algo}: expected {expected}, got {got}")]
    WrongLength {
        algo: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("could not parse hash {0:?}")]
    Unparseable(String),
    #[error("Git content addressing requires SHA-1 or SHA-256, got {0}")]
    InvalidGitHashAlgorithm(String),
}

/// A digest tagged with the algorithm that produced it.
///
/// Each variant fixes the digest size at the type level, so an invalid
/// algorithm/digest combination cannot be represented.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NixHash {
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha512(Box<[u8; 64]>),
}

impl NixHash {
    /// Build from Nix's algorithm name and raw digest bytes.
    pub fn from_algo_and_digest(algo: &str, digest: &[u8]) -> Result<Self, Error> {
        fn fit<const N: usize>(algo: &'static str, digest: &[u8]) -> Result<[u8; N], Error> {
            digest.try_into().map_err(|_| Error::WrongLength {
                algo,
                expected: N,
                got: digest.len(),
            })
        }

        match algo {
            "md5" => Ok(Self::Md5(fit("md5", digest)?)),
            "sha1" => Ok(Self::Sha1(fit("sha1", digest)?)),
            "sha256" => Ok(Self::Sha256(fit("sha256", digest)?)),
            "sha512" => Ok(Self::Sha512(Box::new(fit("sha512", digest)?))),
            other => Err(Error::UnknownAlgo(other.to_owned())),
        }
    }

    /// Nix's canonical algorithm name.
    #[must_use]
    pub const fn algo(&self) -> &'static str {
        match self {
            Self::Md5(_) => "md5",
            Self::Sha1(_) => "sha1",
            Self::Sha256(_) => "sha256",
            Self::Sha512(_) => "sha512",
        }
    }

    #[must_use]
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
        format!("{}-{digest}", self.algo())
    }

    /// `algo:nixbase32`, as used by Nix's traditional hash format.
    #[must_use]
    pub fn to_nix_nixbase32_string(&self) -> String {
        format!(
            "{}:{}",
            self.algo(),
            crate::nixbase32::encode(self.digest_as_bytes())
        )
    }

    /// `algo:base16`, as used inside store-path fingerprints.
    #[must_use]
    pub fn to_nix_base16_string(&self) -> String {
        format!("{}:{}", self.algo(), encode_hex(self.digest_as_bytes()))
    }

    /// Parse SRI or `algo:` followed by Nix base32, base16, or base64.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if let Some((algo, encoded)) = input.split_once('-') {
            let expected = digest_len(algo)?;
            let digest = decode_base64(encoded)
                .filter(|digest| digest.len() == expected)
                .ok_or_else(|| Error::Unparseable(input.to_owned()))?;
            return Self::from_algo_and_digest(algo, &digest);
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
        Self::from_algo_and_digest(algo, &digest)
    }
}

fn digest_len(algo: &str) -> Result<usize, Error> {
    match algo {
        "md5" => Ok(16),
        "sha1" => Ok(20),
        "sha256" => Ok(32),
        "sha512" => Ok(64),
        other => Err(Error::UnknownAlgo(other.to_owned())),
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn hash(&self) -> NixHash {
        match self {
            Self::Flat(hash) | Self::Nar(hash) | Self::Git(hash) => hash.clone(),
            Self::Text(digest) => NixHash::Sha256(*digest),
        }
    }

    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Flat(_) => "flat",
            Self::Nar(_) => "nar",
            Self::Text(_) => "text",
            Self::Git(_) => "git",
        }
    }

    pub fn from_parts(method: &str, algo: &str, digest: &[u8]) -> Result<Self, Error> {
        match method {
            "flat" => Ok(Self::Flat(NixHash::from_algo_and_digest(algo, digest)?)),
            "nar" => Ok(Self::Nar(NixHash::from_algo_and_digest(algo, digest)?)),
            "text" => match NixHash::from_algo_and_digest(algo, digest)? {
                NixHash::Sha256(digest) => Ok(Self::Text(digest)),
                other => Err(Error::UnknownAlgo(format!(
                    "text content addressing is sha256 only, got {}",
                    other.algo()
                ))),
            },
            "git" => match NixHash::from_algo_and_digest(algo, digest)? {
                hash @ (NixHash::Sha1(_) | NixHash::Sha256(_)) => Ok(Self::Git(hash)),
                other => Err(Error::InvalidGitHashAlgorithm(other.algo().to_owned())),
            },
            other => Err(Error::Unparseable(format!(
                "unknown content-address method {other:?}"
            ))),
        }
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
            assert_eq!(NixHash::parse(encoded), Ok(hash.clone()), "{encoded}");
        }
    }

    #[test]
    fn rejects_wrong_digest_length() {
        assert!(matches!(
            NixHash::parse("sha256-AA=="),
            Err(Error::Unparseable(_))
        ));
        assert!(matches!(
            NixHash::from_algo_and_digest("sha1", &[0; 19]),
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

        let git = CAHash::from_parts("git", "sha1", &[0; 20]).unwrap();
        assert_eq!(
            git.to_nix_string(),
            format!("fixed:git:{}", git.hash().to_nix_nixbase32_string())
        );
        assert!(matches!(
            CAHash::from_parts("git", "md5", &[0; 16]),
            Err(Error::InvalidGitHashAlgorithm(_))
        ));
    }
}
