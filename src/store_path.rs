//! Validated Nix store paths and their construction algorithms.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::hash::{CAHash, NixHash};
use crate::nixbase32;

pub const STORE_DIR: &str = "/nix/store";
pub const DIGEST_LEN: usize = 20;
pub const MAX_NAME_LEN: usize = 211;

const DIGEST_CHARS: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("path does not start with {STORE_DIR}/")]
    NotInStoreDir,
    #[error("store path has no `-` separating digest from name")]
    MissingSeparator,
    #[error("invalid digest: {0}")]
    InvalidDigest(#[from] nixbase32::Error),
    #[error("invalid name {0:?}")]
    InvalidName(String),
    #[error("invalid store-path reference {0:?}")]
    InvalidReference(String),
    #[error("{method} content addressing does not allow references with this hash algorithm")]
    ReferencesNotAllowed { method: &'static str },
    #[error("Git content addressing requires SHA-1 or SHA-256, got {0}")]
    InvalidGitHashAlgorithm(&'static str),
    #[error("text content addressing does not allow a self reference")]
    TextSelfReference,
}

/// A validated Nix store path basename: a 20-byte digest and a name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorePath {
    digest: [u8; DIGEST_LEN],
    name: String,
}

impl PartialOrd for StorePath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StorePath {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.digest == other.digest {
            return self.name.cmp(&other.name);
        }
        nixbase32::cmp_encoded(&self.digest, &other.digest).then_with(|| self.name.cmp(&other.name))
    }
}

impl fmt::Display for StorePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{STORE_DIR}/{}-{}",
            nixbase32::encode(&self.digest),
            self.name
        )
    }
}

impl FromStr for StorePath {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::from_absolute_path(path.as_bytes())
    }
}

pub(crate) fn validate_name(name: &str) -> Result<(), Error> {
    let invalid_dot_component =
        name == "." || name == ".." || name.starts_with(".-") || name.starts_with("..-");
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !invalid_dot_component
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
        });
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidName(name.to_owned()))
    }
}

impl StorePath {
    pub fn from_absolute_path(path: &[u8]) -> Result<Self, Error> {
        let prefix_len = const { STORE_DIR.len() + 1 };
        if path.len() <= prefix_len
            || &path[..STORE_DIR.len()] != STORE_DIR.as_bytes()
            || path[STORE_DIR.len()] != b'/'
        {
            return Err(Error::NotInStoreDir);
        }
        Self::from_basename(&path[prefix_len..])
    }

    /// Parse `<digest>-<name>` without the store directory.
    pub fn from_basename(basename: &[u8]) -> Result<Self, Error> {
        if basename.len() <= DIGEST_CHARS || basename[DIGEST_CHARS] != b'-' {
            return Err(Error::MissingSeparator);
        }
        let digest = nixbase32::decode_fixed(&basename[..DIGEST_CHARS])?;
        let name = std::str::from_utf8(&basename[DIGEST_CHARS + 1..])
            .map_err(|_| Error::InvalidName(String::from_utf8_lossy(basename).into_owned()))?;
        Self::from_parts(digest, name)
    }

    pub fn from_parts(digest: [u8; DIGEST_LEN], name: &str) -> Result<Self, Error> {
        validate_name(name)?;
        Ok(Self {
            digest,
            name: name.to_owned(),
        })
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; DIGEST_LEN] {
        &self.digest
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn is_derivation(&self) -> bool {
        self.name.ends_with(".drv")
    }

    #[must_use]
    pub fn to_absolute_path(&self) -> String {
        self.to_string()
    }

    #[must_use]
    pub fn to_basename(&self) -> String {
        format!("{}-{}", nixbase32::encode(&self.digest), self.name)
    }
}

/// Construct a text-addressed path, including `.drv` files and
/// `builtins.toFile` values.
pub fn build_text_path<'a, I>(name: &str, content: &[u8], references: I) -> Result<StorePath, Error>
where
    I: IntoIterator<Item = &'a str>,
{
    let references = parse_references(references)?;
    let ty = make_type("text", &references, false);
    let digest: [u8; 32] = Sha256::digest(content).into();
    make_store_path(&ty, &NixHash::Sha256(digest), name)
}

/// Construct a path from a Nix content address and its references.
pub fn build_ca_path<'a, I>(
    name: &str,
    ca: &CAHash,
    references: I,
    self_reference: bool,
) -> Result<StorePath, Error>
where
    I: IntoIterator<Item = &'a str>,
{
    let references = parse_references(references)?;
    match ca {
        CAHash::Text(digest) => {
            if self_reference {
                return Err(Error::TextSelfReference);
            }
            make_store_path(
                &make_type("text", &references, false),
                &NixHash::Sha256(*digest),
                name,
            )
        }
        CAHash::Nar(NixHash::Sha256(digest)) => make_store_path(
            &make_type("source", &references, self_reference),
            &NixHash::Sha256(*digest),
            name,
        ),
        CAHash::Git(hash) if !matches!(hash, NixHash::Sha1(_) | NixHash::Sha256(_)) => {
            Err(Error::InvalidGitHashAlgorithm(hash.algo()))
        }
        CAHash::Flat(hash) | CAHash::Nar(hash) | CAHash::Git(hash) => {
            if !references.is_empty() || self_reference {
                return Err(Error::ReferencesNotAllowed {
                    method: ca.method(),
                });
            }
            let ingestion_prefix = match ca {
                CAHash::Flat(_) => "",
                CAHash::Nar(_) => "r:",
                CAHash::Git(_) => "git:",
                CAHash::Text(_) => unreachable!(),
            };
            let payload = format!(
                "fixed:out:{ingestion_prefix}{}:{}:",
                hash.algo(),
                encode_hex(hash.digest_as_bytes())
            );
            let digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
            make_store_path("output:out", &NixHash::Sha256(digest), name)
        }
    }
}

/// Construct the path of an input-addressed derivation output.
pub fn build_output_path(
    output_path_modulo: &[u8; 32],
    output_name: &str,
    drv_name: &str,
) -> Result<StorePath, Error> {
    let name = output_path_name(drv_name, output_name)?;
    make_store_path(
        &format!("output:{output_name}"),
        &NixHash::Sha256(*output_path_modulo),
        &name,
    )
}

/// Return `drv_name` for `out`, or `<drv_name>-<output_name>` otherwise.
pub fn output_path_name(drv_name: &str, output_name: &str) -> Result<String, Error> {
    let name = if output_name == "out" {
        drv_name.to_owned()
    } else {
        format!("{drv_name}-{output_name}")
    };
    validate_name(&name)?;
    Ok(name)
}

/// Return the value produced by `builtins.placeholder output_name`.
#[must_use]
pub fn hash_placeholder(output_name: &str) -> String {
    let digest = Sha256::digest(format!("nix-output:{output_name}").as_bytes());
    format!("/{}", nixbase32::encode(&digest))
}

fn make_store_path(ty: &str, hash: &NixHash, name: &str) -> Result<StorePath, Error> {
    validate_name(name)?;
    let fingerprint = format!(
        "{ty}:{}:{}:{STORE_DIR}:{name}",
        hash.algo(),
        encode_hex(hash.digest_as_bytes())
    );
    let full_digest = Sha256::digest(fingerprint.as_bytes());
    let mut digest = [0u8; DIGEST_LEN];
    for (index, byte) in full_digest.iter().enumerate() {
        digest[index % DIGEST_LEN] ^= byte;
    }
    StorePath::from_parts(digest, name)
}

fn parse_references<'a, I>(references: I) -> Result<BTreeSet<StorePath>, Error>
where
    I: IntoIterator<Item = &'a str>,
{
    references
        .into_iter()
        .map(|reference| {
            StorePath::from_absolute_path(reference.as_bytes())
                .map_err(|_| Error::InvalidReference(reference.to_owned()))
        })
        .collect()
}

fn make_type(prefix: &str, references: &BTreeSet<StorePath>, self_reference: bool) -> String {
    let mut ty = prefix.to_owned();
    for reference in references {
        ty.push(':');
        ty.push_str(&reference.to_absolute_path());
    }
    if self_reference {
        ty.push_str(":self");
    }
    ty
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_round_trip() {
        let path = StorePath::from_parts([42; DIGEST_LEN], "hello-1.0").unwrap();
        assert_eq!(
            StorePath::from_absolute_path(path.to_absolute_path().as_bytes()),
            Ok(path.clone())
        );
        assert_eq!(path.to_absolute_path().parse(), Ok(path));
    }

    #[test]
    fn validates_names_like_nix() {
        for valid in ["hello", ".hidden", "...", "foo?bar=baz"] {
            assert!(StorePath::from_parts([0; DIGEST_LEN], valid).is_ok());
        }
        for invalid in ["", ".", "..", ".-foo", "..-foo", "has space"] {
            assert!(StorePath::from_parts([0; DIGEST_LEN], invalid).is_err());
        }
        assert!(StorePath::from_parts([0; DIGEST_LEN], &"x".repeat(212)).is_err());
    }

    #[test]
    fn text_path_known_answer() {
        let path = build_text_path("hello", b"hello", std::iter::empty()).unwrap();
        assert_eq!(
            path.to_absolute_path(),
            "/nix/store/i4f75pn3bxkxdk2kld86k5qazq4cqj8i-hello"
        );
    }

    #[test]
    fn placeholder_matches_nix() {
        assert_eq!(
            hash_placeholder("out"),
            "/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
        );
    }

    #[test]
    fn reference_order_and_duplicates_do_not_change_paths() {
        let a = StorePath::from_parts([1; DIGEST_LEN], "a")
            .unwrap()
            .to_absolute_path();
        let b = StorePath::from_parts([2; DIGEST_LEN], "b")
            .unwrap()
            .to_absolute_path();
        let left = build_text_path("x", b"x", [&a[..], &b[..], &a[..]]).unwrap();
        let right = build_text_path("x", b"x", [&b[..], &a[..]]).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn git_paths_accept_only_git_hash_algorithms() {
        assert!(
            build_ca_path(
                "git-tree",
                &CAHash::Git(NixHash::Sha1([0; 20])),
                std::iter::empty(),
                false,
            )
            .is_ok()
        );
        assert!(matches!(
            build_ca_path(
                "git-tree",
                &CAHash::Git(NixHash::Md5([0; 16])),
                std::iter::empty(),
                false,
            ),
            Err(Error::InvalidGitHashAlgorithm("md5"))
        ));
    }
}
