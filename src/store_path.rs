//! Validated Nix store paths and their construction algorithms.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::DerivationModuloHash;
use crate::hash::{CAHash, ContentAddressMethod, HashAlgorithm, NixHash};
use crate::nixbase32;

/// Default absolute directory containing Nix store objects.
pub const STORE_DIR: &str = "/nix/store";
/// Number of bytes in the compressed digest portion of a store path.
pub const DIGEST_LEN: usize = 20;
/// Maximum byte length of a Nix store-path name.
pub const MAX_NAME_LEN: usize = 211;

const DIGEST_CHARS: usize = 32;

/// Failure to parse or construct a Nix store path.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The configured store directory is not an absolute, lexically canonical path.
    #[error("invalid store directory {0:?}")]
    InvalidStoreDir(String),
    /// The supplied absolute path is outside the configured store directory.
    #[error("path is outside the configured store directory")]
    NotInStoreDir,
    /// The basename has no separator between its digest and name.
    #[error("store path has no `-` separating digest from name")]
    MissingSeparator,
    /// The digest portion is not canonical Nix base32.
    #[error("invalid digest: {0}")]
    InvalidDigest(#[from] nixbase32::Error),
    /// The name does not obey Nix's store-path name rules.
    #[error("invalid name {0:?}")]
    InvalidName(String),
    /// The content-address method and algorithm do not support references.
    #[error("{method} content addressing does not allow references with this hash algorithm")]
    ReferencesNotAllowed {
        /// Content-address method that rejected the references.
        method: ContentAddressMethod,
    },
    /// Git content addressing was paired with an unsupported hash algorithm.
    #[error("Git content addressing requires SHA-1 or SHA-256, got {0}")]
    InvalidGitHashAlgorithm(HashAlgorithm),
    /// Text content addresses cannot refer to their own result.
    #[error("text content addressing does not allow a self reference")]
    TextSelfReference,
    /// A downstream dynamic-output placeholder did not name an output edge.
    #[error("a downstream placeholder needs at least one output")]
    EmptyDownstreamOutputChain,
    /// A downstream dynamic-output placeholder did not start from a derivation.
    #[error("downstream placeholder base {path} does not name a derivation")]
    NotADerivation {
        /// Store path supplied as the downstream placeholder's base.
        path: StorePath,
    },
    /// A downstream dynamic-output placeholder used an invalid output name.
    #[error("invalid output name {0:?}")]
    InvalidOutputName(String),
}

/// A logical Nix store directory used for path parsing, rendering, and hashing.
///
/// Store paths contain only their digest and name. This value supplies the
/// absolute directory whose bytes participate in the full path and in Nix's
/// store-path fingerprints. [`Default`] selects [`STORE_DIR`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreDir(String);

impl Default for StoreDir {
    fn default() -> Self {
        Self(STORE_DIR.to_owned())
    }
}

impl fmt::Display for StoreDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for StoreDir {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::new(path)
    }
}

impl StoreDir {
    /// Validate and retain an absolute, lexically canonical store directory.
    pub fn new(path: impl Into<String>) -> Result<Self, Error> {
        let path = path.into();
        let valid = path == "/"
            || (path.starts_with('/')
                && !path.as_bytes().contains(&0)
                && !path.ends_with('/')
                && path.split('/').skip(1).all(|component| {
                    !component.is_empty() && component != "." && component != ".."
                }));
        if valid {
            Ok(Self(path))
        } else {
            Err(Error::InvalidStoreDir(path))
        }
    }

    /// Return the absolute logical store directory.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse an absolute store path using this logical store directory.
    pub fn parse_path(&self, path: &[u8]) -> Result<StorePath, Error> {
        let directory = self.0.as_bytes();
        let basename = if directory == b"/" {
            path.strip_prefix(b"/".as_slice())
        } else {
            path.strip_prefix(directory)
                .and_then(|rest| rest.strip_prefix(b"/".as_slice()))
        }
        .filter(|basename| !basename.is_empty())
        .ok_or(Error::NotInStoreDir)?;
        StorePath::from_basename(basename)
    }

    /// Render a complete absolute path in this logical store directory.
    #[must_use]
    pub fn render_path(&self, path: &StorePath) -> String {
        if self.0 == "/" {
            format!("/{}", path.to_basename())
        } else {
            format!("{}/{}", self.0, path.to_basename())
        }
    }

    /// Construct a text-addressed path in this logical store directory.
    pub fn build_text_path<'a, I>(
        &self,
        name: &str,
        content: &[u8],
        references: I,
    ) -> Result<StorePath, Error>
    where
        I: IntoIterator<Item = &'a StorePath>,
    {
        let references = references.into_iter().cloned().collect();
        let ty = make_type(self, "text", &references, false);
        let digest: [u8; 32] = Sha256::digest(content).into();
        make_store_path(self, &ty, &NixHash::Sha256(digest), name)
    }

    /// Construct a path from a Nix content address and its references.
    pub fn build_ca_path<'a, I>(
        &self,
        name: &str,
        ca: &CAHash,
        references: I,
        self_reference: bool,
    ) -> Result<StorePath, Error>
    where
        I: IntoIterator<Item = &'a StorePath>,
    {
        let references = references.into_iter().cloned().collect();
        match ca {
            CAHash::Text(digest) => {
                if self_reference {
                    return Err(Error::TextSelfReference);
                }
                make_store_path(
                    self,
                    &make_type(self, "text", &references, false),
                    &NixHash::Sha256(*digest),
                    name,
                )
            }
            CAHash::Nar(NixHash::Sha256(digest)) => make_store_path(
                self,
                &make_type(self, "source", &references, self_reference),
                &NixHash::Sha256(*digest),
                name,
            ),
            CAHash::Git(hash) if !matches!(hash, NixHash::Sha1(_) | NixHash::Sha256(_)) => {
                Err(Error::InvalidGitHashAlgorithm(hash.algorithm()))
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
                    hash.algorithm(),
                    encode_hex(hash.digest_as_bytes())
                );
                let digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
                make_store_path(self, "output:out", &NixHash::Sha256(digest), name)
            }
        }
    }

    /// Construct an input-addressed derivation output path in this store.
    pub fn build_output_path(
        &self,
        output_path_modulo: DerivationModuloHash,
        output_name: &str,
        drv_name: &str,
    ) -> Result<StorePath, Error> {
        let name = output_path_name(drv_name, output_name)?;
        make_store_path(
            self,
            &format!("output:{output_name}"),
            &NixHash::Sha256(output_path_modulo.into_bytes()),
            &name,
        )
    }
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
    /// Parse an absolute `/nix/store/<digest>-<name>` byte string.
    pub fn from_absolute_path(path: &[u8]) -> Result<Self, Error> {
        StoreDir::default().parse_path(path)
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

    /// Construct a store path from its compressed digest and validated name.
    pub fn from_parts(digest: [u8; DIGEST_LEN], name: &str) -> Result<Self, Error> {
        validate_name(name)?;
        Ok(Self {
            digest,
            name: name.to_owned(),
        })
    }

    #[must_use]
    /// Return the compressed 20-byte store-path digest.
    pub const fn digest(&self) -> &[u8; DIGEST_LEN] {
        &self.digest
    }

    #[must_use]
    /// Return the store-path name following the digest separator.
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    /// Whether this path's name has the `.drv` suffix.
    pub fn is_derivation(&self) -> bool {
        self.name.ends_with(".drv")
    }

    #[must_use]
    /// Render the complete absolute path, including [`STORE_DIR`].
    pub fn to_absolute_path(&self) -> String {
        self.to_string()
    }

    /// Render the complete absolute path in a configured logical store.
    #[must_use]
    pub fn to_absolute_path_in(&self, store_dir: &StoreDir) -> String {
        store_dir.render_path(self)
    }

    #[must_use]
    /// Render `<digest>-<name>` without [`STORE_DIR`].
    pub fn to_basename(&self) -> String {
        format!("{}-{}", nixbase32::encode(&self.digest), self.name)
    }
}

/// Construct a text-addressed path, including `.drv` files and
/// `builtins.toFile` values.
pub fn build_text_path<'a, I>(name: &str, content: &[u8], references: I) -> Result<StorePath, Error>
where
    I: IntoIterator<Item = &'a StorePath>,
{
    StoreDir::default().build_text_path(name, content, references)
}

/// Construct a path from a Nix content address and its references.
pub fn build_ca_path<'a, I>(
    name: &str,
    ca: &CAHash,
    references: I,
    self_reference: bool,
) -> Result<StorePath, Error>
where
    I: IntoIterator<Item = &'a StorePath>,
{
    StoreDir::default().build_ca_path(name, ca, references, self_reference)
}

/// Construct the path of an input-addressed derivation output.
pub fn build_output_path(
    output_path_modulo: DerivationModuloHash,
    output_name: &str,
    drv_name: &str,
) -> Result<StorePath, Error> {
    StoreDir::default().build_output_path(output_path_modulo, output_name, drv_name)
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

/// Return Nix's placeholder for an output reached through dynamic derivations.
///
/// `base` is the store path of the derivation where the chain begins and
/// `output_names` names its requested output followed by every dynamically
/// produced derivation output. The chain must be non-empty, every name must be
/// a valid Nix output name, and `base` must end in `.drv`.
///
/// The returned absolute-looking value is a placeholder, not a store path. It
/// starts with `/` and contains the 32-byte Nix-base32 SHA-256 digest used by
/// Nix 2.35 while resolving `xp-dyn-drv` inputs. It is independent of the
/// configured logical store directory.
pub fn downstream_placeholder<I, S>(base: &StorePath, output_names: I) -> Result<String, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut output_names = output_names.into_iter();
    let first = output_names
        .next()
        .ok_or(Error::EmptyDownstreamOutputChain)?;
    let first = first.as_ref();
    validate_output_name(first)?;

    let drv_name = base
        .name()
        .strip_suffix(".drv")
        .ok_or_else(|| Error::NotADerivation { path: base.clone() })?;
    let output_path_name = output_path_name(drv_name, first)?;
    let upstream_clear = format!(
        "nix-upstream-output:{}:{output_path_name}",
        nixbase32::encode(base.digest())
    );
    let mut digest: [u8; 32] = Sha256::digest(upstream_clear.as_bytes()).into();

    for output_name in output_names {
        let output_name = output_name.as_ref();
        validate_output_name(output_name)?;
        digest = downstream_placeholder_digest(digest, output_name);
    }

    Ok(format!("/{}", nixbase32::encode(&digest)))
}

fn validate_output_name(name: &str) -> Result<(), Error> {
    if name == "drv" || validate_name(name).is_err() {
        Err(Error::InvalidOutputName(name.to_owned()))
    } else {
        Ok(())
    }
}

fn downstream_placeholder_digest(previous: [u8; 32], output_name: &str) -> [u8; 32] {
    // Nix's `compressHash` XOR-folds the full SHA-256 into store-path width
    // before using it as the identity of the dynamically generated derivation.
    let mut compressed = [0_u8; DIGEST_LEN];
    for (index, byte) in previous.into_iter().enumerate() {
        compressed[index % compressed.len()] ^= byte;
    }
    let clear = format!(
        "nix-computed-output:{}:{output_name}",
        nixbase32::encode(&compressed)
    );
    Sha256::digest(clear.as_bytes()).into()
}

fn make_store_path(
    store_dir: &StoreDir,
    ty: &str,
    hash: &NixHash,
    name: &str,
) -> Result<StorePath, Error> {
    validate_name(name)?;
    let fingerprint = format!(
        "{ty}:{}:{}:{store_dir}:{name}",
        hash.algorithm(),
        encode_hex(hash.digest_as_bytes())
    );
    let full_digest = Sha256::digest(fingerprint.as_bytes());
    let mut digest = [0u8; DIGEST_LEN];
    for (index, byte) in full_digest.iter().enumerate() {
        digest[index % DIGEST_LEN] ^= byte;
    }
    StorePath::from_parts(digest, name)
}

fn make_type(
    store_dir: &StoreDir,
    prefix: &str,
    references: &BTreeSet<StorePath>,
    self_reference: bool,
) -> String {
    let mut ty = prefix.to_owned();
    for reference in references {
        ty.push(':');
        ty.push_str(&reference.to_absolute_path_in(store_dir));
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
    fn alternate_store_changes_identity_and_round_trips() {
        let alternate = StoreDir::new("/guix/store").unwrap();
        let default = build_text_path("hello", b"hello", std::iter::empty()).unwrap();
        let relocated = alternate
            .build_text_path("hello", b"hello", std::iter::empty())
            .unwrap();

        assert_ne!(default.digest(), relocated.digest());
        let rendered = relocated.to_absolute_path_in(&alternate);
        assert_eq!(rendered, format!("/guix/store/{}", relocated.to_basename()));
        assert_eq!(alternate.parse_path(rendered.as_bytes()), Ok(relocated));
        assert_eq!(
            StoreDir::default().parse_path(rendered.as_bytes()),
            Err(Error::NotInStoreDir)
        );
    }

    #[test]
    fn store_directory_must_be_lexically_canonical() {
        for valid in ["/", "/nix/store", "/guix/store"] {
            assert!(StoreDir::new(valid).is_ok(), "{valid:?}");
        }
        for invalid in [
            "",
            "relative/store",
            "/nix/store/",
            "/nix//store",
            "/nix/./store",
            "/nix/../store",
            "/nix/\0store",
        ] {
            assert!(StoreDir::new(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn store_directory_prefix_and_root_boundaries_are_unambiguous() {
        let store = StoreDir::new("/gnu/store").unwrap();
        let path = store
            .build_text_path("hello", b"hello", std::iter::empty())
            .unwrap();
        let basename = path.to_basename();

        assert_eq!(
            store.parse_path(format!("/gnu/store/{basename}").as_bytes()),
            Ok(path.clone())
        );
        assert_eq!(
            store.parse_path(format!("/gnu/store2/{basename}").as_bytes()),
            Err(Error::NotInStoreDir)
        );
        assert!(store.parse_path(b"/gnu/store").is_err());
        assert!(
            store
                .parse_path(format!("/gnu/store/{basename}/nested").as_bytes())
                .is_err()
        );

        let root = StoreDir::new("/").unwrap();
        let rendered = root.render_path(&path);
        assert_eq!(rendered, format!("/{basename}"));
        assert_eq!(root.parse_path(rendered.as_bytes()), Ok(path));
    }

    #[test]
    fn alternate_store_affects_every_store_path_construction_algorithm() {
        let alternate = StoreDir::new("/gnu/store").unwrap();
        let reference = StorePath::from_parts([1; DIGEST_LEN], "reference").unwrap();
        let ca = CAHash::Nar(NixHash::Sha256([2; 32]));
        let modulo = DerivationModuloHash::new([3; 32]);

        assert_ne!(
            build_text_path("text", b"content", [&reference]).unwrap(),
            alternate
                .build_text_path("text", b"content", [&reference])
                .unwrap()
        );
        assert_ne!(
            build_ca_path("source", &ca, [&reference], true).unwrap(),
            alternate
                .build_ca_path("source", &ca, [&reference], true)
                .unwrap()
        );
        assert_ne!(
            build_output_path(modulo, "out", "example").unwrap(),
            alternate
                .build_output_path(modulo, "out", "example")
                .unwrap()
        );
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
    fn downstream_placeholders_match_nix_2_35() {
        let base = StorePath::from_basename(b"g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo.drv").unwrap();
        assert_eq!(
            downstream_placeholder(&base, ["out"]).unwrap(),
            "/0c6rn30q4frawknapgwq386zq358m8r6msvywcvc89n6m5p2dgbz"
        );

        let nested =
            StorePath::from_basename(b"g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo.drv.drv").unwrap();
        let output_names = vec!["out".to_owned(), "out".to_owned()];
        assert_eq!(
            downstream_placeholder(&nested, output_names).unwrap(),
            "/0gn6agqxjyyalf0dpihgyf49xq5hqxgw100f0wydnj6yqrhqsb3w"
        );

        assert_eq!(
            downstream_placeholder(&nested, std::iter::repeat_n("out", 1_024))
                .unwrap()
                .len(),
            53
        );
    }

    #[test]
    fn downstream_placeholders_reject_invalid_inputs() {
        let derivation = StorePath::from_parts([0; DIGEST_LEN], "example.drv").unwrap();
        assert_eq!(
            downstream_placeholder(&derivation, Vec::<&str>::new()),
            Err(Error::EmptyDownstreamOutputChain)
        );
        assert_eq!(
            downstream_placeholder(&derivation, ["bad output"]),
            Err(Error::InvalidOutputName("bad output".to_owned()))
        );
        assert_eq!(
            downstream_placeholder(&derivation, ["drv"]),
            Err(Error::InvalidOutputName("drv".to_owned()))
        );

        let non_derivation = StorePath::from_parts([0; DIGEST_LEN], "not-a-drv").unwrap();
        assert_eq!(
            downstream_placeholder(&non_derivation, ["out"]),
            Err(Error::NotADerivation {
                path: non_derivation,
            })
        );
    }

    #[test]
    fn reference_order_and_duplicates_do_not_change_paths() {
        let a = StorePath::from_parts([1; DIGEST_LEN], "a").unwrap();
        let b = StorePath::from_parts([2; DIGEST_LEN], "b").unwrap();
        let left = build_text_path("x", b"x", [&a, &b, &a]).unwrap();
        let right = build_text_path("x", b"x", [&b, &a]).unwrap();
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
            Err(Error::InvalidGitHashAlgorithm(HashAlgorithm::Md5))
        ));
    }
}
