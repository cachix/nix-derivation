//! Pure Rust Nix derivations.
//!
//! The `ATerm` representation is identity-bearing: its bytes determine the
//! derivation's store path and participate in output-path hashing. Parsing is
//! therefore byte-oriented and serialization follows Nix's canonical field
//! order, escaping, and map ordering exactly.
//!
//! # Example
//!
//! ```
//! use nix_derivation::DerivationBuilder;
//!
//! let derivation = DerivationBuilder::new("example", "x86_64-linux", "/bin/sh")
//!     .input_addressed_output("out")
//!     .argument("-c")
//!     .argument("printf built > $out")
//!     .build()?;
//!
//! assert!(derivation.resolved_outputs()["out"].path.is_some());
//! # Ok::<(), nix_derivation::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

mod builder;
pub mod hash;
pub mod nixbase32;
mod parser;
pub mod store_path;
pub mod structured_attrs;
mod write;

pub use builder::{DerivationBuilder, ValidatedDerivation};
pub use hash::{CAHash, ContentAddressMethod, HashAlgorithm, NixHash};
pub use store_path::StorePath;
pub use structured_attrs::{StructuredAttrs, StructuredAttrsFiles};

#[cfg(test)]
mod tests;

/// A derivation parse or semantic error.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The byte input is not a well-formed supported derivation `ATerm`.
    #[error("ATerm parse error at byte {offset}: {message}")]
    Parse {
        /// Byte offset at which parsing failed.
        offset: usize,
        /// Human-readable description of the expected syntax.
        message: String,
    },
    /// A textual derivation field contains non-UTF-8 bytes.
    #[error("{field} is not valid UTF-8")]
    InvalidUtf8 {
        /// Name of the field containing invalid bytes.
        field: &'static str,
    },
    /// A derivation field contains a malformed Nix store path.
    #[error("invalid store path in derivation: {0}")]
    InvalidStorePath(#[from] store_path::Error),
    /// A derivation output contains a malformed or unsupported content hash.
    #[error("invalid content hash in derivation: {0}")]
    InvalidHash(#[from] hash::Error),
    /// The structured-attribute JSON or requested file materialization is invalid.
    #[error("invalid structured attributes: {0}")]
    StructuredAttrs(String),
    /// A fixed-output derivation does not have exactly one output named `out`.
    #[error(
        "fixed output derivation {name:?} has {outputs} outputs, expected exactly one named \"out\""
    )]
    InvalidFixedOutputs {
        /// Derivation name.
        name: String,
        /// Number of declared outputs.
        outputs: usize,
    },
    /// A parsed derivation violates a semantic build invariant.
    #[error("invalid derivation: {0}")]
    InvalidDerivation(String),
}

/// Failure while resolving an input during derivation hashing or validation.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputResolutionError<E> {
    /// The derivation itself is malformed or semantically invalid.
    #[error(transparent)]
    Derivation(#[from] Error),
    /// The caller's resolver failed for a particular input derivation.
    #[error("failed to resolve input derivation {path}: {error}")]
    Resolve {
        /// Input derivation whose identity was requested.
        path: StorePath,
        /// Error returned by the resolver callback.
        error: E,
    },
}

/// A SHA-256 digest used by Nix's derivation-modulo hashing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivationModuloHash([u8; 32]);

impl DerivationModuloHash {
    /// Wrap raw SHA-256 digest bytes as a derivation-modulo hash.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw SHA-256 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the newtype and return the raw SHA-256 digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for DerivationModuloHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl From<DerivationModuloHash> for [u8; 32] {
    fn from(hash: DerivationModuloHash) -> Self {
        hash.into_bytes()
    }
}

impl AsRef<[u8; 32]> for DerivationModuloHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl fmt::Display for DerivationModuloHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The identity of a derivation when it is used as an input.
///
/// Input-addressed derivations have a regular hash, fixed-output derivations
/// have a content-derived hash, and derivations whose inputs or outputs have
/// not been resolved yet are deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDerivationHash {
    /// Identity of an ordinary input-addressed derivation.
    Regular(DerivationModuloHash),
    /// Content-derived identity of a fixed-output derivation.
    FixedOutput(DerivationModuloHash),
    /// Identity cannot be calculated until another input or output is resolved.
    Deferred,
}

impl From<[u8; 32]> for InputDerivationHash {
    fn from(hash: [u8; 32]) -> Self {
        Self::regular(hash)
    }
}

impl From<DerivationModuloHash> for InputDerivationHash {
    fn from(hash: DerivationModuloHash) -> Self {
        Self::Regular(hash)
    }
}

impl InputDerivationHash {
    /// Construct an ordinary input-addressed identity.
    #[must_use]
    pub fn regular(hash: impl Into<DerivationModuloHash>) -> Self {
        Self::Regular(hash.into())
    }

    /// Construct a fixed-output identity.
    #[must_use]
    pub fn fixed_output(hash: impl Into<DerivationModuloHash>) -> Self {
        Self::FixedOutput(hash.into())
    }

    /// Return the regular hash, if this is an input-addressed identity.
    #[must_use]
    pub const fn regular_hash(&self) -> Option<&DerivationModuloHash> {
        match self {
            Self::Regular(hash) => Some(hash),
            Self::FixedOutput(_) | Self::Deferred => None,
        }
    }

    /// Return the fixed-output hash, if this is a fixed-output identity.
    #[must_use]
    pub const fn fixed_output_hash(&self) -> Option<&DerivationModuloHash> {
        match self {
            Self::FixedOutput(hash) => Some(hash),
            Self::Regular(_) | Self::Deferred => None,
        }
    }

    /// Whether this identity still depends on unresolved information.
    #[must_use]
    pub const fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred)
    }
}

/// State of the hash used to construct input-addressed output paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputPathHash {
    /// A quotient hash that can be used to construct output paths.
    Ready(DerivationModuloHash),
    /// The hash depends on an unresolved dynamic or content-addressed input.
    Deferred,
}

impl From<DerivationModuloHash> for OutputPathHash {
    fn from(hash: DerivationModuloHash) -> Self {
        Self::Ready(hash)
    }
}

impl OutputPathHash {
    /// Construct a ready output-path hash.
    #[must_use]
    pub fn ready(hash: impl Into<DerivationModuloHash>) -> Self {
        Self::Ready(hash.into())
    }

    /// Borrow the ready hash, or return `None` when deferred.
    #[must_use]
    pub const fn as_ready(&self) -> Option<&DerivationModuloHash> {
        match self {
            Self::Ready(hash) => Some(hash),
            Self::Deferred => None,
        }
    }

    /// Consume this state and return the ready hash, or `None` when deferred.
    #[must_use]
    pub const fn into_ready(self) -> Option<DerivationModuloHash> {
        match self {
            Self::Ready(hash) => Some(hash),
            Self::Deferred => None,
        }
    }

    /// Whether calculating this hash requires more information.
    #[must_use]
    pub const fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred)
    }
}

/// The five output variants represented by Nix 2.34 derivation `ATerms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// An input-addressed output whose path is known before building.
    InputAddressed {
        /// Declared output store path.
        path: StorePath,
    },
    /// A fixed output addressed by an expected content hash.
    Fixed {
        /// Expected content address.
        ca: CAHash,
    },
    /// A pure content-addressed output whose digest is known after building.
    Floating {
        /// How the output is ingested before hashing.
        method: ContentAddressMethod,
        /// Algorithm used to hash the ingested output.
        hash_algorithm: HashAlgorithm,
    },
    /// An input-addressed output that cannot yet be resolved.
    Deferred,
    /// An impure output accepted from an external source after building.
    Impure {
        /// How the output is ingested before hashing.
        method: ContentAddressMethod,
        /// Algorithm used to hash the ingested output.
        hash_algorithm: HashAlgorithm,
    },
}

impl Output {
    /// The path known before building, if any.
    pub fn path(
        &self,
        derivation_name: &str,
        output_name: &str,
    ) -> Result<Option<StorePath>, Error> {
        match self {
            Self::InputAddressed { path } => Ok(Some(path.clone())),
            Self::Fixed { ca } => {
                let name = store_path::output_path_name(derivation_name, output_name)?;
                Ok(Some(store_path::build_ca_path(
                    &name,
                    ca,
                    std::iter::empty::<&StorePath>(),
                    false,
                )?))
            }
            Self::Floating { .. } | Self::Deferred | Self::Impure { .. } => Ok(None),
        }
    }

    #[must_use]
    /// Return the expected content address for a fixed output.
    pub const fn fixed_content_address(&self) -> Option<&CAHash> {
        match self {
            Self::Fixed { ca } => Some(ca),
            _ => None,
        }
    }
}

/// Flattened output view for build translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationOutput {
    /// Store path known before building, if this output kind has one.
    pub path: Option<StorePath>,
    /// Expected fixed content address, if this is a fixed output.
    pub ca_hash: Option<CAHash>,
}

/// One node in Nix's input-derivation trie.
///
/// `outputs` are requested directly from this derivation. Each
/// `dynamic_outputs` entry follows an output which itself evaluates to a
/// derivation, as represented by the `xp-dyn-drv` `ATerm` format.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InputDerivation {
    outputs: BTreeSet<String>,
    dynamic_outputs: BTreeMap<String, InputDerivation>,
}

/// Maximum recursive dynamic-input depth accepted from `ATerms` or builders.
pub const MAX_DYNAMIC_INPUT_DEPTH: usize = 256;

impl InputDerivation {
    /// Construct a leaf requesting the supplied output names.
    pub fn new<I, S>(outputs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            outputs: outputs.into_iter().map(Into::into).collect(),
            dynamic_outputs: BTreeMap::new(),
        }
    }

    /// Add a recursively requested dynamic output and return the updated value.
    pub fn with_dynamic_output(
        mut self,
        name: impl Into<String>,
        input: InputDerivation,
    ) -> Result<Self, Error> {
        self.insert_dynamic_output(name, input)?;
        Ok(self)
    }

    /// Request one direct output, returning whether it was newly inserted.
    pub fn insert_output(&mut self, output: impl Into<String>) -> bool {
        self.outputs.insert(output.into())
    }

    /// Insert a recursively requested dynamic output.
    ///
    /// The returned value is the previous subtree with the same name, if any.
    pub fn insert_dynamic_output(
        &mut self,
        name: impl Into<String>,
        input: InputDerivation,
    ) -> Result<Option<InputDerivation>, Error> {
        if input.max_depth() >= MAX_DYNAMIC_INPUT_DEPTH {
            return Err(Error::InvalidDerivation(format!(
                "dynamic input derivation nesting exceeds {MAX_DYNAMIC_INPUT_DEPTH} levels"
            )));
        }
        Ok(self.dynamic_outputs.insert(name.into(), input))
    }

    /// Outputs requested directly from this input derivation.
    #[must_use]
    pub fn outputs(&self) -> &BTreeSet<String> {
        &self.outputs
    }

    /// Recursive derivations reached through a dynamically produced output.
    #[must_use]
    pub fn dynamic_outputs(&self) -> &BTreeMap<String, InputDerivation> {
        &self.dynamic_outputs
    }

    #[must_use]
    /// Whether this input follows any dynamically produced derivations.
    pub fn is_dynamic(&self) -> bool {
        !self.dynamic_outputs.is_empty()
    }

    /// Walk this input and all recursively requested dynamic inputs in
    /// depth-first, lexicographic edge-name order.
    #[must_use]
    pub fn walk(&self) -> InputDerivationWalk<'_> {
        InputDerivationWalk {
            stack: vec![(0, None, self)],
        }
    }

    /// Deepest dynamic edge below this node. A leaf has depth zero.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.walk().map(|node| node.depth).max().unwrap_or(0)
    }
}

/// One item yielded by [`InputDerivation::walk`].
#[derive(Debug, Clone, Copy)]
pub struct InputDerivationNode<'a> {
    depth: usize,
    dynamic_output: Option<&'a str>,
    input: &'a InputDerivation,
}

impl<'a> InputDerivationNode<'a> {
    /// Number of dynamic-output edges between this node and the root.
    #[must_use]
    pub const fn depth(self) -> usize {
        self.depth
    }

    /// Dynamic output followed from the parent, or `None` for the root node.
    #[must_use]
    pub const fn dynamic_output(self) -> Option<&'a str> {
        self.dynamic_output
    }

    /// Return the input-derivation node at this position.
    #[must_use]
    pub const fn input(self) -> &'a InputDerivation {
        self.input
    }
}

/// Depth-first iterator over a recursive input-derivation tree.
#[derive(Debug, Clone)]
pub struct InputDerivationWalk<'a> {
    stack: Vec<(usize, Option<&'a str>, &'a InputDerivation)>,
}

impl<'a> Iterator for InputDerivationWalk<'a> {
    type Item = InputDerivationNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (depth, dynamic_output, input) = self.stack.pop()?;
        self.stack.extend(
            input
                .dynamic_outputs
                .iter()
                .rev()
                .map(|(name, child)| (depth + 1, Some(name.as_str()), child)),
        );
        Some(InputDerivationNode {
            depth,
            dynamic_output,
            input,
        })
    }
}

/// One parsed `Derive(...)` or `DrvWithVersion("xp-dyn-drv",...)` value.
#[derive(Debug, Clone)]
pub struct Derivation {
    name: String,
    outputs: BTreeMap<String, Output>,
    input_derivations: BTreeMap<StorePath, InputDerivation>,
    input_sources: BTreeSet<StorePath>,
    system: String,
    builder: String,
    arguments: Vec<String>,
    environment: BTreeMap<String, Vec<u8>>,
    structured_attrs: Option<structured_attrs::StructuredAttrs>,
    aterm_size_hint: usize,
}

impl PartialEq for Derivation {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.outputs == other.outputs
            && self.input_derivations == other.input_derivations
            && self.input_sources == other.input_sources
            && self.system == other.system
            && self.builder == other.builder
            && self.arguments == other.arguments
            && self.environment == other.environment
            && self.structured_attrs == other.structured_attrs
    }
}

impl Eq for Derivation {}

impl Derivation {
    /// Parse one derivation ATerm. `name` is carried out of band by Nix and
    /// excludes the `.drv` suffix.
    pub fn from_aterm_bytes(bytes: &[u8], name: &str) -> Result<Self, Error> {
        parser::parse(bytes, name)
    }

    /// Consume this value for editing. [`DerivationBuilder::build`] validates
    /// the edited result before returning it.
    pub fn into_builder(self) -> DerivationBuilder {
        DerivationBuilder::from_derivation(self)
    }

    /// Check semantic invariants and wrap this value as validated.
    pub fn into_validated(self) -> Result<ValidatedDerivation, Error> {
        ValidatedDerivation::try_from(self)
    }

    /// Check semantic invariants using the modulo hashes of input derivations.
    ///
    /// Nix needs store access to validate input-addressed output paths when a
    /// derivation has input derivations. This variant supplies the equivalent
    /// information without coupling the crate to a store implementation.
    pub fn into_validated_with_input_hashes<F, H>(
        self,
        mut resolve: F,
    ) -> Result<ValidatedDerivation, Error>
    where
        F: FnMut(&StorePath) -> H,
        H: Into<InputDerivationHash>,
    {
        match self.try_into_validated_with_input_hashes(|path| {
            Ok::<_, std::convert::Infallible>(resolve(path).into())
        }) {
            Ok(derivation) => Ok(derivation),
            Err(InputResolutionError::Derivation(error)) => Err(error),
            Err(InputResolutionError::Resolve { error, .. }) => match error {},
        }
    }

    /// Fallible form of [`Self::into_validated_with_input_hashes`].
    pub fn try_into_validated_with_input_hashes<F, E, H>(
        self,
        resolve: F,
    ) -> Result<ValidatedDerivation, InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        ValidatedDerivation::try_from_with_input_hashes(self, resolve)
    }

    #[must_use]
    /// Return the out-of-band derivation name without the `.drv` suffix.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Outputs in their lossless `ATerm` representation.
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<String, Output> {
        &self.outputs
    }

    /// Write Nix's canonical unmasked `ATerm` representation.
    pub fn write_aterm<W: io::Write + ?Sized>(&self, writer: &mut W) -> io::Result<()> {
        write::serialize(self, writer)
    }

    /// Serialize using Nix's canonical unmasked representation.
    #[must_use]
    pub fn to_aterm_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.aterm_size_hint);
        self.write_aterm(&mut bytes)
            .expect("writing a derivation to Vec cannot fail");
        bytes
    }

    /// Input derivations including recursively requested dynamic outputs.
    #[must_use]
    pub fn input_derivations(&self) -> &BTreeMap<StorePath, InputDerivation> {
        &self.input_derivations
    }

    #[must_use]
    /// Input source store paths referenced directly by this derivation.
    pub fn input_sources(&self) -> &BTreeSet<StorePath> {
        &self.input_sources
    }

    /// Flatten outputs into the paths and fixed content addresses needed by a
    /// build system. Floating, deferred, and impure outputs have no path.
    pub fn resolved_outputs(&self) -> Result<BTreeMap<String, DerivationOutput>, Error> {
        self.outputs
            .iter()
            .map(|(name, output)| {
                Ok((
                    name.clone(),
                    DerivationOutput {
                        path: output.path(&self.name, name)?,
                        ca_hash: output.fixed_content_address().cloned(),
                    },
                ))
            })
            .collect()
    }

    /// Compute this derivation's identity when used as an input derivation.
    pub fn hash_input_derivation_modulo<F, H>(
        &self,
        mut resolve: F,
    ) -> Result<InputDerivationHash, Error>
    where
        F: FnMut(&StorePath) -> H,
        H: Into<InputDerivationHash>,
    {
        match self.try_hash_input_derivation_modulo(|path| {
            Ok::<_, std::convert::Infallible>(resolve(path).into())
        }) {
            Ok(hash) => Ok(hash),
            Err(InputResolutionError::Derivation(error)) => Err(error),
            Err(InputResolutionError::Resolve { error, .. }) => match error {},
        }
    }

    /// Fallible form of [`Self::hash_input_derivation_modulo`].
    pub fn try_hash_input_derivation_modulo<F, E, H>(
        &self,
        mut resolve: F,
    ) -> Result<InputDerivationHash, InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        match self.output_type()? {
            OutputType::Fixed => {
                let output = self
                    .outputs
                    .get("out")
                    .expect("output_type checked the fixed output name");
                let Output::Fixed { ca } = output else {
                    unreachable!("output_type checked fixed outputs")
                };
                let path = output
                    .path(&self.name, "out")?
                    .expect("fixed output has a path");
                return Ok(InputDerivationHash::fixed_output(fixed_output_hash(
                    ca, &path,
                )));
            }
            OutputType::InputAddressed => {}
            OutputType::Floating(_) | OutputType::Deferred | OutputType::Impure => {
                return Ok(InputDerivationHash::Deferred);
            }
        }

        let Some(actual_inputs) = self.try_modulo_inputs(&mut resolve)? else {
            return Ok(InputDerivationHash::Deferred);
        };

        let mut writer = HashWriter(Sha256::new());
        write::serialize_input_modulo(self, &mut writer, &actual_inputs)
            .expect("hash writer cannot fail");
        Ok(InputDerivationHash::regular(<[u8; 32]>::from(
            writer.0.finalize(),
        )))
    }

    /// Compute the quotient hash used to construct this derivation's own
    /// input-addressed output paths.
    ///
    /// [`OutputPathHash::Deferred`] means that a dynamic or
    /// content-addressed input must be resolved first. Other output types do
    /// not have an input-addressed output hash.
    pub fn hash_output_path_modulo<F, H>(&self, mut resolve: F) -> Result<OutputPathHash, Error>
    where
        F: FnMut(&StorePath) -> H,
        H: Into<InputDerivationHash>,
    {
        match self.try_hash_output_path_modulo(|path| {
            Ok::<_, std::convert::Infallible>(resolve(path).into())
        }) {
            Ok(hash) => Ok(hash),
            Err(InputResolutionError::Derivation(error)) => Err(error),
            Err(InputResolutionError::Resolve { error, .. }) => match error {},
        }
    }

    /// Fallible form of [`Self::hash_output_path_modulo`].
    pub fn try_hash_output_path_modulo<F, E, H>(
        &self,
        mut resolve: F,
    ) -> Result<OutputPathHash, InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        match self.output_type()? {
            OutputType::InputAddressed | OutputType::Deferred => {}
            OutputType::Fixed | OutputType::Floating(_) | OutputType::Impure => {
                return Err(Error::InvalidDerivation(
                    "only input-addressed derivations have an output-path modulo hash".to_owned(),
                )
                .into());
            }
        }
        let Some(actual_inputs) = self.try_modulo_inputs(&mut resolve)? else {
            return Ok(OutputPathHash::Deferred);
        };
        let mut writer = HashWriter(Sha256::new());
        write::serialize_output_modulo(self, &mut writer, &actual_inputs)
            .expect("hash writer cannot fail");
        Ok(OutputPathHash::ready(<[u8; 32]>::from(writer.0.finalize())))
    }

    fn try_modulo_inputs<F, E, H>(
        &self,
        mut resolve: F,
    ) -> Result<Option<write::HashModuloInputs>, InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        if self
            .input_derivations
            .values()
            .any(InputDerivation::is_dynamic)
        {
            return Ok(None);
        }

        let mut actual_inputs = write::HashModuloInputs::new();
        for (path, input) in &self.input_derivations {
            let input_hash = resolve(path)
                .map_err(|error| InputResolutionError::Resolve {
                    path: path.clone(),
                    error,
                })?
                .into();
            match input_hash {
                InputDerivationHash::Regular(hash) => {
                    actual_inputs.insert(hash, input.outputs.clone());
                }
                InputDerivationHash::FixedOutput(hash) => {
                    for output in &input.outputs {
                        if output != "out" {
                            return Err(Error::InvalidDerivation(format!(
                                "fixed-output input derivation {} cannot provide requested output {output:?}",
                                path.to_absolute_path()
                            ))
                            .into());
                        }
                        actual_inputs.insert(hash, BTreeSet::from(["out".to_owned()]));
                    }
                }
                InputDerivationHash::Deferred => return Ok(None),
            }
        }
        Ok(Some(actual_inputs))
    }

    /// Calculate this derivation's own `.drv` store path.
    pub fn drv_path(&self) -> Result<StorePath, Error> {
        let bytes = self.to_aterm_bytes();
        Ok(store_path::build_text_path(
            &format!("{}.drv", self.name),
            &bytes,
            self.input_derivations
                .keys()
                .chain(self.input_sources.iter()),
        )?)
    }

    /// Determine whether this has the single fixed-output derivation shape.
    pub fn is_fixed_output(&self) -> Result<bool, Error> {
        Ok(matches!(self.output_type()?, OutputType::Fixed))
    }

    /// Validate the semantic invariants expected by Nix/Snix consumers.
    ///
    /// Parsing is deliberately separate: Nix's parser can round-trip some
    /// characterization fixtures (for example, an output-less dynamic
    /// derivation) that are not valid to build or hash.
    ///
    /// Input-addressed derivations with input derivations require
    /// [`Self::validate_with_input_hashes`], because their expected output
    /// paths depend on the modulo hashes of those inputs.
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_structure()?;
        if self.needs_input_hashes_for_output_paths()? {
            return Err(Error::InvalidDerivation(
                "input-addressed output validation requires input derivation modulo hashes"
                    .to_owned(),
            ));
        }

        match self.try_validate_output_paths(
            |_| -> Result<InputDerivationHash, std::convert::Infallible> {
                unreachable!(
                    "a derivation without input-dependent paths cannot request an input hash"
                )
            },
        ) {
            Ok(()) => Ok(()),
            Err(InputResolutionError::Derivation(error)) => Err(error),
            Err(InputResolutionError::Resolve { error, .. }) => match error {},
        }
    }

    /// Validate output identities using infallibly resolved input hashes.
    pub fn validate_with_input_hashes<F, H>(&self, mut resolve: F) -> Result<(), Error>
    where
        F: FnMut(&StorePath) -> H,
        H: Into<InputDerivationHash>,
    {
        match self.try_validate_with_input_hashes(|path| {
            Ok::<_, std::convert::Infallible>(resolve(path).into())
        }) {
            Ok(()) => Ok(()),
            Err(InputResolutionError::Derivation(error)) => Err(error),
            Err(InputResolutionError::Resolve { error, .. }) => match error {},
        }
    }

    /// Fallible form of [`Self::validate_with_input_hashes`].
    pub fn try_validate_with_input_hashes<F, E, H>(
        &self,
        resolve: F,
    ) -> Result<(), InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        self.validate_structure()?;
        self.try_validate_output_paths(resolve)
    }

    fn validate_structure(&self) -> Result<(), Error> {
        self.output_type()?;

        let drv_file_name = format!("{}.drv", self.name);
        if store_path::validate_name(&drv_file_name).is_err() {
            return Err(Error::InvalidDerivation(format!(
                "invalid derivation name {:?}",
                self.name
            )));
        }

        for (output_name, output) in &self.outputs {
            validate_output_name(output_name)?;
            if matches!(output, Output::Fixed { .. }) {
                output.path(&self.name, output_name)?;
            }
        }

        for (path, input) in &self.input_derivations {
            if !path.is_derivation() {
                return Err(Error::InvalidDerivation(format!(
                    "input path {} does not name a .drv file",
                    path.to_absolute_path()
                )));
            }
            validate_input_node(path, input)?;
        }

        if self.system.is_empty() {
            return Err(Error::InvalidDerivation("system is empty".to_owned()));
        }
        if self.builder.is_empty() {
            return Err(Error::InvalidDerivation("builder is empty".to_owned()));
        }
        if self.environment.contains_key("") {
            return Err(Error::InvalidDerivation(
                "environment contains an empty key".to_owned(),
            ));
        }
        if self.environment.contains_key("__json") {
            return Err(Error::InvalidDerivation(
                "environment key \"__json\" is reserved for structured attributes".to_owned(),
            ));
        }
        Ok(())
    }

    fn needs_input_hashes_for_output_paths(&self) -> Result<bool, Error> {
        Ok(match self.output_type()? {
            OutputType::InputAddressed => !self.input_derivations.is_empty(),
            OutputType::Deferred => {
                !self.input_derivations.is_empty()
                    && !self
                        .input_derivations
                        .values()
                        .any(InputDerivation::is_dynamic)
            }
            OutputType::Fixed | OutputType::Floating(_) | OutputType::Impure => false,
        })
    }

    fn try_expected_output_paths<F, E, H>(
        &self,
        mut resolve: F,
    ) -> Result<BTreeMap<String, StorePath>, InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        match self.output_type()? {
            output_type @ (OutputType::InputAddressed | OutputType::Deferred) => {
                let hash = match self.try_hash_output_path_modulo(&mut resolve)? {
                    OutputPathHash::Ready(hash) => hash,
                    OutputPathHash::Deferred => {
                        if matches!(output_type, OutputType::Deferred) {
                            return Ok(BTreeMap::new());
                        }
                        return Err(Error::InvalidDerivation(
                            "input-addressed outputs must be deferred until dynamic or content-addressed inputs are resolved"
                                .to_owned(),
                        )
                        .into());
                    }
                };
                self.outputs
                    .keys()
                    .map(|name| {
                        Ok((
                            name.clone(),
                            store_path::build_output_path(hash, name, &self.name)?,
                        ))
                    })
                    .collect::<Result<_, Error>>()
                    .map_err(Into::into)
            }
            OutputType::Fixed => self
                .outputs
                .iter()
                .map(|(name, output)| {
                    Ok((
                        name.clone(),
                        output
                            .path(&self.name, name)?
                            .expect("fixed outputs always have a path"),
                    ))
                })
                .collect::<Result<_, Error>>()
                .map_err(Into::into),
            OutputType::Floating(_) | OutputType::Impure => Ok(BTreeMap::new()),
        }
    }

    fn try_validate_output_paths<F, E, H>(&self, resolve: F) -> Result<(), InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        if matches!(self.output_type()?, OutputType::Deferred) {
            // Nix currently accepts deferred outputs that could be filled in,
            // for compatibility with derivations emitted by older versions.
            return Ok(());
        }
        for (name, expected) in self.try_expected_output_paths(resolve)? {
            if let Output::InputAddressed { path } = &self.outputs[&name]
                && path != &expected
            {
                return Err(Error::InvalidDerivation(format!(
                    "output {name:?} has path {}, expected {}",
                    path.to_absolute_path(),
                    expected.to_absolute_path()
                ))
                .into());
            }

            let expected = expected.to_absolute_path();
            match self.environment.get(&name) {
                None => {
                    return Err(Error::InvalidDerivation(format!(
                        "output {name:?} is missing its environment entry {expected:?}"
                    ))
                    .into());
                }
                Some(actual) if actual != expected.as_bytes() => {
                    return Err(Error::InvalidDerivation(format!(
                        "output {name:?} has environment value {:?}, expected {expected:?}",
                        String::from_utf8_lossy(actual)
                    ))
                    .into());
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    fn try_fill_output_paths<F, E, H>(&mut self, resolve: F) -> Result<(), InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<InputDerivationHash>,
    {
        self.validate_structure()?;
        if matches!(
            self.output_type()?,
            OutputType::InputAddressed | OutputType::Deferred
        ) {
            // Nix constructs input-addressed derivations with an empty env
            // entry for every output before taking the masked modulo hash.
            // The entry itself is identity-bearing even though its value is
            // masked, so builders must add missing entries before hashing.
            for name in self.outputs.keys() {
                self.environment.entry(name.clone()).or_default();
            }
        }
        for (name, path) in self.try_expected_output_paths(resolve)? {
            match self
                .outputs
                .get_mut(&name)
                .expect("expected paths only contain declared outputs")
            {
                Output::InputAddressed { path: output_path } => *output_path = path.clone(),
                output @ Output::Deferred => {
                    *output = Output::InputAddressed { path: path.clone() };
                }
                Output::Fixed { .. } => {}
                Output::Floating { .. } | Output::Impure { .. } => {
                    unreachable!("these output types have no expected paths")
                }
            }
            self.environment
                .insert(name, path.to_absolute_path().into_bytes());
        }
        Ok(())
    }

    #[must_use]
    /// Return the platform identifier used to execute the builder.
    pub fn system(&self) -> &str {
        &self.system
    }

    #[must_use]
    /// Return the executable or builtin builder identifier.
    pub fn builder(&self) -> &str {
        &self.builder
    }

    #[must_use]
    /// Return the ordered builder arguments.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    /// Return ordinary environment entries, whose values may be arbitrary bytes.
    pub fn environment(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.environment
    }

    #[must_use]
    /// Return parsed structured attributes when the derivation uses `__structuredAttrs`.
    pub fn structured_attrs(&self) -> Option<&StructuredAttrs> {
        self.structured_attrs.as_ref()
    }

    /// Materialize `.attrs.json` and `.attrs.sh` when this derivation uses
    /// structured attributes.
    pub fn structured_attrs_files(&self) -> Result<Option<StructuredAttrsFiles>, Error> {
        let Some(attrs) = self.structured_attrs.as_ref() else {
            return Ok(None);
        };
        let output_paths = self
            .outputs
            .iter()
            .map(|(name, output)| {
                let path = output.path(&self.name, name)?.ok_or_else(|| {
                    Error::StructuredAttrs(format!(
                        "output {name:?} has no known path; provide its scratch path explicitly"
                    ))
                })?;
                Ok((name.clone(), path))
            })
            .collect::<Result<BTreeMap<_, _>, Error>>()?;
        Ok(Some(structured_attrs::files(attrs, &output_paths)?))
    }

    /// Materialize structured-attribute files using the builder's output paths.
    ///
    /// Nix substitutes output placeholders with scratch paths immediately
    /// before exposing `.attrs.json` and `.attrs.sh` to a builder. Callers that
    /// use redirected, floating, deferred, or impure outputs must supply those
    /// concrete paths here.
    pub fn structured_attrs_files_with_output_paths(
        &self,
        output_paths: &BTreeMap<String, StorePath>,
    ) -> Result<Option<StructuredAttrsFiles>, Error> {
        let Some(attrs) = self.structured_attrs.as_ref() else {
            return Ok(None);
        };
        if !self.outputs.keys().eq(output_paths.keys()) {
            return Err(Error::StructuredAttrs(
                "concrete output paths do not match the derivation outputs".to_owned(),
            ));
        }
        Ok(Some(structured_attrs::files(attrs, output_paths)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputType {
    InputAddressed,
    Fixed,
    Floating(HashAlgorithm),
    Deferred,
    Impure,
}

impl Derivation {
    fn output_type(&self) -> Result<OutputType, Error> {
        let mut found = None;
        for (name, output) in &self.outputs {
            let next = match output {
                Output::InputAddressed { .. } => OutputType::InputAddressed,
                Output::Fixed { .. } => {
                    if name != "out" || self.outputs.len() != 1 {
                        return Err(Error::InvalidFixedOutputs {
                            name: self.name.clone(),
                            outputs: self.outputs.len(),
                        });
                    }
                    OutputType::Fixed
                }
                Output::Floating { hash_algorithm, .. } => OutputType::Floating(*hash_algorithm),
                Output::Deferred => OutputType::Deferred,
                Output::Impure { .. } => OutputType::Impure,
            };
            if let Some(previous) = found
                && previous != next
            {
                let message = if matches!(
                    (previous, next),
                    (OutputType::Floating(_), OutputType::Floating(_))
                ) {
                    "all floating outputs must use the same hash algorithm"
                } else {
                    "cannot mix derivation output types"
                };
                return Err(Error::InvalidDerivation(message.to_owned()));
            }
            found = Some(next);
        }
        found.ok_or_else(|| Error::InvalidDerivation("must have at least one output".to_owned()))
    }
}

fn validate_output_name(name: &str) -> Result<(), Error> {
    if name == "drv" || store_path::validate_name(name).is_err() {
        return Err(Error::InvalidDerivation(format!(
            "invalid output name {name:?}"
        )));
    }
    Ok(())
}

fn validate_input_node(path: &StorePath, input: &InputDerivation) -> Result<(), Error> {
    for node in input.walk() {
        if node.depth() > MAX_DYNAMIC_INPUT_DEPTH {
            return Err(Error::InvalidDerivation(format!(
                "input derivation {} exceeds {MAX_DYNAMIC_INPUT_DEPTH} dynamic levels",
                path.to_absolute_path()
            )));
        }
        let input = node.input();
        if input.outputs.is_empty() && input.dynamic_outputs.is_empty() {
            return Err(Error::InvalidDerivation(format!(
                "input derivation {} requests no outputs",
                path.to_absolute_path()
            )));
        }
        for name in &input.outputs {
            validate_output_name(name).map_err(|_| {
                Error::InvalidDerivation(format!(
                    "input derivation {} has invalid requested output {name:?}",
                    path.to_absolute_path()
                ))
            })?;
        }
        for name in input.dynamic_outputs.keys() {
            validate_output_name(name).map_err(|_| {
                Error::InvalidDerivation(format!(
                    "input derivation {} has invalid dynamic output {name:?}",
                    path.to_absolute_path()
                ))
            })?;
        }
    }
    Ok(())
}

fn fixed_output_hash(ca: &CAHash, path: &StorePath) -> DerivationModuloHash {
    let (method_prefix, hash): (&str, NixHash) = match ca {
        CAHash::Flat(hash) => ("", hash.clone()),
        CAHash::Nar(hash) => ("r:", hash.clone()),
        CAHash::Text(digest) => ("text:", NixHash::Sha256(*digest)),
        CAHash::Git(hash) => ("git:", hash.clone()),
    };
    let mut digest = Sha256::new();
    digest.update(b"fixed:out:");
    digest.update(method_prefix.as_bytes());
    digest.update(hash.algorithm().as_str().as_bytes());
    digest.update(b":");
    update_hex(&mut digest, hash.digest_as_bytes());
    digest.update(b":");
    digest.update(path.to_absolute_path().as_bytes());
    DerivationModuloHash::new(digest.finalize().into())
}

fn update_hex(digest: &mut Sha256, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        digest.update([HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]]);
    }
}

struct HashWriter(Sha256);

impl io::Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
