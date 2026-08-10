//! Pure Rust Nix derivations.
//!
//! The ATerm representation is identity-bearing: its bytes determine the
//! derivation's store path and participate in output-path hashing. Parsing is
//! therefore byte-oriented and serialization follows Nix's canonical field
//! order, escaping, and map ordering exactly.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
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
pub use hash::{CAHash, NixHash};
pub use store_path::StorePath;
pub use structured_attrs::{StructuredAttrs, StructuredAttrsFiles};

#[cfg(test)]
mod tests;

/// A derivation parse or semantic error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("ATerm parse error at byte {offset}: {message}")]
    Parse { offset: usize, message: String },
    #[error("{field} is not valid UTF-8")]
    InvalidUtf8 { field: &'static str },
    #[error("invalid store path in derivation: {0}")]
    InvalidStorePath(#[from] store_path::Error),
    #[error("invalid content hash in derivation: {0}")]
    InvalidHash(#[from] hash::Error),
    #[error("invalid structured attributes: {0}")]
    StructuredAttrs(String),
    #[error(
        "fixed output derivation {name:?} has {outputs} outputs, expected exactly one named \"out\""
    )]
    InvalidFixedOutputs { name: String, outputs: usize },
    #[error("invalid derivation: {0}")]
    InvalidDerivation(String),
}

/// Failure while hashing a derivation with a fallible input resolver.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HashDerivationError<E> {
    #[error(transparent)]
    Derivation(#[from] Error),
    #[error("failed to resolve input derivation {path}: {error}")]
    Resolve { path: StorePath, error: E },
}

/// Hash algorithms understood by Nix derivation output declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    fn parse(value: &[u8]) -> Result<Self, Error> {
        match value {
            b"md5" => Ok(Self::Md5),
            b"sha1" => Ok(Self::Sha1),
            b"sha256" => Ok(Self::Sha256),
            b"sha512" => Ok(Self::Sha512),
            _ => Err(Error::Parse {
                offset: 0,
                message: format!(
                    "unknown hash algorithm {:?}",
                    String::from_utf8_lossy(value)
                ),
            }),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

/// How an output is ingested before hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContentAddressMethod {
    Flat,
    Nar,
    Text,
    Git,
}

impl ContentAddressMethod {
    fn parse_prefix(value: &[u8]) -> (Self, &[u8]) {
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

    const fn prefix(self) -> &'static str {
        match self {
            Self::Flat => "",
            Self::Nar => "r:",
            Self::Text => "text:",
            Self::Git => "git:",
        }
    }
}

/// The five output variants represented by Nix 2.34 derivation ATerms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    InputAddressed {
        path: StorePath,
    },
    Fixed {
        ca: CAHash,
    },
    Floating {
        method: ContentAddressMethod,
        hash_algorithm: HashAlgorithm,
    },
    Deferred,
    Impure {
        method: ContentAddressMethod,
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
                    std::iter::empty(),
                    false,
                )?))
            }
            Self::Floating { .. } | Self::Deferred | Self::Impure { .. } => Ok(None),
        }
    }

    #[must_use]
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
    pub path: Option<StorePath>,
    pub ca_hash: Option<CAHash>,
}

/// One node in Nix's input-derivation trie.
///
/// `outputs` are requested directly from this derivation. Each
/// `dynamic_outputs` entry follows an output which itself evaluates to a
/// derivation, as represented by the `xp-dyn-drv` ATerm format.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InputDerivation {
    outputs: BTreeSet<String>,
    dynamic_outputs: BTreeMap<String, InputDerivation>,
}

/// Maximum recursive dynamic-input depth accepted from ATerms or builders.
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

    pub fn with_dynamic_output(
        mut self,
        name: impl Into<String>,
        input: InputDerivation,
    ) -> Result<Self, Error> {
        self.insert_dynamic_output(name, input)?;
        Ok(self)
    }

    pub fn insert_output(&mut self, output: impl Into<String>) -> bool {
        self.outputs.insert(output.into())
    }

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
    #[must_use]
    pub const fn depth(self) -> usize {
        self.depth
    }

    /// Dynamic output followed from the parent, or `None` for the root node.
    #[must_use]
    pub const fn dynamic_output(self) -> Option<&'a str> {
        self.dynamic_output
    }

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
    #[must_use]
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
    pub fn into_validated_with_input_hashes<F>(
        self,
        mut resolve: F,
    ) -> Result<ValidatedDerivation, Error>
    where
        F: FnMut(&StorePath) -> [u8; 32],
    {
        match self.try_into_validated_with_input_hashes(|path| {
            Ok::<_, std::convert::Infallible>(resolve(path))
        }) {
            Ok(derivation) => Ok(derivation),
            Err(HashDerivationError::Derivation(error)) => Err(error),
            Err(HashDerivationError::Resolve { error, .. }) => match error {},
        }
    }

    /// Fallible form of [`Self::into_validated_with_input_hashes`].
    pub fn try_into_validated_with_input_hashes<F, E>(
        self,
        resolve: F,
    ) -> Result<ValidatedDerivation, HashDerivationError<E>>
    where
        F: FnMut(&StorePath) -> Result<[u8; 32], E>,
    {
        ValidatedDerivation::try_from_with_input_hashes(self, resolve)
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Outputs in their lossless ATerm representation.
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<String, Output> {
        &self.outputs
    }

    /// Write Nix's canonical unmasked ATerm representation.
    pub fn write_aterm(&self, writer: &mut impl io::Write) -> io::Result<()> {
        write::serialize(self, writer, false, None)
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

    /// Compute Nix's derivation hash modulo its input derivations.
    ///
    /// Input hashes are always the unmasked hashes of those inputs. For the
    /// current derivation, `mask_outputs` additionally clears output paths and
    /// environment entries whose keys name outputs.
    pub fn hash_derivation_modulo<F>(
        &self,
        mask_outputs: bool,
        mut resolve: F,
    ) -> Result<[u8; 32], Error>
    where
        F: FnMut(&StorePath) -> [u8; 32],
    {
        match self.try_hash_derivation_modulo(mask_outputs, |path| {
            Ok::<_, std::convert::Infallible>(resolve(path))
        }) {
            Ok(hash) => Ok(hash),
            Err(HashDerivationError::Derivation(error)) => Err(error),
            Err(HashDerivationError::Resolve { error, .. }) => match error {},
        }
    }

    /// Compute Nix's derivation hash while allowing input lookup to fail.
    ///
    /// This is the natural entry point for stores and graph evaluators: a
    /// missing input is returned with its [`StorePath`] instead of forcing the
    /// resolver to panic or maintain a separate preflight pass.
    pub fn try_hash_derivation_modulo<F, E>(
        &self,
        mask_outputs: bool,
        mut resolve: F,
    ) -> Result<[u8; 32], HashDerivationError<E>>
    where
        F: FnMut(&StorePath) -> Result<[u8; 32], E>,
    {
        if self.is_fixed_output()? {
            let Some((output_name, Output::Fixed { ca })) = self.outputs.first_key_value() else {
                unreachable!("is_fixed_output checked the output variant")
            };
            if self.outputs.len() != 1 || output_name != "out" {
                return Err(Error::InvalidFixedOutputs {
                    name: self.name.clone(),
                    outputs: self.outputs.len(),
                }
                .into());
            }
            let path = self
                .outputs
                .get(output_name)
                .expect("output still present")
                .path(&self.name, output_name)?
                .expect("fixed output has a path");
            return Ok(fixed_output_hash(ca, &path));
        }

        // Equal input modulo hashes share one actualInputs entry. Nix unions
        // their requested output names rather than allowing the later map
        // entry to overwrite the earlier one.
        let mut actual_inputs: BTreeMap<[u8; 32], BTreeSet<String>> = BTreeMap::new();
        for (path, input) in &self.input_derivations {
            let input_hash = resolve(path).map_err(|error| HashDerivationError::Resolve {
                path: path.clone(),
                error,
            })?;
            // Nix inserts an actualInputs entry only while visiting direct
            // output requests. A dynamic-only root is resolved above, but it
            // contributes no empty `(hash, [])` entry to this modulo hash.
            if !input.outputs.is_empty() {
                actual_inputs
                    .entry(input_hash)
                    .or_default()
                    // Dynamic child nodes are resolved separately and do not
                    // enter this top-level hash.
                    .extend(input.outputs.iter().cloned());
            }
        }

        let mut writer = HashWriter(Sha256::new());
        write::serialize(self, &mut writer, mask_outputs, Some(&actual_inputs))
            .expect("hash writer cannot fail");
        Ok(writer.0.finalize().into())
    }

    pub fn drv_path(&self) -> Result<StorePath, Error> {
        let bytes = self.to_aterm_bytes();
        let references: Vec<String> = self
            .input_derivations
            .keys()
            .chain(self.input_sources.iter())
            .map(StorePath::to_absolute_path)
            .collect();
        Ok(store_path::build_text_path(
            &format!("{}.drv", self.name),
            &bytes,
            references.iter().map(String::as_str),
        )?)
    }

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

        match self.try_validate_output_paths(|_| -> Result<_, std::convert::Infallible> {
            unreachable!("a derivation without input-dependent paths cannot request an input hash")
        }) {
            Ok(()) => Ok(()),
            Err(HashDerivationError::Derivation(error)) => Err(error),
            Err(HashDerivationError::Resolve { error, .. }) => match error {},
        }
    }

    /// Validate output identities using infallibly resolved input hashes.
    pub fn validate_with_input_hashes<F>(&self, mut resolve: F) -> Result<(), Error>
    where
        F: FnMut(&StorePath) -> [u8; 32],
    {
        match self
            .try_validate_with_input_hashes(|path| Ok::<_, std::convert::Infallible>(resolve(path)))
        {
            Ok(()) => Ok(()),
            Err(HashDerivationError::Derivation(error)) => Err(error),
            Err(HashDerivationError::Resolve { error, .. }) => match error {},
        }
    }

    /// Fallible form of [`Self::validate_with_input_hashes`].
    pub fn try_validate_with_input_hashes<F, E>(
        &self,
        resolve: F,
    ) -> Result<(), HashDerivationError<E>>
    where
        F: FnMut(&StorePath) -> Result<[u8; 32], E>,
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
        Ok(matches!(self.output_type()?, OutputType::InputAddressed)
            && !self.input_derivations.is_empty())
    }

    fn try_expected_output_paths<F, E>(
        &self,
        mut resolve: F,
    ) -> Result<BTreeMap<String, StorePath>, HashDerivationError<E>>
    where
        F: FnMut(&StorePath) -> Result<[u8; 32], E>,
    {
        match self.output_type()? {
            OutputType::InputAddressed => {
                let hash = self.try_hash_derivation_modulo(true, &mut resolve)?;
                self.outputs
                    .keys()
                    .map(|name| {
                        Ok((
                            name.clone(),
                            store_path::build_output_path(&hash, name, &self.name)?,
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
            OutputType::Floating(_) | OutputType::Deferred | OutputType::Impure => {
                Ok(BTreeMap::new())
            }
        }
    }

    fn try_validate_output_paths<F, E>(&self, resolve: F) -> Result<(), HashDerivationError<E>>
    where
        F: FnMut(&StorePath) -> Result<[u8; 32], E>,
    {
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

    fn try_fill_output_paths<F, E>(&mut self, resolve: F) -> Result<(), HashDerivationError<E>>
    where
        F: FnMut(&StorePath) -> Result<[u8; 32], E>,
    {
        self.validate_structure()?;
        if matches!(self.output_type()?, OutputType::InputAddressed) {
            // Nix constructs input-addressed derivations with an empty env
            // entry for every output before taking the masked modulo hash.
            // The entry itself is identity-bearing even though its value is
            // masked, so builders must add missing entries before hashing.
            for name in self.outputs.keys() {
                self.environment.entry(name.clone()).or_default();
            }
        }
        for (name, path) in self.try_expected_output_paths(resolve)? {
            if let Output::InputAddressed { path: output_path } = self
                .outputs
                .get_mut(&name)
                .expect("expected paths only contain declared outputs")
            {
                *output_path = path.clone();
            }
            self.environment
                .insert(name, path.to_absolute_path().into_bytes());
        }
        Ok(())
    }

    #[must_use]
    pub fn system(&self) -> &str {
        &self.system
    }

    #[must_use]
    pub fn builder(&self) -> &str {
        &self.builder
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.environment
    }

    #[must_use]
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

fn fixed_output_hash(ca: &CAHash, path: &StorePath) -> [u8; 32] {
    let (method_prefix, hash): (&str, NixHash) = match ca {
        CAHash::Flat(hash) => ("", hash.clone()),
        CAHash::Nar(hash) => ("r:", hash.clone()),
        CAHash::Text(digest) => ("text:", NixHash::Sha256(*digest)),
        CAHash::Git(hash) => ("git:", hash.clone()),
    };
    let mut digest = Sha256::new();
    digest.update(b"fixed:out:");
    digest.update(method_prefix.as_bytes());
    digest.update(hash.algo().as_bytes());
    digest.update(b":");
    update_hex(&mut digest, hash.digest_as_bytes());
    digest.update(b":");
    digest.update(path.to_absolute_path().as_bytes());
    digest.finalize().into()
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
