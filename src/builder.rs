use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use crate::{
    CAHash, ContentAddressMethod, Derivation, DerivationOutput, Error, InputDerivation, Output,
    StoreDir, StorePath, StructuredAttrs, store_path,
};

/// One realised output in a dynamic derivation input chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicOutputReplacement {
    /// Input derivation where the dynamic output chain begins.
    pub base_derivation: StorePath,
    /// Output names followed from the base derivation to the realised output.
    pub output_chain: Vec<String>,
    /// Concrete store path produced by the final output in the chain.
    pub realised_path: StorePath,
}

/// Store-independent facts needed to resolve all dynamic derivation inputs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DynamicInputResolution {
    /// Placeholder-to-path replacements for realised outputs in dynamic chains.
    pub replacements: Vec<DynamicOutputReplacement>,
    /// Realised leaf outputs that become direct source inputs.
    pub input_sources: BTreeSet<StorePath>,
}

/// One ordinary `exportReferencesGraph` declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportReferencesGraph {
    /// File to create in the build directory.
    pub file_name: String,
    /// Root store path whose reference graph is exported.
    pub root: StorePath,
}

/// Construct or edit a derivation, validating all invariants at the end.
#[derive(Debug, Clone)]
#[must_use = "a derivation builder has no effect until it is built"]
pub struct DerivationBuilder {
    store_dir: StoreDir,
    name: String,
    outputs: BTreeMap<String, Output>,
    input_derivations: BTreeMap<StorePath, InputDerivation>,
    input_sources: BTreeSet<StorePath>,
    system: String,
    builder: String,
    arguments: Vec<String>,
    environment: BTreeMap<String, Vec<u8>>,
    structured_attrs: Option<StructuredAttrs>,
    aterm_size_hint: usize,
}

impl DerivationBuilder {
    /// Start a derivation with the three required scalar fields.
    pub fn new(
        name: impl Into<String>,
        system: impl Into<String>,
        builder: impl Into<String>,
    ) -> Self {
        Self::new_in_store(StoreDir::default(), name, system, builder)
    }

    /// Start a derivation in a configured logical store directory.
    pub fn new_in_store(
        store_dir: StoreDir,
        name: impl Into<String>,
        system: impl Into<String>,
        builder: impl Into<String>,
    ) -> Self {
        Self {
            store_dir,
            name: name.into(),
            outputs: BTreeMap::new(),
            input_derivations: BTreeMap::new(),
            input_sources: BTreeSet::new(),
            system: system.into(),
            builder: builder.into(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            structured_attrs: None,
            aterm_size_hint: 256,
        }
    }

    /// Consume a parsed derivation for zero-copy editing.
    pub fn from_derivation(derivation: Derivation) -> Self {
        Self {
            store_dir: derivation.store_dir,
            name: derivation.name,
            outputs: derivation.outputs,
            input_derivations: derivation.input_derivations,
            input_sources: derivation.input_sources,
            system: derivation.system,
            builder: derivation.builder,
            arguments: derivation.arguments,
            environment: derivation.environment,
            structured_attrs: derivation.structured_attrs,
            aterm_size_hint: derivation.aterm_size_hint,
        }
    }

    /// Declare or replace an output.
    pub fn output(mut self, name: impl Into<String>, output: Output) -> Self {
        self.outputs.insert(name.into(), output);
        self
    }

    /// Declare an input-addressed output whose store path will be calculated by [`Self::build`].
    ///
    /// When dynamic or content-addressed inputs prevent immediate resolution,
    /// the resulting validated derivation retains a deferred output instead.
    pub fn input_addressed_output(self, name: impl Into<String>) -> Self {
        self.output(name, Output::Deferred)
    }

    /// Declare or replace an input derivation and its requested outputs.
    pub fn input_derivation(mut self, path: StorePath, input: InputDerivation) -> Self {
        self.input_derivations.insert(path, input);
        self
    }

    /// Add a directly referenced input source.
    pub fn input_source(mut self, path: StorePath) -> Self {
        self.input_sources.insert(path);
        self
    }

    /// Append one builder argument.
    pub fn argument(mut self, argument: impl Into<String>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Declare or replace an ordinary environment entry.
    pub fn environment(mut self, key: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Enable structured attributes with a validated JSON object.
    pub fn structured_attrs(mut self, attrs: StructuredAttrs) -> Self {
        self.structured_attrs = Some(attrs);
        self
    }

    /// Return the derivation name without its `.drv` suffix.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the logical store directory used for path identities.
    #[must_use]
    pub fn store_dir(&self) -> &StoreDir {
        &self.store_dir
    }

    /// Return the output declarations accumulated so far.
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<String, Output> {
        &self.outputs
    }

    /// Return the input derivations accumulated so far.
    #[must_use]
    pub fn input_derivations(&self) -> &BTreeMap<StorePath, InputDerivation> {
        &self.input_derivations
    }

    /// Return the direct input sources accumulated so far.
    #[must_use]
    pub fn input_sources(&self) -> &BTreeSet<StorePath> {
        &self.input_sources
    }

    /// Return the platform identifier used to execute the builder.
    #[must_use]
    pub fn system(&self) -> &str {
        &self.system
    }

    /// Return the executable or builtin builder identifier.
    #[must_use]
    pub fn builder(&self) -> &str {
        &self.builder
    }

    /// Return the ordered builder arguments accumulated so far.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Return ordinary environment entries accumulated so far.
    #[must_use]
    pub fn environment_entries(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.environment
    }

    /// Return the structured attributes accumulated so far.
    #[must_use]
    pub fn structured_attrs_ref(&self) -> Option<&StructuredAttrs> {
        self.structured_attrs.as_ref()
    }

    /// Mutably access the derivation name.
    pub fn name_mut(&mut self) -> &mut String {
        &mut self.name
    }

    /// Mutably access all output declarations.
    pub fn outputs_mut(&mut self) -> &mut BTreeMap<String, Output> {
        &mut self.outputs
    }

    /// Mutably access all input derivations.
    pub fn input_derivations_mut(&mut self) -> &mut BTreeMap<StorePath, InputDerivation> {
        &mut self.input_derivations
    }

    /// Mutably access all direct input sources.
    pub fn input_sources_mut(&mut self) -> &mut BTreeSet<StorePath> {
        &mut self.input_sources
    }

    /// Mutably access the platform identifier.
    pub fn system_mut(&mut self) -> &mut String {
        &mut self.system
    }

    /// Mutably access the executable or builtin builder identifier.
    pub fn builder_mut(&mut self) -> &mut String {
        &mut self.builder
    }

    /// Mutably access the ordered builder arguments.
    pub fn arguments_mut(&mut self) -> &mut Vec<String> {
        &mut self.arguments
    }

    /// Mutably access all ordinary environment entries.
    pub fn environment_mut(&mut self) -> &mut BTreeMap<String, Vec<u8>> {
        &mut self.environment
    }

    /// Mutably access the optional structured attributes.
    pub fn structured_attrs_mut(&mut self) -> &mut Option<StructuredAttrs> {
        &mut self.structured_attrs
    }

    /// Validate and finish construction.
    pub fn build(self) -> Result<ValidatedDerivation, Error> {
        let mut derivation = self.into_derivation();
        if derivation.needs_input_hashes_for_output_paths()? {
            return Err(Error::InvalidDerivation(
                "resolving derivation output paths with inputs requires input derivation modulo hashes"
                    .to_owned(),
            ));
        }
        match derivation.try_fill_output_paths(
            |_| -> Result<crate::InputDerivationHash, std::convert::Infallible> {
                unreachable!(
                    "a derivation without input-dependent paths cannot request an input hash"
                )
            },
        ) {
            Ok(()) => Ok(ValidatedDerivation(derivation)),
            Err(crate::InputResolutionError::Derivation(error)) => Err(error),
            Err(crate::InputResolutionError::Resolve { error, .. }) => match error {},
        }
    }

    /// Validate and finish construction using input derivation modulo hashes.
    pub fn build_with_input_hashes<F, H>(self, mut resolve: F) -> Result<ValidatedDerivation, Error>
    where
        F: FnMut(&StorePath) -> H,
        H: Into<crate::InputDerivationHash>,
    {
        match self.try_build_with_input_hashes(|path| {
            Ok::<_, std::convert::Infallible>(resolve(path).into())
        }) {
            Ok(derivation) => Ok(derivation),
            Err(crate::InputResolutionError::Derivation(error)) => Err(error),
            Err(crate::InputResolutionError::Resolve { error, .. }) => match error {},
        }
    }

    /// Fallible form of [`Self::build_with_input_hashes`].
    pub fn try_build_with_input_hashes<F, E, H>(
        self,
        resolve: F,
    ) -> Result<ValidatedDerivation, crate::InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<crate::InputDerivationHash>,
    {
        let mut derivation = self.into_derivation();
        derivation.try_fill_output_paths(resolve)?;
        Ok(ValidatedDerivation(derivation))
    }

    fn into_derivation(self) -> Derivation {
        Derivation {
            store_dir: self.store_dir,
            name: self.name,
            outputs: self.outputs,
            input_derivations: self.input_derivations,
            input_sources: self.input_sources,
            system: self.system,
            builder: self.builder,
            arguments: self.arguments,
            environment: self.environment,
            structured_attrs: self.structured_attrs,
            aterm_size_hint: self.aterm_size_hint,
        }
    }
}

impl From<Derivation> for DerivationBuilder {
    fn from(derivation: Derivation) -> Self {
        Self::from_derivation(derivation)
    }
}

/// An owned derivation whose semantic invariants have been checked.
///
/// The wrapper dereferences to [`Derivation`] for read-only access. Converting
/// it back into a builder is the only mutation path, and rebuilding validates
/// the result again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDerivation(Derivation);

impl ValidatedDerivation {
    /// Parse and validate a canonical or non-canonical derivation `ATerm`.
    pub fn from_aterm_bytes(bytes: &[u8], name: &str) -> Result<Self, Error> {
        Derivation::from_aterm_bytes(bytes, name)?.into_validated()
    }

    /// Parse and validate using a configured logical store directory.
    pub fn from_aterm_bytes_in(
        bytes: &[u8],
        name: &str,
        store_dir: StoreDir,
    ) -> Result<Self, Error> {
        Derivation::from_aterm_bytes_in(bytes, name, store_dir)?.into_validated()
    }

    /// Parse and validate using input derivation modulo hashes.
    pub fn from_aterm_bytes_with_input_hashes<F, H>(
        bytes: &[u8],
        name: &str,
        resolve: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(&StorePath) -> H,
        H: Into<crate::InputDerivationHash>,
    {
        Derivation::from_aterm_bytes(bytes, name)?.into_validated_with_input_hashes(resolve)
    }

    /// Parse and validate in a configured logical store using input hashes.
    pub fn from_aterm_bytes_with_input_hashes_in<F, H>(
        bytes: &[u8],
        name: &str,
        store_dir: StoreDir,
        resolve: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(&StorePath) -> H,
        H: Into<crate::InputDerivationHash>,
    {
        Derivation::from_aterm_bytes_in(bytes, name, store_dir)?
            .into_validated_with_input_hashes(resolve)
    }

    /// Fallible form of [`Self::from_aterm_bytes_with_input_hashes`].
    pub fn try_from_aterm_bytes_with_input_hashes<F, E, H>(
        bytes: &[u8],
        name: &str,
        resolve: F,
    ) -> Result<Self, crate::InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<crate::InputDerivationHash>,
    {
        let derivation = Derivation::from_aterm_bytes(bytes, name)?;
        Self::try_from_with_input_hashes(derivation, resolve)
    }

    /// Fallible input-resolution form using a configured logical store.
    pub fn try_from_aterm_bytes_with_input_hashes_in<F, E, H>(
        bytes: &[u8],
        name: &str,
        store_dir: StoreDir,
        resolve: F,
    ) -> Result<Self, crate::InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<crate::InputDerivationHash>,
    {
        let derivation = Derivation::from_aterm_bytes_in(bytes, name, store_dir)?;
        Self::try_from_with_input_hashes(derivation, resolve)
    }

    pub(crate) fn try_from_with_input_hashes<F, E, H>(
        derivation: Derivation,
        resolve: F,
    ) -> Result<Self, crate::InputResolutionError<E>>
    where
        F: FnMut(&StorePath) -> Result<H, E>,
        H: Into<crate::InputDerivationHash>,
    {
        derivation.try_validate_with_input_hashes(resolve)?;
        Ok(Self(derivation))
    }

    /// Borrow the underlying syntactically representable derivation.
    #[must_use]
    pub const fn as_derivation(&self) -> &Derivation {
        &self.0
    }

    /// Unwrap this value without changing its fields.
    #[must_use]
    pub fn into_derivation(self) -> Derivation {
        self.0
    }

    /// Consume this value for editing and subsequent revalidation.
    pub fn into_builder(self) -> DerivationBuilder {
        self.0.into_builder()
    }

    /// Resolve output paths without a remaining semantic error case.
    #[must_use]
    pub fn resolved_outputs(&self) -> BTreeMap<String, DerivationOutput> {
        self.0
            .resolved_outputs()
            .expect("validated derivation has resolvable output declarations")
    }

    /// Determine whether this is a fixed-output derivation.
    #[must_use]
    pub fn is_fixed_output(&self) -> bool {
        self.0
            .is_fixed_output()
            .expect("validated derivation has one consistent output type")
    }

    /// Whether this derivation participates in dynamic derivation resolution.
    #[must_use]
    pub fn uses_dynamic_derivations(&self) -> bool {
        self.0
            .input_derivations
            .values()
            .any(InputDerivation::is_dynamic)
            || self.0.outputs.iter().any(|(name, output)| match output {
                Output::Floating {
                    method: ContentAddressMethod::Text,
                    ..
                } => true,
                Output::Fixed {
                    ca: CAHash::Text(_),
                } => output
                    .path_in(&self.0.store_dir, &self.0.name, name)
                    .expect("validated fixed output has a valid path")
                    .is_some_and(|path| path.is_derivation()),
                _ => false,
            })
    }

    /// Return all explicitly requested Nix system features in sorted order.
    #[must_use]
    pub fn required_system_features(&self) -> BTreeSet<String> {
        let mut features = BTreeSet::new();
        if let Some(value) = self.0.environment.get("requiredSystemFeatures") {
            features.extend(
                String::from_utf8_lossy(value)
                    .split([' ', '\t', '\n', '\r'])
                    .filter(|feature| !feature.is_empty())
                    .map(str::to_owned),
            );
        }
        if let Some(values) = self
            .0
            .structured_attrs
            .as_ref()
            .and_then(|attrs| attrs.get("requiredSystemFeatures"))
            .and_then(serde_json::Value::as_array)
        {
            features.extend(
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned),
            );
        }
        features
    }

    /// Resolve dynamic input placeholders using already-realised store paths.
    ///
    /// This performs only the pure rewrite step. Building input derivations,
    /// loading generated `.drv` files, and deciding which paths are realised
    /// leaves remain the caller's responsibility.
    pub fn resolve_dynamic_inputs(
        self,
        resolution: DynamicInputResolution,
    ) -> Result<ValidatedDerivation, Error> {
        let store_dir = self.0.store_dir.clone();
        let mut rewrites = BTreeMap::new();
        for replacement in resolution.replacements {
            let placeholder = store_path::downstream_placeholder(
                &replacement.base_derivation,
                &replacement.output_chain,
            )?;
            let realised_path = replacement.realised_path.to_absolute_path_in(&store_dir);
            if let Some(previous) = rewrites.insert(placeholder.clone(), realised_path.clone())
                && previous != realised_path
            {
                return Err(Error::InvalidDerivation(format!(
                    "conflicting dynamic input resolutions for placeholder {placeholder}"
                )));
            }
        }

        let mut builder = self.into_builder();
        builder.input_derivations_mut().clear();
        builder.input_sources_mut().extend(resolution.input_sources);
        for argument in builder.arguments_mut() {
            *argument = replace_string(argument, &rewrites);
        }
        for value in builder.environment_mut().values_mut() {
            *value = replace_bytes(value, &rewrites);
        }
        if let Some(attrs) = builder.structured_attrs_mut().take() {
            let json = replace_bytes(attrs.canonical_json(), &rewrites);
            *builder.structured_attrs_mut() = Some(StructuredAttrs::from_json_bytes(json)?);
        }
        builder.build()
    }

    /// Parse the ordinary `exportReferencesGraph` environment option.
    pub fn export_references_graph(&self) -> Result<Vec<ExportReferencesGraph>, Error> {
        let Some(value) = self.0.environment.get("exportReferencesGraph") else {
            return Ok(Vec::new());
        };
        let value = std::str::from_utf8(value).map_err(|_| Error::InvalidUtf8 {
            field: "exportReferencesGraph",
        })?;
        let tokens: Vec<_> = value
            .split([' ', '\t', '\n', '\r'])
            .filter(|token| !token.is_empty())
            .collect();
        if !tokens.len().is_multiple_of(2) {
            return Err(Error::InvalidDerivation(format!(
                "odd number of tokens in exportReferencesGraph: {value:?}"
            )));
        }

        tokens
            .chunks_exact(2)
            .map(|pair| {
                let file_name = pair[0];
                if !valid_export_references_graph_file_name(file_name) {
                    return Err(Error::InvalidDerivation(format!(
                        "invalid file name {file_name:?} in exportReferencesGraph"
                    )));
                }
                Ok(ExportReferencesGraph {
                    file_name: file_name.to_owned(),
                    root: self.0.store_dir.parse_path(pair[1].as_bytes())?,
                })
            })
            .collect()
    }

    /// Calculate this derivation's own `.drv` store path.
    #[must_use]
    pub fn drv_path(&self) -> StorePath {
        self.0
            .drv_path()
            .expect("validated derivation has a valid .drv store-path name")
    }
}

fn replace_string(value: &str, rewrites: &BTreeMap<String, String>) -> String {
    rewrites.iter().fold(value.to_owned(), |value, (from, to)| {
        value.replace(from, to)
    })
}

fn replace_bytes(value: &[u8], rewrites: &BTreeMap<String, String>) -> Vec<u8> {
    rewrites.iter().fold(value.to_vec(), |value, (from, to)| {
        replace_one_bytes(&value, from.as_bytes(), to.as_bytes())
    })
}

fn replace_one_bytes(value: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    debug_assert!(!from.is_empty());
    let mut replaced = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some(position) = rest.windows(from.len()).position(|window| window == from) {
        replaced.extend_from_slice(&rest[..position]);
        replaced.extend_from_slice(to);
        rest = &rest[position + from.len()..];
    }
    replaced.extend_from_slice(rest);
    replaced
}

fn valid_export_references_graph_file_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

impl TryFrom<Derivation> for ValidatedDerivation {
    type Error = Error;

    fn try_from(derivation: Derivation) -> Result<Self, Self::Error> {
        derivation.validate()?;
        Ok(Self(derivation))
    }
}

impl From<ValidatedDerivation> for Derivation {
    fn from(derivation: ValidatedDerivation) -> Self {
        derivation.0
    }
}

impl AsRef<Derivation> for ValidatedDerivation {
    fn as_ref(&self) -> &Derivation {
        &self.0
    }
}

impl Deref for ValidatedDerivation {
    type Target = Derivation;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
