//! Nix derived-path expressions.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use crate::store_path::{self, StoreDir, StorePath};
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};
use thiserror::Error;

/// The key identifying one named output of a derivation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DrvOutput {
    drv_path: StorePath,
    output_name: String,
}

impl DrvOutput {
    /// Construct a derivation-output identifier.
    #[must_use]
    pub fn new(drv_path: StorePath, output_name: impl Into<String>) -> Self {
        Self {
            drv_path,
            output_name: output_name.into(),
        }
    }

    /// Parse Nix's basename form, `<store-path-basename>^<output-name>`.
    pub fn parse(input: &str) -> Result<Self, DrvOutputParseError> {
        let (drv_path, output_name) = split_drv_output(input)?;
        let drv_path = StorePath::from_basename(drv_path.as_bytes()).map_err(|error| {
            DrvOutputParseError::InvalidDerivationPath {
                message: error.to_string(),
            }
        })?;
        Ok(Self::new(drv_path, output_name))
    }

    /// Parse Nix's store-aware absolute form, `<store-path>^<output-name>`.
    pub fn parse_in(store_dir: &StoreDir, input: &str) -> Result<Self, DrvOutputParseError> {
        let (drv_path, output_name) = split_drv_output(input)?;
        let drv_path = store_dir.parse_path(drv_path.as_bytes()).map_err(|error| {
            DrvOutputParseError::InvalidDerivationPath {
                message: error.to_string(),
            }
        })?;
        Ok(Self::new(drv_path, output_name))
    }

    /// Derivation store path in this identifier.
    #[must_use]
    pub const fn drv_path(&self) -> &StorePath {
        &self.drv_path
    }

    /// Name of the derivation output.
    #[must_use]
    pub fn output_name(&self) -> &str {
        &self.output_name
    }

    /// Render Nix's absolute form using the supplied logical store directory.
    #[must_use]
    pub fn render(&self, store_dir: &StoreDir) -> String {
        format!(
            "{}^{}",
            store_dir.render_path(&self.drv_path),
            self.output_name
        )
    }
}

impl fmt::Display for DrvOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}^{}",
            self.drv_path.to_basename(),
            self.output_name
        )
    }
}

impl Serialize for DrvOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("DrvOutput", 2)?;
        output.serialize_field("drvPath", &self.drv_path)?;
        output.serialize_field("outputName", &self.output_name)?;
        output.end()
    }
}

impl FromStr for DrvOutput {
    type Err = DrvOutputParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

fn split_drv_output(input: &str) -> Result<(&str, &str), DrvOutputParseError> {
    input
        .rsplit_once('^')
        .ok_or(DrvOutputParseError::MissingSeparator)
}

/// Failure to parse a derivation-output identifier.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum DrvOutputParseError {
    /// The identifier did not contain the `^` separator.
    #[error("derivation-output identifier has no '^' separator")]
    MissingSeparator,
    /// The derivation component was not a valid store path.
    #[error("invalid derivation path: {message}")]
    InvalidDerivationPath {
        /// Store-path parser detail.
        message: String,
    },
}

/// A derived path that resolves to exactly one store path.
///
/// `P` is the representation used for the opaque base. The default is a
/// validated [`StorePath`]; transports may use `String` and validate at the
/// store boundary.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SingleDerivedPath<P = StorePath> {
    /// A concrete, already resolved path.
    Opaque(P),
    /// One named output of a derivation, which may itself be derived.
    Built {
        /// Path to the producing derivation.
        drv_path: Box<SingleDerivedPath<P>>,
        /// Requested output name.
        output: String,
    },
}

impl<P> SingleDerivedPath<P> {
    /// Return the opaque base and its ordered dynamic-output chain.
    #[must_use]
    pub fn components(&self) -> (&P, Vec<&str>) {
        let mut current = self;
        let mut outputs = Vec::new();
        loop {
            match current {
                Self::Opaque(path) => {
                    outputs.reverse();
                    return (path, outputs);
                }
                Self::Built { drv_path, output } => {
                    outputs.push(output.as_str());
                    current = drv_path;
                }
            }
        }
    }

    /// Return the concrete store-path representation at the base of the chain.
    #[must_use]
    pub fn base(&self) -> &P {
        let mut current = self;
        loop {
            match current {
                Self::Opaque(path) => return path,
                Self::Built { drv_path, .. } => current = drv_path,
            }
        }
    }
}

impl SingleDerivedPath<String> {
    /// Parse a caret-separated path without validating its opaque base.
    ///
    /// This is intended for transport boundaries. Store implementations should
    /// subsequently validate the base with [`SingleDerivedPath::parse_in`].
    #[must_use]
    pub fn parse(value: &str) -> Self {
        parse_string_single(value, '^')
    }

    /// Parse the legacy exclamation-mark-separated form without validation.
    #[must_use]
    pub fn parse_legacy(value: &str) -> Self {
        parse_string_single(value, '!')
    }
}

impl SingleDerivedPath<StorePath> {
    /// Parse a caret-separated path for a configured logical store directory.
    pub fn parse_in(store_dir: &StoreDir, value: &str) -> Result<Self, store_path::Error> {
        parse_store_single(store_dir, value, '^')
    }

    /// Parse the legacy exclamation-mark-separated form for a configured store.
    pub fn parse_legacy_in(store_dir: &StoreDir, value: &str) -> Result<Self, store_path::Error> {
        parse_store_single(store_dir, value, '!')
    }

    /// Render the caret-separated form in a configured logical store.
    #[must_use]
    pub fn render(&self, store_dir: &StoreDir) -> String {
        render_single(self, store_dir, '^')
    }

    /// Render the legacy exclamation-mark-separated form in a configured store.
    #[must_use]
    pub fn render_legacy(&self, store_dir: &StoreDir) -> String {
        render_single(self, store_dir, '!')
    }
}

impl FromStr for SingleDerivedPath<StorePath> {
    type Err = store_path::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_in(&StoreDir::default(), value)
    }
}

impl<P: fmt::Display> fmt::Display for SingleDerivedPath<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (base, outputs) = self.components();
        write!(formatter, "{base}")?;
        for output in outputs {
            write!(formatter, "^{output}")?;
        }
        Ok(())
    }
}

impl<P: Serialize> Serialize for SingleDerivedPath<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Opaque(path) => path.serialize(serializer),
            Self::Built { drv_path, output } => {
                let mut path = serializer.serialize_struct("SingleDerivedPath", 2)?;
                path.serialize_field("drvPath", drv_path)?;
                path.serialize_field("output", output)?;
                path.end()
            }
        }
    }
}

/// A derived path that resolves to either one path or a set of outputs.
///
/// An empty `outputs` vector represents Nix's `*` (all outputs).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DerivedPath<P = StorePath> {
    /// A concrete, already resolved path.
    Opaque(P),
    /// A derivation and the output names requested from it.
    Built {
        /// Path to the producing derivation.
        drv_path: SingleDerivedPath<P>,
        /// Requested output names; empty means all outputs.
        outputs: Vec<String>,
    },
}

impl<P> DerivedPath<P> {
    /// Return the opaque base at the root of this expression.
    #[must_use]
    pub fn base(&self) -> &P {
        match self {
            Self::Opaque(path) => path,
            Self::Built { drv_path, .. } => drv_path.base(),
        }
    }
}

impl<P: fmt::Display> fmt::Display for DerivedPath<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opaque(path) => write!(formatter, "{path}"),
            Self::Built { drv_path, outputs } => {
                write!(formatter, "{drv_path}^")?;
                if outputs.is_empty() {
                    formatter.write_str("*")
                } else {
                    let outputs = outputs.iter().collect::<BTreeSet<_>>();
                    for (index, output) in outputs.into_iter().enumerate() {
                        if index != 0 {
                            formatter.write_str(",")?;
                        }
                        formatter.write_str(output)?;
                    }
                    Ok(())
                }
            }
        }
    }
}

impl<P: Serialize> Serialize for DerivedPath<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Opaque(path) => path.serialize(serializer),
            Self::Built { drv_path, outputs } => {
                let mut path = serializer.serialize_struct("DerivedPath", 2)?;
                path.serialize_field("drvPath", drv_path)?;
                path.serialize_field("outputs", &JsonOutputs(outputs))?;
                path.end()
            }
        }
    }
}

struct JsonOutputs<'a>(&'a [String]);

impl Serialize for JsonOutputs<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.is_empty() {
            let mut outputs = serializer.serialize_seq(Some(1))?;
            outputs.serialize_element("*")?;
            return outputs.end();
        }

        let canonical = self.0.iter().collect::<BTreeSet<_>>();
        let mut outputs = serializer.serialize_seq(Some(canonical.len()))?;
        for output in canonical {
            outputs.serialize_element(output)?;
        }
        outputs.end()
    }
}

impl DerivedPath<StorePath> {
    /// Parse Nix's caret-separated derived-path representation.
    pub fn parse_in(store_dir: &StoreDir, value: &str) -> Result<Self, store_path::Error> {
        parse_store_derived(store_dir, value, '^')
    }

    /// Parse Nix's legacy exclamation-mark-separated representation.
    pub fn parse_legacy_in(store_dir: &StoreDir, value: &str) -> Result<Self, store_path::Error> {
        parse_store_derived(store_dir, value, '!')
    }

    /// Render Nix's caret-separated form in a configured logical store.
    #[must_use]
    pub fn render(&self, store_dir: &StoreDir) -> String {
        render_derived(self, store_dir, '^')
    }

    /// Render Nix's legacy exclamation-mark-separated form in a configured store.
    #[must_use]
    pub fn render_legacy(&self, store_dir: &StoreDir) -> String {
        render_derived(self, store_dir, '!')
    }
}

impl FromStr for DerivedPath<StorePath> {
    type Err = store_path::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_in(&StoreDir::default(), value)
    }
}

fn parse_string_single(value: &str, separator: char) -> SingleDerivedPath<String> {
    let mut parts = value.split(separator);
    let mut path = SingleDerivedPath::Opaque(parts.next().unwrap_or_default().to_owned());
    for output in parts {
        path = SingleDerivedPath::Built {
            drv_path: Box::new(path),
            output: output.to_owned(),
        };
    }
    path
}

fn parse_store_single(
    store_dir: &StoreDir,
    value: &str,
    separator: char,
) -> Result<SingleDerivedPath<StorePath>, store_path::Error> {
    let mut parts = value.split(separator);
    let base = parts.next().unwrap_or_default();
    let mut path = SingleDerivedPath::Opaque(store_dir.parse_path(base.as_bytes())?);
    for output in parts {
        path = SingleDerivedPath::Built {
            drv_path: Box::new(path),
            output: output.to_owned(),
        };
    }
    Ok(path)
}

fn parse_store_derived(
    store_dir: &StoreDir,
    value: &str,
    separator: char,
) -> Result<DerivedPath<StorePath>, store_path::Error> {
    let Some((drv_path, outputs)) = value.rsplit_once(separator) else {
        return Ok(DerivedPath::Opaque(store_dir.parse_path(value.as_bytes())?));
    };
    Ok(DerivedPath::Built {
        drv_path: parse_store_single(store_dir, drv_path, separator)?,
        outputs: parse_outputs(outputs)?,
    })
}

fn parse_outputs(value: &str) -> Result<Vec<String>, store_path::Error> {
    if value == "*" {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|name| {
            store_path::validate_name(name)
                .map_err(|_| store_path::Error::InvalidOutputName(name.to_owned()))?;
            Ok(name.to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(BTreeSet::into_iter)
        .map(Iterator::collect)
}

fn render_single(
    value: &SingleDerivedPath<StorePath>,
    store_dir: &StoreDir,
    separator: char,
) -> String {
    let (base, outputs) = value.components();
    let mut rendered = store_dir.render_path(base);
    for output in outputs {
        rendered.push(separator);
        rendered.push_str(output);
    }
    rendered
}

fn render_derived(value: &DerivedPath<StorePath>, store_dir: &StoreDir, separator: char) -> String {
    match value {
        DerivedPath::Opaque(path) => store_dir.render_path(path),
        DerivedPath::Built { drv_path, outputs } => {
            let mut rendered = render_single(drv_path, store_dir, separator);
            rendered.push(separator);
            if outputs.is_empty() {
                rendered.push('*');
            } else {
                let outputs = outputs.iter().collect::<BTreeSet<_>>();
                for (index, output) in outputs.into_iter().enumerate() {
                    if index != 0 {
                        rendered.push(',');
                    }
                    rendered.push_str(output);
                }
            }
            rendered
        }
    }
}
