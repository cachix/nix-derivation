//! Lossless derivation CBOR format version 1, specific to this crate.
//!
//! This is an interchange format, not a Nix store encoding. Store paths and
//! derivation hashes still use ATerm. See `docs/cbor.md` in the repository for
//! the complete wire schema.
//!
//! The structure follows Nix JSON v4, with version `1`, environment values
//! encoded as byte strings, and optional `structuredAttrs` encoded as a byte
//! string containing Nix-compatible canonical JSON. Other strings are UTF-8
//! text, preserved without Unicode normalization. Store paths are basenames;
//! the logical store directory is supplied out of band.
//!
//! Writers follow RFC 8949 section 4.2.1: shortest encodings, definite lengths,
//! and maps sorted by encoded key bytes. Readers also accept unordered maps
//! and non-minimal lengths/integers, but reject duplicate keys, duplicate set
//! entries, unknown fields, indefinite lengths, trailing data, and wrong types.
//!
//! # Example
//!
//! ```
//! use nix_derivation::{Derivation, DerivationBuilder};
//!
//! let drv = DerivationBuilder::new("binary", "x86_64-linux", "/bin/sh")
//!     .input_addressed_output("out")
//!     .environment("payload", vec![0x00, 0xff, 0x80])
//!     .build()?
//!     .into_derivation();
//! let decoded = Derivation::from_cbor_bytes(&drv.to_cbor_bytes()?)?;
//! assert_eq!(decoded.to_aterm_bytes(), drv.to_aterm_bytes());
//! # Ok::<(), nix_derivation::Error>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use minicbor::{Decoder, Encoder, encode::write::Writer};

use crate::{
    CAHash, Derivation, Error, InputDerivation, MAX_DYNAMIC_INPUT_DEPTH, NixHash, Output, StoreDir,
    StorePath, StructuredAttrs,
};

/// Version of this crate's derivation CBOR schema (independent of Nix JSON).
pub const VERSION: u64 = 1;

impl From<minicbor::decode::Error> for Error {
    fn from(error: minicbor::decode::Error) -> Self {
        Self::Cbor(error.to_string())
    }
}

impl From<minicbor::encode::Error<io::Error>> for Error {
    fn from(error: minicbor::encode::Error<io::Error>) -> Self {
        Self::Cbor(match error.as_write() {
            Some(source) => format!("{error}: {source}"),
            None => error.to_string(),
        })
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Cbor(message.into())
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| invalid(format!("missing field {field:?}")))
}

/// Parse one complete CBOR derivation using the default `/nix/store`.
pub fn from_slice(bytes: &[u8]) -> Result<Derivation, Error> {
    from_slice_in(bytes, StoreDir::default())
}

/// Parse one complete CBOR derivation using a configured logical store.
///
/// As with ATerm and JSON parsing, build validity is checked separately with
/// [`Derivation::validate`].
pub fn from_slice_in(bytes: &[u8], store_dir: StoreDir) -> Result<Derivation, Error> {
    let mut reader = Reader(Decoder::new(bytes));
    let (mut version, mut name, mut system, mut builder) = (None, None, None, None);
    let (mut args, mut env, mut inputs, mut outputs, mut attrs) = (None, None, None, None, None);
    reader.map(|r, key| {
        match key {
            "version" => {
                let found = r.0.u64()?;
                if found != VERSION {
                    return Err(Error::UnsupportedCborVersion {
                        found,
                        expected: VERSION,
                    });
                }
                version = Some(found);
            }
            "name" => name = Some(r.text()?),
            "system" => system = Some(r.text()?),
            "builder" => builder = Some(r.text()?),
            "args" => args = Some(r.array(Reader::text)?),
            "env" => env = Some(owned_keys(r.map(|r, _| Ok(r.0.bytes()?.to_vec()))?)),
            "inputs" => inputs = Some(r.inputs()?),
            "outputs" => outputs = Some(owned_keys(r.map(|r, _| r.output())?)),
            "structuredAttrs" => attrs = Some(StructuredAttrs::from_json_bytes(r.0.bytes()?)?),
            _ => return Err(invalid(format!("unknown derivation field {key:?}"))),
        }
        Ok(())
    })?;
    if reader.0.position() != bytes.len() {
        return Err(invalid("trailing data after derivation"));
    }
    required(version, "version")?;
    let (input_sources, input_derivations) = required(inputs, "inputs")?;
    Ok(Derivation {
        store_dir,
        name: required(name, "name")?,
        system: required(system, "system")?,
        builder: required(builder, "builder")?,
        arguments: required(args, "args")?,
        environment: required(env, "env")?,
        outputs: required(outputs, "outputs")?,
        input_sources,
        input_derivations,
        structured_attrs: attrs,
        aterm_size_hint: bytes.len(),
    })
}

fn owned_keys<T>(map: BTreeMap<&str, T>) -> BTreeMap<String, T> {
    map.into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

struct Reader<'b>(Decoder<'b>);

impl<'b> Reader<'b> {
    fn text(&mut self) -> Result<String, Error> {
        Ok(self.0.str()?.to_owned())
    }

    fn length(&self, length: Option<u64>, minimum_item_bytes: u64) -> Result<u64, Error> {
        let length = length.ok_or_else(|| invalid("indefinite lengths are not supported"))?;
        let remaining = (self.0.input().len() - self.0.position()) as u64;
        if length > remaining / minimum_item_bytes {
            return Err(invalid("container length exceeds remaining input"));
        }
        Ok(length)
    }

    fn map<T>(
        &mut self,
        mut read: impl FnMut(&mut Self, &'b str) -> Result<T, Error>,
    ) -> Result<BTreeMap<&'b str, T>, Error> {
        let length = self.0.map()?;
        let length = self.length(length, 2)?;
        let mut result = BTreeMap::new();
        for _ in 0..length {
            let key = self.0.str()?;
            if result.contains_key(key) {
                return Err(invalid(format!("duplicate map key {key:?}")));
            }
            result.insert(key, read(self, key)?);
        }
        Ok(result)
    }

    fn array<T>(
        &mut self,
        mut read: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let length = self.0.array()?;
        let length = self.length(length, 1)?;
        let mut result = Vec::new();
        for _ in 0..length {
            result.push(read(self)?);
        }
        Ok(result)
    }

    fn inputs(
        &mut self,
    ) -> Result<(BTreeSet<StorePath>, BTreeMap<StorePath, InputDerivation>), Error> {
        let (mut srcs, mut drvs) = (None, None);
        self.map(|r, key| {
            match key {
                "srcs" => srcs = Some(unique_set(r.array(|r| store_path(r.0.str()?))?)?),
                "drvs" => {
                    let entries = r.map(|r, key| Ok((store_path(key)?, r.input(0)?)))?;
                    drvs = Some(entries.into_values().collect());
                }
                _ => return Err(invalid(format!("unknown inputs field {key:?}"))),
            }
            Ok(())
        })?;
        Ok((required(srcs, "srcs")?, required(drvs, "drvs")?))
    }

    fn input(&mut self, depth: usize) -> Result<InputDerivation, Error> {
        if depth > MAX_DYNAMIC_INPUT_DEPTH {
            return Err(invalid(format!(
                "dynamic input derivation nesting exceeds {MAX_DYNAMIC_INPUT_DEPTH} levels"
            )));
        }
        let (mut outputs, mut dynamic_outputs) = (None, None);
        self.map(|r, key| {
            match key {
                "outputs" => outputs = Some(unique_set(r.array(Self::text)?)?),
                "dynamicOutputs" => {
                    dynamic_outputs = Some(owned_keys(r.map(|r, _| r.input(depth + 1))?))
                }
                _ => return Err(invalid(format!("unknown input derivation field {key:?}"))),
            }
            Ok(())
        })?;
        // The depth was checked while reading, so no subtree scans are needed.
        Ok(InputDerivation {
            outputs: required(outputs, "outputs")?,
            dynamic_outputs: required(dynamic_outputs, "dynamicOutputs")?,
        })
    }

    fn output(&mut self) -> Result<Output, Error> {
        let (mut path, mut method, mut hash, mut algorithm, mut impure) =
            (None, None, None, None, None);
        self.map(|r, key| {
            match key {
                "path" => path = Some(store_path(r.0.str()?)?),
                "method" => method = Some(r.0.str()?.parse()?),
                "hash" => hash = Some(NixHash::parse_sri(r.0.str()?)?),
                "hashAlgo" => algorithm = Some(r.0.str()?.parse()?),
                "impure" => impure = Some(r.0.bool()?),
                _ => return Err(invalid(format!("unknown output field {key:?}"))),
            }
            Ok(())
        })?;
        match (path, method, hash, algorithm, impure) {
            (Some(path), None, None, None, None) => Ok(Output::InputAddressed { path }),
            (None, Some(method), Some(hash), None, None) => Ok(Output::Fixed {
                ca: CAHash::from_parts(method, hash.algorithm(), hash.digest_as_bytes())?,
            }),
            (None, Some(method), None, Some(hash_algorithm), None) => Ok(Output::Floating {
                method,
                hash_algorithm,
            }),
            (None, None, None, None, None) => Ok(Output::Deferred),
            (None, Some(method), None, Some(hash_algorithm), Some(true)) => Ok(Output::Impure {
                method,
                hash_algorithm,
            }),
            _ => Err(invalid("invalid derivation output fields")),
        }
    }
}

fn store_path(path: &str) -> Result<StorePath, Error> {
    Ok(StorePath::from_basename(path.as_bytes())?)
}

fn unique_set<T: Ord>(values: Vec<T>) -> Result<BTreeSet<T>, Error> {
    let mut set = BTreeSet::new();
    for value in values {
        if !set.insert(value) {
            return Err(invalid("duplicate set entry"));
        }
    }
    Ok(set)
}

/// Serialize a derivation using deterministic CBOR encoding.
pub fn to_vec(derivation: &Derivation) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    write(derivation, &mut bytes)?;
    Ok(bytes)
}

/// Stream deterministic CBOR to an I/O writer without buffering the document.
pub fn write<W: io::Write + ?Sized>(derivation: &Derivation, writer: &mut W) -> Result<(), Error> {
    let mut writer = CborWriter(Encoder::new(Writer::new(writer)));
    writer.derivation(derivation)
}

struct CborWriter<W>(Encoder<Writer<W>>);

impl<W: io::Write> CborWriter<W> {
    fn derivation(&mut self, drv: &Derivation) -> Result<(), Error> {
        // All map keys in the schema are text: encoded-key order is byte
        // length first, then lexical UTF-8 byte order for equal lengths.
        self.0
            .map(if drv.structured_attrs.is_some() { 9 } else { 8 })?;
        self.0.str("env")?;
        self.map(drv.environment.iter(), |w, value| {
            w.0.bytes(value)?;
            Ok(())
        })?;
        self.0.str("args")?;
        self.strings(drv.arguments.iter().map(String::as_str))?;
        self.0.str("name")?.str(&drv.name)?;
        self.0.str("inputs")?.map(2)?.str("drvs")?;
        self.map(
            drv.input_derivations
                .iter()
                .map(|(path, input)| (path.to_basename(), input)),
            |w, input| w.input(input),
        )?;
        self.0.str("srcs")?;
        let mut sources: Vec<_> = drv
            .input_sources
            .iter()
            .map(StorePath::to_basename)
            .collect();
        sources.sort_unstable();
        self.strings(sources.iter())?;
        self.0.str("system")?.str(&drv.system)?;
        self.0.str("builder")?.str(&drv.builder)?;
        self.0.str("outputs")?;
        self.map(drv.outputs.iter(), |w, output| w.output(output))?;
        self.0.str("version")?.u64(VERSION)?;
        if let Some(attrs) = &drv.structured_attrs {
            self.0
                .str("structuredAttrs")?
                .bytes(attrs.canonical_json())?;
        }
        Ok(())
    }

    fn map<K: AsRef<str>, V>(
        &mut self,
        entries: impl Iterator<Item = (K, V)>,
        mut write: impl FnMut(&mut Self, V) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut entries: Vec<_> = entries.collect();
        entries.sort_unstable_by(|(a, _), (b, _)| {
            let (a, b) = (a.as_ref(), b.as_ref());
            a.len()
                .cmp(&b.len())
                .then_with(|| a.as_bytes().cmp(b.as_bytes()))
        });
        self.0.map(entries.len() as u64)?;
        for (key, value) in entries {
            self.0.str(key.as_ref())?;
            write(self, value)?;
        }
        Ok(())
    }

    fn strings<S: AsRef<str>>(
        &mut self,
        strings: impl ExactSizeIterator<Item = S>,
    ) -> Result<(), Error> {
        self.0.array(strings.len() as u64)?;
        for string in strings {
            self.0.str(string.as_ref())?;
        }
        Ok(())
    }

    fn input(&mut self, input: &InputDerivation) -> Result<(), Error> {
        self.0.map(2)?.str("outputs")?;
        self.strings(input.outputs.iter().map(String::as_str))?;
        self.0.str("dynamicOutputs")?;
        self.map(input.dynamic_outputs.iter(), |w, input| w.input(input))
    }

    fn output(&mut self, output: &Output) -> Result<(), Error> {
        match output {
            Output::InputAddressed { path } => {
                self.0.map(1)?.str("path")?.str(&path.to_basename())?;
            }
            Output::Fixed { ca } => {
                self.0
                    .map(2)?
                    .str("hash")?
                    .str(&ca.hash().to_sri_string())?
                    .str("method")?
                    .str(&ca.method().to_string())?;
            }
            Output::Floating {
                method,
                hash_algorithm,
            }
            | Output::Impure {
                method,
                hash_algorithm,
            } => {
                let impure = matches!(output, Output::Impure { .. });
                self.0.map(if impure { 3 } else { 2 })?;
                if impure {
                    self.0.str("impure")?.bool(true)?;
                }
                self.0
                    .str("method")?
                    .str(&method.to_string())?
                    .str("hashAlgo")?
                    .str(hash_algorithm.as_str())?;
            }
            Output::Deferred => {
                self.0.map(0)?;
            }
        }
        Ok(())
    }
}
