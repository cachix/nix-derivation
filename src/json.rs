//! Nix derivation JSON format version 4.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};

use crate::{
    CAHash, ContentAddressMethod, Derivation, Error, HashAlgorithm, InputDerivation,
    MAX_DYNAMIC_INPUT_DEPTH, NixHash, Output, StoreDir, StorePath, StructuredAttrs,
};

/// The complete derivation JSON format version supported by Nix.
pub const VERSION: u64 = 4;

const MAX_JSON_NESTING: usize = MAX_DYNAMIC_INPUT_DEPTH * 2 + 32;

#[derive(Deserialize)]
struct WireVersion {
    version: u64,
}

#[derive(Deserialize)]
struct WireDerivation {
    version: u64,
    name: String,
    outputs: BTreeMap<String, Value>,
    inputs: WireInputs,
    system: String,
    builder: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    #[serde(
        rename = "structuredAttrs",
        default,
        deserialize_with = "deserialize_present"
    )]
    structured_attrs: Option<Value>,
}

fn deserialize_present<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct WireInputs {
    srcs: Vec<String>,
    drvs: BTreeMap<String, WireInput>,
}

#[derive(Deserialize)]
struct WireInput {
    outputs: Vec<String>,
    #[serde(rename = "dynamicOutputs")]
    dynamic_outputs: BTreeMap<String, WireInput>,
}

#[derive(Serialize)]
struct EncodedDerivation<'a> {
    args: &'a [String],
    builder: &'a str,
    env: BTreeMap<&'a str, &'a str>,
    inputs: EncodedInputs<'a>,
    name: &'a str,
    outputs: BTreeMap<&'a str, Value>,
    #[serde(rename = "structuredAttrs", skip_serializing_if = "Option::is_none")]
    structured_attrs: Option<Box<RawValue>>,
    system: &'a str,
    version: u64,
}

#[derive(Serialize)]
struct EncodedInputs<'a> {
    drvs: BTreeMap<String, EncodedInput<'a>>,
    srcs: Vec<String>,
}

#[derive(Serialize)]
struct EncodedInput<'a> {
    #[serde(rename = "dynamicOutputs")]
    dynamic_outputs: BTreeMap<&'a str, EncodedInput<'a>>,
    outputs: &'a BTreeSet<String>,
}

/// Parse complete derivation JSON version 4 in the default `/nix/store`.
pub fn from_slice(bytes: &[u8]) -> Result<Derivation, Error> {
    from_slice_in(bytes, StoreDir::default())
}

/// Parse complete derivation JSON version 4 in a configured logical store.
pub fn from_slice_in(bytes: &[u8], store_dir: StoreDir) -> Result<Derivation, Error> {
    check_nesting(bytes)?;

    // Decode the version independently so another format's shape cannot hide
    // the more useful unsupported-version error behind a v4 field error.
    let mut version_deserializer = serde_json::Deserializer::from_slice(bytes);
    version_deserializer.disable_recursion_limit();
    let version = WireVersion::deserialize(&mut version_deserializer)
        .map_err(|error| Error::Json(error.to_string()))?;
    version_deserializer
        .end()
        .map_err(|error| Error::Json(error.to_string()))?;
    if version.version != VERSION {
        return Err(Error::UnsupportedJsonVersion {
            found: version.version,
            expected: VERSION,
        });
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    deserializer.disable_recursion_limit();
    let wire = WireDerivation::deserialize(&mut deserializer)
        .map_err(|error| Error::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| Error::Json(error.to_string()))?;
    from_wire(wire, store_dir)
}

fn check_nesting(bytes: &[u8]) -> Result<(), Error> {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_NESTING {
                    return Err(Error::Json(format!(
                        "JSON nesting exceeds {MAX_JSON_NESTING} levels"
                    )));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn from_wire(wire: WireDerivation, store_dir: StoreDir) -> Result<Derivation, Error> {
    if wire.version != VERSION {
        return Err(Error::UnsupportedJsonVersion {
            found: wire.version,
            expected: VERSION,
        });
    }
    let aterm_size_hint = bytes_size_hint(&wire);

    let outputs = wire
        .outputs
        .into_iter()
        .map(|(name, output)| Ok((name, parse_output(output)?)))
        .collect::<Result<_, Error>>()?;
    let input_sources = wire
        .inputs
        .srcs
        .into_iter()
        .map(|path| parse_store_path(&path))
        .collect::<Result<_, Error>>()?;
    let input_derivations = wire
        .inputs
        .drvs
        .into_iter()
        .map(|(path, input)| Ok((parse_store_path(&path)?, parse_input(input, 0)?)))
        .collect::<Result<_, Error>>()?;
    let structured_attrs = wire
        .structured_attrs
        .map(|value| {
            serde_json::to_vec(&value)
                .map_err(|error| Error::Json(error.to_string()))
                .and_then(StructuredAttrs::from_json_bytes)
        })
        .transpose()?;

    Ok(Derivation {
        store_dir,
        name: wire.name,
        outputs,
        input_derivations,
        input_sources,
        system: wire.system,
        builder: wire.builder,
        arguments: wire.args,
        environment: wire
            .env
            .into_iter()
            .map(|(key, value)| (key, value.into_bytes()))
            .collect(),
        structured_attrs,
        aterm_size_hint,
    })
}

fn bytes_size_hint(wire: &WireDerivation) -> usize {
    256 + wire.name.len()
        + wire.system.len()
        + wire.builder.len()
        + wire.args.iter().map(String::len).sum::<usize>()
        + wire
            .env
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
}

fn parse_store_path(path: &str) -> Result<StorePath, Error> {
    Ok(StorePath::from_basename(path.as_bytes())?)
}

fn parse_input(wire: WireInput, depth: usize) -> Result<InputDerivation, Error> {
    if depth > MAX_DYNAMIC_INPUT_DEPTH {
        return Err(Error::InvalidDerivation(format!(
            "dynamic input derivation nesting exceeds {MAX_DYNAMIC_INPUT_DEPTH} levels"
        )));
    }
    let mut input = InputDerivation::new(wire.outputs);
    for (name, child) in wire.dynamic_outputs {
        input.insert_dynamic_output(name, parse_input(child, depth + 1)?)?;
    }
    Ok(input)
}

fn parse_output(value: Value) -> Result<Output, Error> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::Json("derivation output must be an object".to_owned()))?;
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();

    if keys == BTreeSet::from(["path"]) {
        return Ok(Output::InputAddressed {
            path: parse_store_path(string_field(object, "path")?)?,
        });
    }
    if keys == BTreeSet::from(["hash", "method"]) {
        let method: ContentAddressMethod = string_field(object, "method")?.parse()?;
        let hash = NixHash::parse_sri(string_field(object, "hash")?)?;
        return Ok(Output::Fixed {
            ca: CAHash::from_parts(method, hash.algorithm(), hash.digest_as_bytes())?,
        });
    }
    if keys == BTreeSet::from(["hashAlgo", "method"]) {
        return Ok(Output::Floating {
            method: string_field(object, "method")?.parse()?,
            hash_algorithm: string_field(object, "hashAlgo")?.parse()?,
        });
    }
    if keys.is_empty() {
        return Ok(Output::Deferred);
    }
    if keys == BTreeSet::from(["hashAlgo", "impure", "method"]) {
        return Ok(Output::Impure {
            method: string_field(object, "method")?.parse()?,
            hash_algorithm: string_field(object, "hashAlgo")?.parse()?,
        });
    }

    Err(Error::Json("invalid JSON for derivation output".to_owned()))
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Json(format!("derivation output field {key:?} must be a string")))
}

/// Convert a derivation to Nix's JSON version 4 value tree.
pub fn to_value(derivation: &Derivation) -> Result<Value, Error> {
    serde_json::to_value(encoded(derivation)?).map_err(|error| Error::Json(error.to_string()))
}

/// Serialize a derivation as compact Nix JSON version 4.
pub fn to_vec(derivation: &Derivation) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&encoded(derivation)?).map_err(|error| Error::Json(error.to_string()))
}

/// Stream a derivation as compact Nix JSON version 4.
pub fn write<W: io::Write + ?Sized>(derivation: &Derivation, writer: &mut W) -> Result<(), Error> {
    serde_json::to_writer(writer, &encoded(derivation)?)
        .map_err(|error| Error::Json(error.to_string()))
}

fn encoded(derivation: &Derivation) -> Result<EncodedDerivation<'_>, Error> {
    let env = derivation
        .environment
        .iter()
        .map(|(key, value)| {
            std::str::from_utf8(value)
                .map(|value| (key.as_str(), value))
                .map_err(|_| Error::InvalidUtf8 {
                    field: "environment value in derivation JSON",
                })
        })
        .collect::<Result<_, Error>>()?;
    let outputs = derivation
        .outputs
        .iter()
        .map(|(name, output)| Ok((name.as_str(), encode_output(output))))
        .collect::<Result<_, Error>>()?;
    let structured_attrs = derivation
        .structured_attrs
        .as_ref()
        .map(|attrs| {
            let canonical = String::from_utf8(attrs.canonical_json().to_vec()).map_err(|_| {
                Error::InvalidUtf8 {
                    field: "structured attributes in derivation JSON",
                }
            })?;
            RawValue::from_string(canonical).map_err(|error| Error::Json(error.to_string()))
        })
        .transpose()?;

    Ok(EncodedDerivation {
        args: &derivation.arguments,
        builder: &derivation.builder,
        env,
        inputs: EncodedInputs {
            drvs: derivation
                .input_derivations
                .iter()
                .map(|(path, input)| (path.to_basename(), encode_input(input)))
                .collect(),
            srcs: derivation
                .input_sources
                .iter()
                .map(StorePath::to_basename)
                .collect(),
        },
        name: &derivation.name,
        outputs,
        structured_attrs,
        system: &derivation.system,
        version: VERSION,
    })
}

fn encode_input(input: &InputDerivation) -> EncodedInput<'_> {
    EncodedInput {
        dynamic_outputs: input
            .dynamic_outputs()
            .iter()
            .map(|(name, input)| (name.as_str(), encode_input(input)))
            .collect(),
        outputs: input.outputs(),
    }
}

fn encode_output(output: &Output) -> Value {
    let mut object = Map::new();
    match output {
        Output::InputAddressed { path } => {
            object.insert("path".to_owned(), Value::String(path.to_basename()));
        }
        Output::Fixed { ca } => {
            object.insert("method".to_owned(), Value::String(ca.method().to_string()));
            object.insert("hash".to_owned(), Value::String(ca.hash().to_sri_string()));
        }
        Output::Floating {
            method,
            hash_algorithm,
        } => {
            encode_method_algorithm(&mut object, *method, *hash_algorithm);
        }
        Output::Deferred => {}
        Output::Impure {
            method,
            hash_algorithm,
        } => {
            encode_method_algorithm(&mut object, *method, *hash_algorithm);
            object.insert("impure".to_owned(), Value::Bool(true));
        }
    }
    Value::Object(object)
}

fn encode_method_algorithm(
    object: &mut Map<String, Value>,
    method: ContentAddressMethod,
    algorithm: HashAlgorithm,
) {
    object.insert("method".to_owned(), Value::String(method.to_string()));
    object.insert("hashAlgo".to_owned(), Value::String(algorithm.to_string()));
}
