use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use crate::InputDerivation;
use crate::{CAHash, ContentAddressMethod, Derivation, HashAlgorithm, NixHash, Output, StorePath};

pub(super) fn serialize(
    derivation: &Derivation,
    writer: &mut impl Write,
    mask_outputs: bool,
    actual_inputs: Option<&BTreeMap<[u8; 32], BTreeSet<String>>>,
) -> io::Result<()> {
    if derivation
        .input_derivations
        .values()
        .any(InputDerivation::is_dynamic)
    {
        writer.write_all(b"DrvWithVersion(\"xp-dyn-drv\",")?;
    } else {
        writer.write_all(b"Derive(")?;
    }
    write_outputs(derivation, writer, mask_outputs)?;
    writer.write_all(b",")?;
    write_inputs(derivation, writer, actual_inputs)?;
    writer.write_all(b",")?;
    write_store_paths(writer, derivation.input_sources.iter())?;
    writer.write_all(b",")?;
    write_unquoted(writer, derivation.system.as_bytes())?;
    writer.write_all(b",")?;
    write_escaped(writer, derivation.builder.as_bytes())?;
    writer.write_all(b",")?;
    write_string_list(
        writer,
        derivation.arguments.iter().map(|value| value.as_bytes()),
    )?;
    writer.write_all(b",")?;
    write_environment(derivation, writer, mask_outputs)?;
    writer.write_all(b")")
}

fn write_outputs(
    derivation: &Derivation,
    writer: &mut impl Write,
    mask_outputs: bool,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, (name, output)) in derivation.outputs.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(b"(")?;
        write_unquoted(writer, name.as_bytes())?;
        writer.write_all(b",")?;
        match output {
            Output::InputAddressed { path } => {
                if mask_outputs {
                    write_unquoted(writer, b"")?;
                } else {
                    write_unquoted(writer, path.to_absolute_path().as_bytes())?;
                }
                writer.write_all(b",\"\",\"\"")?;
            }
            Output::Fixed { ca } => {
                if mask_outputs {
                    write_unquoted(writer, b"")?;
                } else {
                    let path = output
                        .path(&derivation.name, name)
                        .expect("validated fixed output path")
                        .expect("fixed outputs have paths");
                    write_unquoted(writer, path.to_absolute_path().as_bytes())?;
                }
                writer.write_all(b",")?;
                let (method, hash) = fixed_parts(ca);
                write_unquoted(writer, method.as_bytes())?;
                writer.write_all(b",")?;
                write_unquoted_hex(writer, hash.digest_as_bytes())?;
            }
            Output::Floating {
                method,
                hash_algorithm,
            } => {
                write_unquoted(writer, b"")?;
                writer.write_all(b",")?;
                write_method_algorithm(writer, *method, *hash_algorithm)?;
                writer.write_all(b",\"\"")?;
            }
            Output::Deferred => writer.write_all(b"\"\",\"\",\"\"")?,
            Output::Impure {
                method,
                hash_algorithm,
            } => {
                write_unquoted(writer, b"")?;
                writer.write_all(b",")?;
                write_method_algorithm(writer, *method, *hash_algorithm)?;
                writer.write_all(b",\"impure\"")?;
            }
        }
        writer.write_all(b")")?;
    }
    writer.write_all(b"]")
}

fn write_inputs(
    derivation: &Derivation,
    writer: &mut impl Write,
    actual_inputs: Option<&BTreeMap<[u8; 32], BTreeSet<String>>>,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    if let Some(actual_inputs) = actual_inputs {
        for (index, (hash, outputs)) in actual_inputs.iter().enumerate() {
            if index != 0 {
                writer.write_all(b",")?;
            }
            writer.write_all(b"(")?;
            write_unquoted_hex(writer, hash)?;
            writer.write_all(b",")?;
            write_unquoted_string_list(writer, outputs.iter().map(|value| value.as_bytes()))?;
            writer.write_all(b")")?;
        }
    } else {
        for (index, (path, input)) in derivation.input_derivations.iter().enumerate() {
            if index != 0 {
                writer.write_all(b",")?;
            }
            writer.write_all(b"(")?;
            write_unquoted(writer, path.to_absolute_path().as_bytes())?;
            writer.write_all(b",")?;
            write_input_derivation(writer, input)?;
            writer.write_all(b")")?;
        }
    }
    writer.write_all(b"]")
}

fn write_input_derivation(writer: &mut impl Write, input: &InputDerivation) -> io::Result<()> {
    if input.dynamic_outputs.is_empty() {
        return write_unquoted_string_list(
            writer,
            input.outputs.iter().map(|value| value.as_bytes()),
        );
    }

    writer.write_all(b"(")?;
    write_unquoted_string_list(writer, input.outputs.iter().map(|value| value.as_bytes()))?;
    writer.write_all(b",[")?;
    for (index, (name, child)) in input.dynamic_outputs.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(b"(")?;
        write_unquoted(writer, name.as_bytes())?;
        writer.write_all(b",")?;
        write_input_derivation(writer, child)?;
        writer.write_all(b")")?;
    }
    writer.write_all(b"])")
}

fn write_store_paths<'a>(
    writer: &mut impl Write,
    paths: impl Iterator<Item = &'a StorePath>,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, path) in paths.enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        write_unquoted(writer, path.to_absolute_path().as_bytes())?;
    }
    writer.write_all(b"]")
}

fn write_environment(
    derivation: &Derivation,
    writer: &mut impl Write,
    mask_outputs: bool,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    let mut first = true;
    let mut wrote_structured_attrs = false;
    for (key, value) in &derivation.environment {
        if !wrote_structured_attrs && key.as_str() > "__json" {
            if let Some(attrs) = derivation.structured_attrs.as_ref() {
                write_environment_entry(
                    derivation,
                    writer,
                    &mut first,
                    "__json",
                    attrs.canonical_json(),
                    mask_outputs,
                )?;
            }
            wrote_structured_attrs = true;
        }
        write_environment_entry(derivation, writer, &mut first, key, value, mask_outputs)?;
    }
    if !wrote_structured_attrs && let Some(attrs) = derivation.structured_attrs.as_ref() {
        write_environment_entry(
            derivation,
            writer,
            &mut first,
            "__json",
            attrs.canonical_json(),
            mask_outputs,
        )?;
    }
    writer.write_all(b"]")
}

fn write_environment_entry(
    derivation: &Derivation,
    writer: &mut impl Write,
    first: &mut bool,
    key: &str,
    value: &[u8],
    mask_outputs: bool,
) -> io::Result<()> {
    if !*first {
        writer.write_all(b",")?;
    }
    *first = false;
    writer.write_all(b"(")?;
    write_escaped(writer, key.as_bytes())?;
    writer.write_all(b",")?;
    if mask_outputs && derivation.outputs.contains_key(key) {
        write_escaped(writer, b"")?;
    } else {
        write_escaped(writer, value)?;
    }
    writer.write_all(b")")
}

fn write_string_list<'a>(
    writer: &mut impl Write,
    values: impl Iterator<Item = &'a [u8]>,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, value) in values.enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        write_escaped(writer, value)?;
    }
    writer.write_all(b"]")
}

fn write_unquoted_string_list<'a>(
    writer: &mut impl Write,
    values: impl Iterator<Item = &'a [u8]>,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, value) in values.enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        write_unquoted(writer, value)?;
    }
    writer.write_all(b"]")
}

fn write_escaped(writer: &mut impl Write, value: &[u8]) -> io::Result<()> {
    writer.write_all(b"\"")?;
    let mut start = 0;
    for (index, byte) in value.iter().copied().enumerate() {
        let escape: Option<&[u8]> = match byte {
            b'"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            b'\n' => Some(b"\\n"),
            b'\r' => Some(b"\\r"),
            b'\t' => Some(b"\\t"),
            _ => None,
        };
        if let Some(escape) = escape {
            writer.write_all(&value[start..index])?;
            writer.write_all(escape)?;
            start = index + 1;
        }
    }
    writer.write_all(&value[start..])?;
    writer.write_all(b"\"")
}

fn write_unquoted(writer: &mut impl Write, value: &[u8]) -> io::Result<()> {
    writer.write_all(b"\"")?;
    writer.write_all(value)?;
    writer.write_all(b"\"")
}

fn write_unquoted_hex(writer: &mut impl Write, value: &[u8]) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    writer.write_all(b"\"")?;
    for byte in value {
        writer.write_all(&[HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]])?;
    }
    writer.write_all(b"\"")
}

fn write_method_algorithm(
    writer: &mut impl Write,
    method: ContentAddressMethod,
    algorithm: HashAlgorithm,
) -> io::Result<()> {
    writer.write_all(b"\"")?;
    writer.write_all(method.prefix().as_bytes())?;
    writer.write_all(algorithm.as_str().as_bytes())?;
    writer.write_all(b"\"")
}

fn fixed_parts(ca: &CAHash) -> (String, NixHash) {
    match ca {
        CAHash::Flat(hash) => (hash.algo().to_owned(), hash.clone()),
        CAHash::Nar(hash) => (format!("r:{}", hash.algo()), hash.clone()),
        CAHash::Text(digest) => ("text:sha256".to_owned(), NixHash::Sha256(*digest)),
        CAHash::Git(hash) => (format!("git:{}", hash.algo()), hash.clone()),
    }
}
