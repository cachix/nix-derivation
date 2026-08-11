use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use memchr::{memchr2, memchr3_iter};

use crate::{
    CAHash, ContentAddressMethod, Derivation, HashAlgorithm, NixHash, Output, StorePath, nixbase32,
};
use crate::{DerivationModuloHash, InputDerivation};

pub(super) type HashModuloInputs = BTreeMap<DerivationModuloHash, BTreeSet<String>>;

trait AtermForm {
    fn uses_dynamic_wrapper(&self, derivation: &Derivation) -> bool;
    fn write_output(
        &self,
        _derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
        name: &str,
        output: &Output,
    ) -> io::Result<()>;
    fn write_inputs(
        &self,
        derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
    ) -> io::Result<()>;
    fn environment_value<'a>(
        &self,
        _derivation: &Derivation,
        key: &str,
        value: &'a [u8],
    ) -> &'a [u8];
}

struct FullAterm;
struct InputModuloAterm<'a>(&'a HashModuloInputs);
struct OutputModuloAterm<'a>(&'a HashModuloInputs);

pub(super) fn serialize(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
) -> io::Result<()> {
    serialize_form(derivation, writer, FullAterm)
}

pub(super) fn serialize_input_modulo(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
    inputs: &HashModuloInputs,
) -> io::Result<()> {
    serialize_form(derivation, writer, InputModuloAterm(inputs))
}

pub(super) fn serialize_output_modulo(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
    inputs: &HashModuloInputs,
) -> io::Result<()> {
    serialize_form(derivation, writer, OutputModuloAterm(inputs))
}

fn serialize_form<F: AtermForm>(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
    form: F,
) -> io::Result<()> {
    if form.uses_dynamic_wrapper(derivation) {
        writer.write_all(b"DrvWithVersion(\"xp-dyn-drv\",")?;
    } else {
        writer.write_all(b"Derive(")?;
    }
    write_outputs(derivation, writer, &form)?;
    writer.write_all(b",")?;
    form.write_inputs(derivation, writer)?;
    writer.write_all(b",")?;
    write_store_paths(
        writer,
        &derivation.store_dir,
        derivation.input_sources.iter(),
    )?;
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
    write_environment(derivation, writer, &form)?;
    writer.write_all(b")")
}

fn write_outputs<F: AtermForm>(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
    form: &F,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, (name, output)) in derivation.outputs.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(b"(")?;
        write_unquoted(writer, name.as_bytes())?;
        writer.write_all(b",")?;
        form.write_output(derivation, writer, name, output)?;
        writer.write_all(b")")?;
    }
    writer.write_all(b"]")
}

fn write_full_inputs(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, (path, input)) in derivation.input_derivations.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(b"(")?;
        write_store_path(writer, &derivation.store_dir, path)?;
        writer.write_all(b",")?;
        write_input_derivation(writer, input)?;
        writer.write_all(b")")?;
    }
    writer.write_all(b"]")
}

fn write_modulo_inputs(
    inputs: &HashModuloInputs,
    writer: &mut (impl Write + ?Sized),
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, (hash, outputs)) in inputs.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(b"(")?;
        write_unquoted_hex(writer, hash.as_bytes())?;
        writer.write_all(b",")?;
        write_unquoted_string_list(writer, outputs.iter().map(|value| value.as_bytes()))?;
        writer.write_all(b")")?;
    }
    writer.write_all(b"]")
}

fn write_input_derivation(
    writer: &mut (impl Write + ?Sized),
    input: &InputDerivation,
) -> io::Result<()> {
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
    writer: &mut (impl Write + ?Sized),
    store_dir: &crate::StoreDir,
    paths: impl Iterator<Item = &'a StorePath>,
) -> io::Result<()> {
    writer.write_all(b"[")?;
    for (index, path) in paths.enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        write_store_path(writer, store_dir, path)?;
    }
    writer.write_all(b"]")
}

fn write_environment<F: AtermForm>(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
    form: &F,
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
                    form,
                )?;
            }
            wrote_structured_attrs = true;
        }
        write_environment_entry(derivation, writer, &mut first, key, value, form)?;
    }
    if !wrote_structured_attrs && let Some(attrs) = derivation.structured_attrs.as_ref() {
        write_environment_entry(
            derivation,
            writer,
            &mut first,
            "__json",
            attrs.canonical_json(),
            form,
        )?;
    }
    writer.write_all(b"]")
}

fn write_environment_entry<F: AtermForm>(
    derivation: &Derivation,
    writer: &mut (impl Write + ?Sized),
    first: &mut bool,
    key: &str,
    value: &[u8],
    form: &F,
) -> io::Result<()> {
    if !*first {
        writer.write_all(b",")?;
    }
    *first = false;
    writer.write_all(b"(")?;
    write_escaped(writer, key.as_bytes())?;
    writer.write_all(b",")?;
    write_escaped(writer, form.environment_value(derivation, key, value))?;
    writer.write_all(b")")
}

impl AtermForm for FullAterm {
    fn uses_dynamic_wrapper(&self, derivation: &Derivation) -> bool {
        derivation
            .input_derivations
            .values()
            .any(InputDerivation::is_dynamic)
    }

    fn write_output(
        &self,
        derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
        name: &str,
        output: &Output,
    ) -> io::Result<()> {
        match output {
            Output::InputAddressed { path } => {
                write_store_path(writer, &derivation.store_dir, path)?;
                writer.write_all(b",\"\",\"\"")
            }
            Output::Fixed { ca } => {
                let path = output
                    .path_in(&derivation.store_dir, &derivation.name, name)
                    .expect("validated fixed output path")
                    .expect("fixed outputs have paths");
                write_store_path(writer, &derivation.store_dir, &path)?;
                writer.write_all(b",")?;
                let (method, hash) = fixed_parts(ca);
                write_unquoted(writer, method.as_bytes())?;
                writer.write_all(b",")?;
                write_unquoted_hex(writer, hash.digest_as_bytes())
            }
            Output::Floating {
                method,
                hash_algorithm,
            } => {
                write_unquoted(writer, b"")?;
                writer.write_all(b",")?;
                write_method_algorithm(writer, *method, *hash_algorithm)?;
                writer.write_all(b",\"\"")
            }
            Output::Deferred => writer.write_all(b"\"\",\"\",\"\""),
            Output::Impure {
                method,
                hash_algorithm,
            } => {
                write_unquoted(writer, b"")?;
                writer.write_all(b",")?;
                write_method_algorithm(writer, *method, *hash_algorithm)?;
                writer.write_all(b",\"impure\"")
            }
        }
    }

    fn write_inputs(
        &self,
        derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
    ) -> io::Result<()> {
        write_full_inputs(derivation, writer)
    }

    fn environment_value<'a>(
        &self,
        _derivation: &Derivation,
        _key: &str,
        value: &'a [u8],
    ) -> &'a [u8] {
        value
    }
}

impl AtermForm for InputModuloAterm<'_> {
    fn uses_dynamic_wrapper(&self, _derivation: &Derivation) -> bool {
        false
    }

    fn write_output(
        &self,
        derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
        _name: &str,
        output: &Output,
    ) -> io::Result<()> {
        let Output::InputAddressed { path } = output else {
            unreachable!("input modulo accepts only input-addressed outputs")
        };
        write_store_path(writer, &derivation.store_dir, path)?;
        writer.write_all(b",\"\",\"\"")
    }

    fn write_inputs(
        &self,
        _derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
    ) -> io::Result<()> {
        write_modulo_inputs(self.0, writer)
    }

    fn environment_value<'a>(
        &self,
        _derivation: &Derivation,
        _key: &str,
        value: &'a [u8],
    ) -> &'a [u8] {
        value
    }
}

impl AtermForm for OutputModuloAterm<'_> {
    fn uses_dynamic_wrapper(&self, _derivation: &Derivation) -> bool {
        false
    }

    fn write_output(
        &self,
        _derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
        _name: &str,
        _output: &Output,
    ) -> io::Result<()> {
        writer.write_all(b"\"\",\"\",\"\"")
    }

    fn write_inputs(
        &self,
        _derivation: &Derivation,
        writer: &mut (impl Write + ?Sized),
    ) -> io::Result<()> {
        write_modulo_inputs(self.0, writer)
    }

    fn environment_value<'a>(
        &self,
        derivation: &Derivation,
        key: &str,
        value: &'a [u8],
    ) -> &'a [u8] {
        if derivation.outputs.contains_key(key) {
            b""
        } else {
            value
        }
    }
}

fn write_string_list<'a>(
    writer: &mut (impl Write + ?Sized),
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
    writer: &mut (impl Write + ?Sized),
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

fn write_escaped(writer: &mut (impl Write + ?Sized), value: &[u8]) -> io::Result<()> {
    writer.write_all(b"\"")?;
    write_escaped_fragment(writer, value)?;
    writer.write_all(b"\"")
}

fn write_escaped_fragment(writer: &mut (impl Write + ?Sized), value: &[u8]) -> io::Result<()> {
    if memchr2(b'\r', b'\t', value).is_none() {
        let mut start = 0;
        for index in memchr3_iter(b'"', b'\\', b'\n', value) {
            writer.write_all(&value[start..index])?;
            writer.write_all(match value[index] {
                b'"' => b"\\\"",
                b'\\' => b"\\\\",
                b'\n' => b"\\n",
                _ => unreachable!("memchr3 returned a different byte"),
            })?;
            start = index + 1;
        }
        return writer.write_all(&value[start..]);
    }

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
    writer.write_all(&value[start..])
}

fn write_store_path(
    writer: &mut (impl Write + ?Sized),
    store_dir: &crate::StoreDir,
    path: &StorePath,
) -> io::Result<()> {
    writer.write_all(b"\"")?;
    write_escaped_fragment(writer, store_dir.as_str().as_bytes())?;
    if store_dir.as_str() != "/" {
        writer.write_all(b"/")?;
    }
    writer.write_all(&nixbase32::encode_fixed::<32>(path.digest()))?;
    writer.write_all(b"-")?;
    writer.write_all(path.name().as_bytes())?;
    writer.write_all(b"\"")
}

fn write_unquoted(writer: &mut (impl Write + ?Sized), value: &[u8]) -> io::Result<()> {
    writer.write_all(b"\"")?;
    writer.write_all(value)?;
    writer.write_all(b"\"")
}

fn write_unquoted_hex(writer: &mut (impl Write + ?Sized), value: &[u8]) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    writer.write_all(b"\"")?;
    for byte in value {
        writer.write_all(&[HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]])?;
    }
    writer.write_all(b"\"")
}

fn write_method_algorithm(
    writer: &mut (impl Write + ?Sized),
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
        CAHash::Flat(hash) => (hash.algorithm().to_string(), hash.clone()),
        CAHash::Nar(hash) => (format!("r:{}", hash.algorithm()), hash.clone()),
        CAHash::Text(digest) => ("text:sha256".to_owned(), NixHash::Sha256(*digest)),
        CAHash::Git(hash) => (format!("git:{}", hash.algorithm()), hash.clone()),
    }
}
