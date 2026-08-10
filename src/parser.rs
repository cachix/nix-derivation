use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use memchr::{memchr, memchr2};

use crate::{
    CAHash, ContentAddressMethod, Derivation, Error, HashAlgorithm, InputDerivation, Output,
    StorePath,
};

pub(super) fn parse(bytes: &[u8], name: &str) -> Result<Derivation, Error> {
    let mut parser = Parser { bytes, pos: 0 };
    let version = if parser.consume(b"DrvWithVersion(") {
        let version = parser.string("derivation ATerm version")?;
        if version != "xp-dyn-drv" {
            return parser.fail(format!("unknown derivation ATerm version {version:?}"));
        }
        parser.expect(b",")?;
        Version::Dynamic
    } else {
        parser.expect(b"Derive(")?;
        Version::Traditional
    };

    // Nix uses std::map::emplace here: the first duplicate output wins.
    let mut outputs = BTreeMap::new();
    for (output_name, output) in parser.list(|p| p.output())? {
        outputs.entry(output_name).or_insert(output);
    }
    parser.expect(b",")?;
    let input_derivations = parser.map(|p| {
        let path = p.store_path("input derivation path")?;
        p.expect(b",")?;
        let input = p.input_derivation(version, 0)?;
        Ok((path, input))
    })?;
    parser.expect(b",")?;
    let input_sources = parser.store_path_set()?;
    parser.expect(b",")?;
    let system = parser.string("system")?;
    parser.expect(b",")?;
    let builder = parser.string("builder")?;
    parser.expect(b",")?;
    let arguments = parser.string_vec("argument")?;
    parser.expect(b",")?;
    let mut environment = parser.map(|p| {
        let key = p.string("environment key")?;
        p.expect(b",")?;
        let value = p.bytes()?;
        Ok((key, value))
    })?;
    parser.expect(b")")?;
    if parser.pos != bytes.len() {
        return parser.fail("trailing bytes after derivation");
    }
    // Nix extracts this transport entry into its structured-attributes field.
    // Validate it now, but defer building and sorting the JSON tree until a
    // caller actually serializes or materializes the structured attributes.
    let structured_attrs = environment
        .remove("__json")
        .map(crate::structured_attrs::StructuredAttrs::parse)
        .transpose()?;

    let derivation = Derivation {
        name: name.to_owned(),
        outputs,
        input_derivations,
        input_sources,
        system,
        builder,
        arguments,
        environment,
        structured_attrs,
        aterm_size_hint: bytes.len(),
    };
    // Fixed-output serialization derives the path from these out-of-band
    // names. Validate it once so later canonical serialization is infallible.
    for (output_name, output) in &derivation.outputs {
        if matches!(output, Output::Fixed { .. }) {
            output.path(name, output_name)?;
        }
    }
    Ok(derivation)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    Traditional,
    Dynamic,
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn fail<T>(&self, message: impl Into<String>) -> Result<T, Error> {
        Err(Error::Parse {
            offset: self.pos,
            message: message.into(),
        })
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), Error> {
        if self.consume(expected) {
            Ok(())
        } else {
            self.fail(format!("expected {:?}", String::from_utf8_lossy(expected)))
        }
    }

    fn consume(&mut self, expected: &[u8]) -> bool {
        if self.bytes[self.pos..].starts_with(expected) {
            self.pos += expected.len();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.bytes_cow()?.into_owned())
    }

    fn bytes_cow(&mut self) -> Result<Cow<'_, [u8]>, Error> {
        self.expect(b"\"")?;
        let start = self.pos;
        let mut cursor = self.pos;
        let mut escaped = false;
        loop {
            let Some(relative) = memchr2(b'"', b'\\', &self.bytes[cursor..]) else {
                return self.fail("unterminated string");
            };
            cursor += relative;
            if self.bytes[cursor] == b'"' {
                let content = &self.bytes[start..cursor];
                self.pos = cursor + 1;
                if !escaped {
                    return Ok(Cow::Borrowed(content));
                }
                let mut decoded = Vec::with_capacity(content.len());
                let mut index = 0;
                while let Some(relative) = memchr(b'\\', &content[index..]) {
                    let escape = index + relative;
                    decoded.extend_from_slice(&content[index..escape]);
                    let Some(&value) = content.get(escape + 1) else {
                        return self.fail("unterminated escape in string");
                    };
                    decoded.push(match value {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        // Nix accepts every other escaped byte as itself,
                        // including quote and backslash.
                        other => other,
                    });
                    index = escape + 2;
                }
                decoded.extend_from_slice(&content[index..]);
                return Ok(Cow::Owned(decoded));
            }
            escaped = true;
            cursor += 2;
            if cursor > self.bytes.len() {
                return self.fail("unterminated escape in string");
            }
        }
    }

    fn string(&mut self, field: &'static str) -> Result<String, Error> {
        match self.bytes_cow()? {
            Cow::Borrowed(bytes) => std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| Error::InvalidUtf8 { field }),
            Cow::Owned(bytes) => String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8 { field }),
        }
    }

    fn list<T>(
        &mut self,
        mut element: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        self.expect(b"[")?;
        let mut values = Vec::new();
        if self.consume(b"]") {
            return Ok(values);
        }
        loop {
            values.push(element(self)?);
            if self.consume(b"]") {
                return Ok(values);
            }
            self.expect(b",")?;
        }
    }

    fn map<K: Ord, V>(
        &mut self,
        mut entry: impl FnMut(&mut Self) -> Result<(K, V), Error>,
    ) -> Result<BTreeMap<K, V>, Error> {
        let entries = self.list(|p| {
            p.expect(b"(")?;
            let entry = entry(p)?;
            p.expect(b")")?;
            Ok(entry)
        })?;
        // Nix uses insert-or-assign for input derivations and environment
        // entries. Canonical ATerms never contain duplicates, but matching the
        // parser makes non-canonical inputs deterministic.
        Ok(entries.into_iter().collect())
    }

    fn string_vec(&mut self, field: &'static str) -> Result<Vec<String>, Error> {
        self.list(|p| p.string(field))
    }

    fn string_set(&mut self, field: &'static str) -> Result<BTreeSet<String>, Error> {
        Ok(self.string_vec(field)?.into_iter().collect())
    }

    fn store_path(&mut self, field: &'static str) -> Result<StorePath, Error> {
        let bytes = self.bytes_cow()?;
        StorePath::from_absolute_path(&bytes).map_err(|error| Error::Parse {
            offset: self.pos,
            message: format!("invalid {field}: {error}"),
        })
    }

    fn store_path_set(&mut self) -> Result<BTreeSet<StorePath>, Error> {
        Ok(self
            .list(|p| p.store_path("input source path"))?
            .into_iter()
            .collect())
    }

    fn input_derivation(
        &mut self,
        version: Version,
        depth: usize,
    ) -> Result<InputDerivation, Error> {
        if depth > crate::MAX_DYNAMIC_INPUT_DEPTH {
            return self.fail("dynamic input derivation nesting exceeds 256 levels");
        }
        if version == Version::Traditional || self.peek() == Some(b'[') {
            return Ok(InputDerivation {
                outputs: self.string_set("input derivation output name")?,
                dynamic_outputs: BTreeMap::new(),
            });
        }
        if self.peek() != Some(b'(') {
            return self.fail("invalid dynamic input derivation node");
        }
        self.expect(b"(")?;
        let outputs = self.string_set("input derivation output name")?;
        self.expect(b",")?;
        let dynamic_outputs = self.map(|p| {
            let name = p.string("dynamic derivation output name")?;
            p.expect(b",")?;
            let child = p.input_derivation(Version::Dynamic, depth + 1)?;
            Ok((name, child))
        })?;
        self.expect(b")")?;
        Ok(InputDerivation {
            outputs,
            dynamic_outputs,
        })
    }

    fn output(&mut self) -> Result<(String, Output), Error> {
        self.expect(b"(")?;
        let output_name = self.string("output name")?;
        self.expect(b",")?;
        let path = self.bytes()?;
        self.expect(b",")?;
        let method_algo = self.bytes()?;
        self.expect(b",")?;
        let hash = self.bytes()?;
        self.expect(b")")?;

        let output = if method_algo.is_empty() {
            if path.is_empty() {
                Output::Deferred
            } else {
                Output::InputAddressed {
                    path: StorePath::from_absolute_path(&path)?,
                }
            }
        } else {
            let (method, algorithm_bytes) = ContentAddressMethod::parse_prefix(&method_algo);
            let hash_algorithm =
                HashAlgorithm::parse(algorithm_bytes).map_err(|error| match error {
                    Error::Parse { message, .. } => Error::Parse {
                        offset: self.pos,
                        message,
                    },
                    other => other,
                })?;
            if hash == b"impure" {
                if !path.is_empty() {
                    return self.fail("impure output must not specify a path");
                }
                Output::Impure {
                    method,
                    hash_algorithm,
                }
            } else if hash.is_empty() {
                if !path.is_empty() {
                    return self.fail("floating content-addressed output must not specify a path");
                }
                Output::Floating {
                    method,
                    hash_algorithm,
                }
            } else {
                // Nix validates but does not retain the serialized fixed path;
                // canonical serialization recomputes it from the content
                // address and the out-of-band derivation name.
                StorePath::from_absolute_path(&path)?;
                let ca = fixed_content_address(method, hash_algorithm, &hash)?;
                Output::Fixed { ca }
            }
        };
        Ok((output_name, output))
    }
}

fn fixed_content_address(
    method: ContentAddressMethod,
    algorithm: HashAlgorithm,
    encoded: &[u8],
) -> Result<CAHash, Error> {
    let encoded = std::str::from_utf8(encoded).map_err(|_| Error::Parse {
        offset: 0,
        message: "fixed output digest is not ASCII base16".to_owned(),
    })?;
    let digest = decode_hex(encoded).ok_or_else(|| Error::Parse {
        offset: 0,
        message: "fixed output digest is not valid base16".to_owned(),
    })?;
    Ok(CAHash::from_parts(
        match method {
            ContentAddressMethod::Flat => "flat",
            ContentAddressMethod::Nar => "nar",
            ContentAddressMethod::Text => "text",
            ContentAddressMethod::Git => "git",
        },
        algorithm.as_str(),
        &digest,
    )?)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?))
        .collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
