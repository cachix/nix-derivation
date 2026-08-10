use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::{Map, Number, Value};

use crate::{Error, StorePath, store_path};

/// Validated structured attributes extracted from a derivation's `__json`
/// transport entry.
///
/// The original JSON bytes are retained for inspection. The typed value tree
/// is built during validation so every infallible accessor consumes the same
/// representation that was already accepted.
#[derive(Debug)]
pub struct StructuredAttrs {
    raw: Vec<u8>,
    object: OnceLock<Map<String, Value>>,
    canonical: OnceLock<Vec<u8>>,
}

impl StructuredAttrs {
    /// Validate and retain a structured-attribute JSON object.
    pub fn from_json_bytes(json: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Self::parse(json.into())
    }

    pub(super) fn parse(raw: Vec<u8>) -> Result<Self, Error> {
        let object = parse_object(&raw)?;
        Ok(Self {
            raw,
            object: OnceLock::from(object),
            canonical: OnceLock::new(),
        })
    }

    /// JSON bytes exactly as they appeared in the parsed derivation.
    #[must_use]
    pub fn raw_json(&self) -> &[u8] {
        &self.raw
    }

    /// Look up a top-level structured attribute without reparsing the JSON on
    /// subsequent calls.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.object().get(key)
    }

    /// Iterate over top-level attributes in canonical key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.object()
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.object().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.object().is_empty()
    }

    /// Canonical compact JSON with recursively sorted object keys.
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        self.canonical
            .get_or_init(|| canonical_object(self.object()))
    }

    fn object(&self) -> &Map<String, Value> {
        self.object
            .get()
            .expect("structured attributes are parsed during construction")
    }
}

impl Clone for StructuredAttrs {
    fn clone(&self) -> Self {
        let cloned = Self {
            raw: self.raw.clone(),
            object: OnceLock::new(),
            canonical: OnceLock::new(),
        };
        if let Some(object) = self.object.get() {
            cloned
                .object
                .set(object.clone())
                .expect("new OnceLock is empty");
        }
        if let Some(canonical) = self.canonical.get() {
            cloned
                .canonical
                .set(canonical.clone())
                .expect("new OnceLock is empty");
        }
        cloned
    }
}

impl PartialEq for StructuredAttrs {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_json() == other.canonical_json()
    }
}

impl Eq for StructuredAttrs {}

/// Files Nix exposes to builders for a structured-attribute derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredAttrsFiles {
    /// Contents of `.attrs.json`.
    pub json: Vec<u8>,
    /// Contents of `.attrs.sh`.
    pub shell: Vec<u8>,
}

impl StructuredAttrsFiles {
    pub const JSON_FILE_NAME: &'static str = ".attrs.json";
    pub const SHELL_FILE_NAME: &'static str = ".attrs.sh";
}

pub(super) fn files(
    attrs: &StructuredAttrs,
    output_paths: &BTreeMap<String, StorePath>,
) -> Result<StructuredAttrsFiles, Error> {
    let mut object = attrs.object().clone();
    if object.contains_key("exportReferencesGraph") {
        return Err(Error::StructuredAttrs(
            "exportReferencesGraph requires store metadata and cannot be generated here".to_owned(),
        ));
    }

    if output_paths.is_empty() {
        return Err(Error::StructuredAttrs(
            "structured attributes require at least one concrete output path".to_owned(),
        ));
    }
    let outputs: Map<String, Value> = output_paths
        .keys()
        .map(|name| {
            (
                name.clone(),
                Value::String(store_path::hash_placeholder(name)),
            )
        })
        .collect();
    object.insert("outputs".to_owned(), Value::Object(outputs));
    object = sort_object(object);

    let json = String::from_utf8(canonical_object(&object))
        .expect("canonical JSON made from strings is valid UTF-8");
    let shell = write_shell(&object);
    let rewrite = |mut value: String| {
        for (name, path) in output_paths {
            value = value.replace(
                &store_path::hash_placeholder(name),
                &path.to_absolute_path(),
            );
        }
        value.into_bytes()
    };
    Ok(StructuredAttrsFiles {
        json: rewrite(json),
        shell: rewrite(shell),
    })
}

fn parse_object(encoded: &[u8]) -> Result<Map<String, Value>, Error> {
    match serde_json::from_slice::<Value>(encoded) {
        Ok(Value::Object(object)) => Ok(sort_object(object)),
        Ok(_) => Err(Error::StructuredAttrs(
            "the __json value is not an object".to_owned(),
        )),
        Err(error) => Err(Error::StructuredAttrs(error.to_string())),
    }
}

fn sort_object(object: Map<String, Value>) -> Map<String, Value> {
    let sorted: BTreeMap<String, Value> = object
        .into_iter()
        .map(|(key, value)| (key, sort_value(value)))
        .collect();
    let mut object = Map::new();
    object.extend(sorted);
    object
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        Value::Object(object) => Value::Object(sort_object(object)),
        scalar => scalar,
    }
}

fn canonical_object(object: &Map<String, Value>) -> Vec<u8> {
    let mut output = Vec::new();
    write_json_value(&Value::Object(object.clone()), &mut output);
    output
}

fn write_json_value(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(nix_number(number).as_bytes()),
        Value::String(value) => {
            serde_json::to_writer(output, value)
                .expect("serializing a parsed JSON string cannot fail");
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_json_value(value, output);
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let sorted: BTreeMap<&str, &Value> = values
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .expect("serializing a parsed JSON key cannot fail");
                output.push(b':');
                write_json_value(value, output);
            }
            output.push(b'}');
        }
    }
}

fn nix_number(number: &Number) -> String {
    if number.is_i64() || number.is_u64() {
        return number.to_string();
    }

    // serde_json and Nix both select the shortest round-tripping decimal
    // digits for an f64, but nlohmann/json applies printf-like presentation:
    // fixed notation in [1e-4, 1e15), otherwise a signed, two-digit exponent.
    let encoded = number.to_string();
    let (sign, unsigned) = encoded
        .strip_prefix('-')
        .map_or(("", encoded.as_str()), |value| ("-", value));
    if unsigned == "0.0" {
        return encoded;
    }

    let (mantissa, explicit_exponent) =
        unsigned
            .split_once(['e', 'E'])
            .map_or((unsigned, 0), |(mantissa, exponent)| {
                (
                    mantissa,
                    exponent
                        .parse::<i32>()
                        .expect("serde_json emits a valid decimal exponent"),
                )
            });
    let fractional_digits = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len()) as i32;
    let mut digits = mantissa.replace('.', "");
    let first_nonzero = digits
        .bytes()
        .position(|byte| byte != b'0')
        .expect("nonzero JSON float has a nonzero digit");
    digits.drain(..first_nonzero);
    let mut decimal_exponent = explicit_exponent - fractional_digits;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
        decimal_exponent += 1;
    }

    let digit_count = i32::try_from(digits.len()).expect("f64 has at most 17 decimal digits");
    let decimal_point = digit_count + decimal_exponent;
    let mut formatted = String::with_capacity(encoded.len() + 4);
    formatted.push_str(sign);

    if digit_count <= decimal_point && decimal_point <= 15 {
        formatted.push_str(&digits);
        formatted.extend(std::iter::repeat_n(
            '0',
            usize::try_from(decimal_point - digit_count).expect("nonnegative zero count"),
        ));
        formatted.push_str(".0");
    } else if 0 < decimal_point && decimal_point <= 15 {
        let split = usize::try_from(decimal_point).expect("positive decimal point");
        formatted.push_str(&digits[..split]);
        formatted.push('.');
        formatted.push_str(&digits[split..]);
    } else if -4 < decimal_point && decimal_point <= 0 {
        formatted.push_str("0.");
        formatted.extend(std::iter::repeat_n(
            '0',
            usize::try_from(-decimal_point).expect("nonnegative zero count"),
        ));
        formatted.push_str(&digits);
    } else {
        formatted.push(digits.as_bytes()[0] as char);
        if digits.len() > 1 {
            formatted.push('.');
            formatted.push_str(&digits[1..]);
        }
        let exponent = decimal_point - 1;
        formatted.push('e');
        formatted.push(if exponent < 0 { '-' } else { '+' });
        let magnitude = exponent.unsigned_abs();
        if magnitude < 10 {
            formatted.push('0');
        }
        formatted.push_str(&magnitude.to_string());
    }
    formatted
}

fn write_shell(object: &Map<String, Value>) -> String {
    // Sort explicitly so this remains stable even if a downstream dependency
    // enables serde_json's `preserve_order` feature.
    let sorted: BTreeMap<&str, &Value> = object
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    let mut shell = String::new();
    for (key, value) in sorted {
        if !is_shell_variable(key) {
            continue;
        }
        if let Some(value) = simple(value) {
            shell.push_str("declare ");
            shell.push_str(key);
            shell.push('=');
            shell.push_str(&value);
            shell.push('\n');
        } else if let Value::Array(values) = value {
            let Some(values) = values.iter().map(simple).collect::<Option<Vec<_>>>() else {
                continue;
            };
            shell.push_str("declare -a ");
            shell.push_str(key);
            shell.push_str("=(");
            for value in values {
                shell.push_str(&value);
                shell.push(' ');
            }
            shell.push_str(")\n");
        } else if let Value::Object(values) = value {
            let sorted: BTreeMap<&str, &Value> = values
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            let Some(values) = sorted
                .into_iter()
                .map(|(key, value)| simple(value).map(|value| (key, value)))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            shell.push_str("declare -A ");
            shell.push_str(key);
            shell.push_str("=(");
            for (inner_key, value) in values {
                shell.push('[');
                shell.push_str(&shell_quote(inner_key));
                shell.push_str("]=");
                shell.push_str(&value);
                shell.push(' ');
            }
            shell.push_str(")\n");
        }
    }
    shell
}

fn simple(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("''".to_owned()),
        Value::Bool(true) => Some("1".to_owned()),
        Value::Bool(false) => Some(String::new()),
        Value::String(value) => Some(shell_quote(value)),
        Value::Number(number) => integral_number(number),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn integral_number(number: &Number) -> Option<String> {
    if let Some(value) = number.as_i64() {
        Some(value.to_string())
    } else if let Some(value) = number.as_u64() {
        Some(value.to_string())
    } else {
        let value = number.as_f64()?;
        (value.is_finite() && value.fract() == 0.0).then(|| format!("{value:.0}"))
    }
}

fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

fn is_shell_variable(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
