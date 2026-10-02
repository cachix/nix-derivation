//! Validated structured attributes and builder-file materialization.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Write as _};
use std::sync::OnceLock;

use memchr::memchr_iter;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::{Error, StoreDir, StorePath, store_path};

/// Validated structured attributes extracted from a derivation's `__json`
/// transport entry.
///
/// The original JSON bytes are retained for inspection. Parsing validates the
/// complete value without materializing it; the typed value tree is built and
/// recursively sorted on first use.
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
        validate_object(&raw)?;
        Ok(Self {
            raw,
            object: OnceLock::new(),
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
    /// Return the number of top-level attributes.
    pub fn len(&self) -> usize {
        self.object().len()
    }

    #[must_use]
    /// Whether the structured-attribute object has no entries.
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
        self.object.get_or_init(|| parse_object(&self.raw))
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
    /// Filename Nix uses for canonical structured JSON.
    pub const JSON_FILE_NAME: &'static str = ".attrs.json";
    /// Filename Nix uses for shell declarations.
    pub const SHELL_FILE_NAME: &'static str = ".attrs.sh";
}

pub(super) fn files(
    attrs: &StructuredAttrs,
    store_dir: &StoreDir,
    output_paths: &BTreeMap<String, StorePath>,
    reference_graphs: &BTreeMap<String, Value>,
) -> Result<StructuredAttrsFiles, Error> {
    let object = attrs.object();
    let requested = requested_reference_graphs(object);
    if !requested
        .iter()
        .copied()
        .eq(reference_graphs.keys().map(String::as_str))
    {
        if reference_graphs.is_empty() {
            return Err(Error::StructuredAttrs(
                "exportReferencesGraph requires store metadata and cannot be generated here"
                    .to_owned(),
            ));
        }
        return Err(Error::StructuredAttrs(format!(
            "reference graphs were supplied for {:?}, but exportReferencesGraph names {requested:?}",
            reference_graphs.keys().collect::<Vec<_>>()
        )));
    }

    // Nix sets each graph as a top-level attribute, replacing any attribute
    // of the same name.
    let object = if reference_graphs.is_empty() {
        Cow::Borrowed(object)
    } else {
        let mut object = object.clone();
        for (key, graph) in reference_graphs {
            let mut graph = graph.clone();
            sort_value(&mut graph);
            object.insert(key.clone(), graph);
        }
        object.sort_keys();
        Cow::Owned(object)
    };
    let object = object.as_ref();

    if output_paths.is_empty() {
        return Err(Error::StructuredAttrs(
            "structured attributes require at least one concrete output path".to_owned(),
        ));
    }

    let replacements = OutputReplacements::new(store_dir, output_paths);
    let mut json = Vec::new();
    write_attrs_json(object, &replacements, &mut json);
    Ok(StructuredAttrsFiles {
        json,
        shell: write_attrs_shell(object, &replacements).into_bytes(),
    })
}

/// The keys of `exportReferencesGraph`, which Nix ignores with a warning
/// when it is not an object.
fn requested_reference_graphs(object: &Map<String, Value>) -> Vec<&str> {
    match object.get("exportReferencesGraph") {
        Some(Value::Object(graphs)) => graphs.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    }
}

struct OutputReplacement<'a> {
    name: &'a str,
    path: String,
}

struct OutputReplacements<'a> {
    entries: Vec<OutputReplacement<'a>>,
    placeholders: HashMap<String, usize>,
    placeholder_len: usize,
}

impl<'a> OutputReplacements<'a> {
    fn new(store_dir: &StoreDir, output_paths: &'a BTreeMap<String, StorePath>) -> Self {
        let entries: Vec<_> = output_paths
            .iter()
            .map(|(name, path)| OutputReplacement {
                name,
                path: path.to_absolute_path_in(store_dir),
            })
            .collect();
        let mut placeholders = HashMap::with_capacity(entries.len());
        for (index, replacement) in entries.iter().enumerate() {
            placeholders
                .entry(store_path::hash_placeholder(replacement.name))
                .or_insert(index);
        }
        let placeholder_len = placeholders.keys().next().map_or(0, String::len);
        debug_assert!(
            placeholders
                .keys()
                .all(|placeholder| placeholder.len() == placeholder_len)
        );
        Self {
            entries,
            placeholders,
            placeholder_len,
        }
    }

    fn rewrite<'value>(&self, value: &'value str) -> Cow<'value, str> {
        let mut cursor = 0;
        let mut rewritten = None;

        for position in memchr_iter(b'/', value.as_bytes()) {
            if position < cursor {
                continue;
            }
            let end = position + self.placeholder_len;
            let Some(placeholder) = value.get(position..end) else {
                continue;
            };
            let Some(replacement) = self
                .placeholders
                .get(placeholder)
                .map(|index| &self.entries[*index])
            else {
                continue;
            };
            let output = rewritten.get_or_insert_with(|| String::with_capacity(value.len()));
            output.push_str(&value[cursor..position]);
            output.push_str(&replacement.path);
            cursor = end;
        }

        match rewritten {
            Some(mut rewritten) => {
                rewritten.push_str(&value[cursor..]);
                Cow::Owned(rewritten)
            }
            None => Cow::Borrowed(value),
        }
    }
}

fn validate_object(encoded: &[u8]) -> Result<(), Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    ValidateObject
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end())
        .map_err(|error| Error::StructuredAttrs(error.to_string()))
}

struct ValidateObject;

impl<'de> DeserializeSeed<'de> for ValidateObject {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for ValidateObject {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(ValidateValue)?;
        }
        Ok(())
    }
}

struct ValidateValue;

impl<'de> DeserializeSeed<'de> for ValidateValue {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValidateValue {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ValidateValue.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(ValidateValue)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(ValidateValue)?;
        }
        Ok(())
    }
}

fn parse_object(encoded: &[u8]) -> Map<String, Value> {
    match serde_json::from_slice::<Value>(encoded)
        .expect("structured attributes were validated during construction")
    {
        Value::Object(object) => sort_object(object),
        _ => unreachable!("structured attributes were validated as an object"),
    }
}

fn sort_object(mut object: Map<String, Value>) -> Map<String, Value> {
    for value in object.values_mut() {
        sort_value(value);
    }
    object.sort_keys();
    object
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(sort_value),
        Value::Object(object) => {
            for value in object.values_mut() {
                sort_value(value);
            }
            object.sort_keys();
        }
        _ => {}
    }
}

fn canonical_object(object: &Map<String, Value>) -> Vec<u8> {
    let mut output = Vec::new();
    write_json_object(object, None, &mut output);
    output
}

fn write_attrs_json(
    object: &Map<String, Value>,
    replacements: &OutputReplacements<'_>,
    output: &mut Vec<u8>,
) {
    output.push(b'{');
    let mut first = true;
    let mut wrote_outputs = false;

    for (key, value) in object {
        if !wrote_outputs && key.as_str() >= "outputs" {
            write_outputs_json(replacements, &mut first, output);
            wrote_outputs = true;
        }
        if key == "outputs" {
            continue;
        }
        write_json_entry(key, value, Some(replacements), &mut first, output);
    }
    if !wrote_outputs {
        write_outputs_json(replacements, &mut first, output);
    }
    output.push(b'}');
}

fn write_outputs_json(
    replacements: &OutputReplacements<'_>,
    first: &mut bool,
    output: &mut Vec<u8>,
) {
    write_json_separator(first, output);
    write_json_string("outputs", None, output);
    output.extend_from_slice(b":{");
    for (index, replacement) in replacements.entries.iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        write_json_string(replacement.name, None, output);
        output.push(b':');
        write_json_string(&replacement.path, None, output);
    }
    output.push(b'}');
}

fn write_json_entry(
    key: &str,
    value: &Value,
    replacements: Option<&OutputReplacements<'_>>,
    first: &mut bool,
    output: &mut Vec<u8>,
) {
    write_json_separator(first, output);
    write_json_string(key, replacements, output);
    output.push(b':');
    write_json_value(value, replacements, output);
}

fn write_json_separator(first: &mut bool, output: &mut Vec<u8>) {
    if *first {
        *first = false;
    } else {
        output.push(b',');
    }
}

fn write_json_value(
    value: &Value,
    replacements: Option<&OutputReplacements<'_>>,
    output: &mut Vec<u8>,
) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(nix_number(number).as_bytes()),
        Value::String(value) => write_json_string(value, replacements, output),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_json_value(value, replacements, output);
            }
            output.push(b']');
        }
        Value::Object(values) => write_json_object(values, replacements, output),
    }
}

fn write_json_object(
    values: &Map<String, Value>,
    replacements: Option<&OutputReplacements<'_>>,
    output: &mut Vec<u8>,
) {
    // StructuredAttrs recursively sorts every materialized object, so
    // iteration is canonical even if serde_json's preserve_order feature is
    // enabled elsewhere in the dependency graph.
    output.push(b'{');
    let mut first = true;
    for (key, value) in values {
        write_json_entry(key, value, replacements, &mut first, output);
    }
    output.push(b'}');
}

fn write_json_string(
    value: &str,
    replacements: Option<&OutputReplacements<'_>>,
    output: &mut Vec<u8>,
) {
    let value = replacements.map_or_else(|| Cow::Borrowed(value), |items| items.rewrite(value));
    serde_json::to_writer(output, value.as_ref())
        .expect("serializing a parsed JSON string cannot fail");
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

fn write_attrs_shell(object: &Map<String, Value>, replacements: &OutputReplacements<'_>) -> String {
    let mut shell = String::new();
    let mut wrote_outputs = false;

    for (key, value) in object {
        if !wrote_outputs && key.as_str() >= "outputs" {
            write_outputs_shell(replacements, &mut shell);
            wrote_outputs = true;
        }
        if key == "outputs" {
            continue;
        }
        write_shell_entry(key, value, replacements, &mut shell);
    }
    if !wrote_outputs {
        write_outputs_shell(replacements, &mut shell);
    }
    shell
}

fn write_outputs_shell(replacements: &OutputReplacements<'_>, shell: &mut String) {
    shell.push_str("declare -A outputs=(");
    for replacement in &replacements.entries {
        shell.push('[');
        write_shell_quote(replacement.name, None, shell);
        shell.push_str("]=");
        write_shell_quote(&replacement.path, None, shell);
        shell.push(' ');
    }
    shell.push_str(")\n");
}

fn write_shell_entry(
    key: &str,
    value: &Value,
    replacements: &OutputReplacements<'_>,
    shell: &mut String,
) {
    if !is_shell_variable(key) {
        return;
    }
    if is_simple(value) {
        shell.push_str("declare ");
        shell.push_str(key);
        shell.push('=');
        write_simple(value, replacements, shell);
        shell.push('\n');
    } else if let Value::Array(values) = value {
        if !values.iter().all(is_simple) {
            return;
        }
        shell.push_str("declare -a ");
        shell.push_str(key);
        shell.push_str("=(");
        for value in values {
            write_simple(value, replacements, shell);
            shell.push(' ');
        }
        shell.push_str(")\n");
    } else if let Value::Object(values) = value {
        if !values.values().all(is_simple) {
            return;
        }
        shell.push_str("declare -A ");
        shell.push_str(key);
        shell.push_str("=(");
        for (inner_key, value) in values {
            shell.push('[');
            write_shell_quote(inner_key, Some(replacements), shell);
            shell.push_str("]=");
            write_simple(value, replacements, shell);
            shell.push(' ');
        }
        shell.push_str(")\n");
    }
}

fn is_simple(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(number) => integral_number(number).is_some(),
        Value::Array(_) | Value::Object(_) => false,
    }
}

fn write_simple(value: &Value, replacements: &OutputReplacements<'_>, output: &mut String) {
    match value {
        Value::Null => output.push_str("''"),
        Value::Bool(true) => output.push('1'),
        Value::Bool(false) => {}
        Value::String(value) => write_shell_quote(value, Some(replacements), output),
        Value::Number(number) => match integral_number(number)
            .expect("write_simple is called only for simple values")
        {
            IntegralNumber::I64(value) => write!(output, "{value}").expect("writing to a String"),
            IntegralNumber::U64(value) => write!(output, "{value}").expect("writing to a String"),
            IntegralNumber::Float(value) => {
                write!(output, "{value:.0}").expect("writing to a String");
            }
        },
        Value::Array(_) | Value::Object(_) => unreachable!("nested values are not simple"),
    }
}

enum IntegralNumber {
    I64(i64),
    U64(u64),
    Float(f64),
}

fn integral_number(number: &Number) -> Option<IntegralNumber> {
    if let Some(value) = number.as_i64() {
        Some(IntegralNumber::I64(value))
    } else if let Some(value) = number.as_u64() {
        Some(IntegralNumber::U64(value))
    } else {
        let value = number.as_f64()?;
        (value.is_finite() && value.fract() == 0.0).then_some(IntegralNumber::Float(value))
    }
}

fn write_shell_quote(
    value: &str,
    replacements: Option<&OutputReplacements<'_>>,
    output: &mut String,
) {
    let value = replacements.map_or_else(|| Cow::Borrowed(value), |items| items.rewrite(value));
    output.push('\'');
    for character in value.chars() {
        if character == '\'' {
            output.push_str("'\\''");
        } else {
            output.push(character);
        }
    }
    output.push('\'');
}

fn is_shell_variable(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
