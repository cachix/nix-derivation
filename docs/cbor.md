# Derivation CBOR version 1

This crate defines a lossless CBOR interchange format for its `Derivation`
model. It is not a Nix wire or store format. Nix compatibility, derivation store
paths, and output-path hashing continue to use the existing ATerm algorithms.
The CBOR version number is independent of the Nix JSON version number.

## API

```rust
use nix_derivation::{Derivation, DerivationBuilder};

let drv = DerivationBuilder::new("binary", "x86_64-linux", "/bin/sh")
    .input_addressed_output("out")
    .environment("payload", vec![0x00, 0xff, 0x80])
    .build()?
    .into_derivation();

let bytes = drv.to_cbor_bytes()?;
let decoded = Derivation::from_cbor_bytes(&bytes)?;
assert_eq!(decoded, drv);
assert_eq!(decoded.to_aterm_bytes(), drv.to_aterm_bytes());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The `cbor` module exposes `from_slice`, `from_slice_in`, `to_vec`, and `write`.
`Derivation` also exposes `from_cbor_bytes_in` and `write_cbor`. The streaming
writer does not allocate a complete encoded document; it buffers map entries
for ordering. The custom-store readers take a `StoreDir`, just like JSON.

## Schema

The structure follows Nix derivation JSON v4, with three differences: the
version is `1`, environment values are byte strings, and `structuredAttrs` is
a byte string containing canonical JSON. In CDDL notation:

```cddl
derivation = {
  "version": 1,
  "name": tstr,
  "system": tstr,
  "builder": tstr,
  "args": [* tstr],
  "env": {* tstr => bstr},
  "outputs": {* tstr => output},
  "inputs": {
    "srcs": [* store-path],
    "drvs": {* store-path => input}
  },
  ? "structuredAttrs": bstr
}

input = {
  "outputs": [* tstr],
  "dynamicOutputs": {* tstr => input}
}

output = {"path": store-path}
       / {"method": method, "hash": tstr}
       / {"method": method, "hashAlgo": hash-algorithm}
       / {}
       / {"impure": true, "method": method, "hashAlgo": hash-algorithm}

method = "flat" / "nar" / "text" / "git"
hash-algorithm = "md5" / "sha1" / "sha256" / "sha512" / "blake3"
store-path = tstr
```

`store-path` contains a Nix store basename, including its 32-character Nix
base32 hash, hyphen, and store name. Absolute paths are rejected. The logical
store directory is supplied out of band; readers default to `/nix/store`.
The fixed-output `hash` is a Nix SRI hash string. Existing content-address
validation applies, including restrictions on method/algorithm combinations.

Every environment value is a CBOR byte string, including empty values and
values containing valid UTF-8. Text strings and arrays of integers are not
accepted as substitutes. Other textual fields retain the crate's existing
UTF-8 requirements. Unicode is never normalized.

When present, `structuredAttrs` contains a UTF-8 JSON object accepted by
`StructuredAttrs`. Writers use `StructuredAttrs::canonical_json()`. This keeps
Nix's handling of integers, floating-point formatting, negative zero, and
strings, without introducing CBOR numeric conversion rules. Readers accept
noncanonical JSON and normalize it on writing. Original JSON whitespace and
escape spelling are not preserved by the round trip; the derivation's
canonical ATerm representation and hashes are preserved. Absent structured
attributes are represented by omission, never `null` or an empty byte string.

## Deterministic encoding

Writers follow the core deterministic encoding requirements of
[RFC 8949 section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1):

- Integers and lengths use their shortest representation.
- All strings, arrays, and maps have definite lengths.
- Map keys are ordered lexicographically by their encoded CBOR bytes.
  All keys here are text strings, so this is equivalent to ordering by UTF-8
  byte length, then by UTF-8 bytes. For example, `"z"` precedes `"aa"`.
- No CBOR tags, floating-point values, or indefinite-length items are emitted.

Additionally, set-valued arrays (`inputs.srcs` and each input's `outputs`) are
sorted lexicographically by their UTF-8 bytes. The `args` array preserves
argument order. All required fields are emitted, including empty containers.

These are RFC 8949 core rules with this schema's application rules, not the
dCBOR or DAG-CBOR profiles. Derivation CBOR bytes are not substituted into
Nix's existing identity calculations.

## Parsing and evolution

Readers consume exactly one complete derivation. They accept unordered maps,
unordered set arrays, and non-minimal integer/length encodings, then normalize
them on writing. They reject duplicate map keys, duplicate set entries,
unknown or missing fields, wrong field types, unsupported versions, trailing
bytes, indefinite lengths, and tags. Dynamic inputs permit at most
`MAX_DYNAMIC_INPUT_DEPTH` (256) edges below each root input. Declared container
lengths are checked against the remaining input before reading entries.

Parsing does not establish build validity; call `Derivation::validate` or
convert to `ValidatedDerivation` as appropriate. CBOR syntax and I/O errors
use `Error::Cbor`; unsupported versions use `Error::UnsupportedCborVersion`.
Existing store-path, hash, and structured-attribute errors retain their types.

Incompatible schema changes, including adding fields rejected by version 1
readers, require a new version. The specification and hand-encoded test
fixture define the format independently of Rust struct layout or codec crate.
