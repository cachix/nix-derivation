# nix-derivation

`nix-derivation` parses, validates, hashes, and serializes Nix derivations and
constructs their store paths in pure, safe Rust. It requires no Nix installation
or C++ runtime, and all its dependencies are published Rust crates.

## What it implements

| Area | Supported features |
| --- | --- |
| Derivation syntax | Traditional `Derive(...)` ATerms and versioned `DrvWithVersion("xp-dyn-drv",...)` ATerms used for recursive dynamic derivations. |
| Parsing | Reads derivations as bytes, requires all input to be consumed, validates UTF-8 in text fields, and handles each field's Nix escaping rules. Environment values may contain arbitrary bytes. Duplicate map and set entries behave like they do in Nix. |
| Serialization | Writes fields in Nix's canonical order, sorts maps and sets, applies Nix escaping, uses traditional syntax when no versioned node is needed, and can stream output through `std::io::Write`. |
| Outputs | Input-addressed, fixed content-addressed, floating content-addressed, deferred, and impure outputs. Multi-output derivations and output placeholders are supported. |
| Content addresses | Supports the flat, NAR, text, and Git ways of hashing content. MD5, SHA-1, SHA-256, and SHA-512 values have their lengths checked by Rust's type system; Nix's restrictions on text and Git algorithms are also checked. |
| Inputs | Input sources, requested outputs from input derivations, and nested trees of dynamic outputs. Trees can be constructed, traversed without recursion with `walk()`, and measured with `max_depth()`. Parsing and construction enforce a depth limit of 256. |
| Derived paths | Typed `DrvOutput` identities plus `SingleDerivedPath` and `DerivedPath` expressions, including dynamic-output chains, store-aware parsing, canonical text and Nix-compatible JSON rendering, and legacy `!` separators. |
| Structured attributes | Reads `__json` as a JSON object supported by Nix while preserving its original bytes. Provides type-checked lookup and iteration, produces Nix-compatible canonical JSON (including float formatting), and generates `.attrs.json` and `.attrs.sh` files with concrete output paths for the builder. |
| Derivation hashing | Type-directed derivation-modulo hashing: `hash_input_derivation_modulo` returns an `InputDerivationHash`, while `hash_output_path_modulo` returns an explicit ready-or-deferred `OutputPathHash`. SHA-256 values use the distinct `DerivationModuloHash` type. The intermediate representation resolves input derivation paths to hashes and cannot contain unresolved dynamic inputs. |
| Store paths | Parsing, validation, and rendering with configurable logical store directories; Nix base32; text, content-addressed, derivation-output, and `.drv` path construction; `builtins.placeholder` values; and Nix 2.35 downstream dynamic-output placeholders. |
| Rust construction | `DerivationBuilder` for type-checked construction and edits, plus `ValidatedDerivation`, an owned derivation whose build rules have already been checked. |
| Safety | `#![forbid(unsafe_code)]`, a fixed maximum nesting depth, structured error types, and parser tests that verify malformed, truncated, and size-limited arbitrary input never causes a panic. |

Here, canonical means that a value always serializes to one standard sequence
of bytes.

Parsing and validation are deliberately separate. `Derivation` can inspect and
serialize syntactically valid test cases even when they are not valid build
recipes. Serialization always uses Nix's canonical format.
`Derivation::validate`,
`Derivation::into_validated`, and `DerivationBuilder::build` enforce rules such
as a nonempty output set, consistent output types, the single `out` rule for
fixed-output derivations, valid derivation/output names, `.drv` input paths,
nonempty system and builder fields, valid dynamic-input depth, and exact
agreement between output paths and their environment entries. Input-addressed
derivations with input derivations use the corresponding `*_with_input_hashes`
APIs because Nix needs the inputs' derivation-modulo hashes to calculate those
paths.

Structured attributes are kept outside the ordinary environment map in a
dedicated `StructuredAttrs` value. The complete `serde_json::Value` tree is
validated during ATerm parsing, so later type-checked access cannot fail.
Canonical JSON bytes are generated only when first requested.

## Deliberate boundaries

This crate does not evaluate Nix expressions, execute builders, implement a
Nix store or database, serialize filesystem trees to NAR, or read filesystem
contents to calculate a declared content digest. It accepts already-computed
digests and implements the Nix metadata, hashing, and store-path algorithms
that use them.

Generating an `exportReferencesGraph` structured attribute requires store
metadata, so it is left to code that connects this crate to a store. Generating
the structured files without store access returns an error for this attribute.

## Compatibility and tests

The stable ATerm implementation follows Nix 2.34 source code and is checked
against test data generated by Nix 2.34. Nix 2.35 downstream dynamic-output
placeholder construction is covered by known-answer vectors. The type-directed
modulo model follows
Nix's merged [intermediate-derivation refactor][nix-modulo-refactor]. Tests
cover every supported ATerm output variant,
recursive dynamic inputs through the 256-level limit, structured JSON, exact
escaping and duplicate-entry behavior, malformed and truncated inputs,
size-limited pseudo-random inputs, and known expected hashes, nixbase32
encodings, placeholders, and store paths. After
parsing and serializing, every Nix-generated test case must reproduce its
original canonical bytes and match Nix's validation, path, and hash results.

## Rust API

`Derivation` owns all parsed data and can hold syntactically valid values that
are not buildable. Its writer produces canonical Nix bytes rather than
preserving the original field order. `ValidatedDerivation` owns a derivation
that has passed validation. Construct one with `DerivationBuilder`, validate a
parsed value with `into_validated()`, or parse and validate in one step with
`ValidatedDerivation::from_aterm_bytes()`.

```rust
use nix_derivation::DerivationBuilder;

let drv = DerivationBuilder::new("example", "x86_64-linux", "/bin/sh")
    .input_addressed_output("out")
    .argument("-c")
    .argument("printf built > $out")
    .build()?;

// These methods cannot return validation errors after a successful build.
let outputs = drv.resolved_outputs();
let drv_path = drv.drv_path();

// Convert back to a builder to edit, then validate again with build().
let mut edit = drv.into_builder();
edit.arguments_mut().push("--verbose".to_owned());
let drv = edit.build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The builder recalculates input-addressed paths and their environment entries
using Nix's required rules for hiding output values during hashing. Deferred
outputs become input-addressed when all inputs are resolved and remain deferred
when a dynamic or content-addressed input is unresolved. When input derivations
are present, call `build_with_input_hashes` with a callback that gets each
input's `InputDerivationHash` from the store or dependency graph; a plain
`[u8; 32]` still works for regular input-addressed dependencies. Use the `try_`
form if that callback can return an error. Parsed derivations are validated
without being modified; use
`validate_with_input_hashes` or `into_validated_with_input_hashes` for the same
input-dependent case.

Use `StoreDir` when paths belong to a non-default logical store. Its bytes are
used consistently for parsing, rendering, derivation serialization, and store
path fingerprints:

```rust
use nix_derivation::{DerivationBuilder, StoreDir};

let store_dir = StoreDir::new("/guix/store")?;
let drv = DerivationBuilder::new_in_store(
    store_dir.clone(),
    "example",
    "x86_64-linux",
    "/bin/sh",
)
.input_addressed_output("out")
.build()?;

let output = drv.resolved_outputs()["out"]
    .path
    .as_ref()
    .expect("input-addressed output")
    .to_absolute_path_in(&store_dir);
assert!(output.starts_with("/guix/store/"));
# Ok::<(), nix_derivation::Error>(())
```

Read methods borrow data from the owned value: outputs and inputs are exposed
as maps and sets, arguments as a slice, strings as `&str`, and byte-valued
environment entries as `&[u8]`. Output paths are calculated explicitly with
`resolved_outputs()` rather than as a hidden part of ordinary getters.

```rust,no_run
use nix_derivation::{Derivation, OutputPathHash};

fn inspect(bytes: &[u8], name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let drv = Derivation::from_aterm_bytes(bytes, name)?;

    for (path, input) in drv.input_derivations() {
        println!("{path}: depth {}", input.max_depth());
        for node in input.walk() {
            println!("{} {:?}", node.depth(), node.dynamic_output());
        }
    }

    if let Some(attrs) = drv.structured_attrs() {
        println!("system: {:?}", attrs.get("system"));
        println!("{} canonical JSON bytes", attrs.canonical_json().len());
        // Uses declared paths for input-addressed/fixed outputs. A build
        // system with redirected or unknown outputs supplies scratch paths to
        // structured_attrs_files_with_output_paths instead.
        let files = drv.structured_attrs_files()?.expect("attrs are present");
        std::fs::write(".attrs.json", files.json)?;
        std::fs::write(".attrs.sh", files.shell)?;
    }

    let hash = drv.try_hash_output_path_modulo(|input| {
        println!("resolve {input}");
        Ok::<_, std::io::Error>([0; 32])
    })?;
    match hash {
        OutputPathHash::Ready(hash) => println!("{hash}"),
        OutputPathHash::Deferred => println!("an input must be resolved first"),
    }
    Ok(())
}
```

`write_aterm()` streams canonical bytes to any `std::io::Write` without first
allocating a complete byte buffer. `to_aterm_bytes()` returns a newly allocated
buffer and cannot fail. `StorePath`, `NixHash`, `CAHash`, `HashAlgorithm`, and
`ContentAddressMethod` implement `FromStr`; all but `NixHash` also implement
`Display` with an unambiguous canonical name or Nix encoding. Store-path
constructors take validated `StorePath` references, and `build_output_path`
takes a `DerivationModuloHash`, so callers do not need to round-trip typed
identities through strings or untagged digest bytes.

## Benchmarks

Run the package's parse, serialize, and hash benchmark with:

```console
cargo bench -p nix-derivation --bench parse
```

It generates inputs at the same 1,764-byte and 16,026-byte sizes as
[Nix's C++ derivation parser benchmark][nix-benchmark], plus a 64 KiB stress
case.

Run the benchmark over Nix-generated test data separately with:

```console
cargo bench -p nix-derivation --bench corpus
```

The test data covers structured attributes, 128 input sources, a recursive
SHA-256 fixed output, strings with many escaped characters, and recursive
dynamic inputs. Nix 2.34.4 creates the first four cases from the network-free
expressions in [`benches/corpus`](benches/corpus/README.md); the dynamic input
comes from a fixed version of Nix's own test data. Before measuring, every
benchmark parses each input, serializes it, parses that result, and serializes
it again. The two serialized results must match exactly. The same cases and
validation checks also run under `cargo test`. “Parse + first serialize” uses
a fresh derivation on every iteration, while “Serialize (warm)” uses the
checked derivation whose structured-attribute canonicalization cache was
populated by that setup.

### Antithesis workload

An opt-in Antithesis driver expands the fixed corpus with coverage-guided
mutations and arbitrary byte inputs. It states properties for panic-free
parsing, canonical ATerm and structured-JSON serialization, streaming writer
equivalence, validation consistency, and store-path round trips. Run a finite
local smoke test with:

```console
cargo run --features antithesis --bin antithesis-driver -- 1000
```

The SDK uses local randomness outside Antithesis. Pass `0` instead of an
iteration count for an unbounded workload in an Antithesis test container.
Build that binary with the Rust coverage flags from the
[Antithesis instrumentation guide][antithesis-rust-instrumentation]; the
optional feature links the required instrumentation runtime.

These results were measured on the same machine as the comparison below, with
each benchmark restricted to one CPU core and run for seven samples:

| Case | Bytes | Parse | Parse + first serialize | Serialize (warm) | Hash with outputs hidden |
| --- | ---: | ---: | ---: | ---: | ---: |
| structured attrs | 4,196 | 26.55 µs | 116.43 µs | 9.60 µs | 22.59 µs |
| 128 inputs | 15,707 | 27.85 µs | 39.17 µs | 8.60 µs | 26.89 µs |
| fixed output | 514 | 4.73 µs | 6.21 µs | 3.07 µs | 2.85 µs |
| escaped strings | 486 | 4.11 µs | 5.00 µs | 2.42 µs | 3.86 µs |
| dynamic derivation | 255 | 4.07 µs | 4.59 µs | 2.00 µs | n/a[^dynamic-hash] |

[^dynamic-hash]: This Nix test case intentionally has no outputs. It is valid
    parser input but not a build recipe that Nix can hash.

### Nix, Lix, and Snix comparison

This is a local snapshot from 2026-08-10, not a universal implementation
ranking. The 1,764-byte `hello.drv` and 16,026-byte `firefox.drv` inputs are the
[actual files][nix-fixtures] used by Nix's own benchmark. The 64 KiB
stress input is a generated traditional `Derive(...)` ATerm containing many
96-byte environment entries. Each supported input was checked for canonical
serialization before timing: serializing an already serialized value had to
produce identical bytes.

Lower is better. The table reports thousands of CPU cycles per operation,
which avoids changes in CPU frequency distorting comparisons between
processes. Each operation ran for a fixed iteration count under `perf stat`,
and the table reports the median counter value from three process runs.

| Operation | Case | Bytes | `nix-derivation` | Nix | Lix | Snix |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| parse | Nix hello | 1,764 | **25.13** | 32.16 | 39.90 | n/a[^snix] |
| parse | Nix Firefox | 16,026 | **100.66** | 485.93 | 109.59 | n/a[^snix] |
| parse | generated stress | 65,536 | **258.76** | 304.75 | 557.76 | 1,578.23 |
| serialize | Nix hello | 1,764 | **5.01** | 12.47 | 23.73 | n/a[^snix] |
| serialize | Nix Firefox | 16,026 | **31.59** | 196.27 | 59.47 | n/a[^snix] |
| serialize | generated stress | 65,536 | **80.89** | 390.00 | 425.09 | 427.72 |

`nix-derivation` uses the fewest cycles in every shared case. The closest result
is Firefox parsing: it uses 8% fewer cycles than Lix while validating the
derivation's structured JSON; Lix 2.95.2 treats that `__json` value as opaque.
On the generated stress input, Snix uses 6.1x as many cycles to parse and 5.3x
as many to serialize.

[^snix]: The Nix files reuse the placeholder digest `aaaa...` for
    distinct store paths. Snix rejects them as duplicate input sources, so no
    valid Snix timing is available for those exact files.

The measurements were taken on an AMD Ryzen 7 7840S using `nix-derivation`
from this source tree, Nix 2.34.4, Lix 2.95.2, and Snix `d048106f03`. Both Rust
implementations were built together with `rustc 1.95.0`, release optimization,
and the default system allocator. The Nix and Lix drivers used Clang 21.1.8
with `-O3` and linked their packaged release libraries. Lix requires assertions
to remain enabled; the Nix driver used `-DNDEBUG`.

Parse measurements include all work performed by each implementation's public
parse function. In particular, the C++ drivers construct the owned
`std::string` passed to Nix and Lix on every parse, while the Rust APIs borrow
the input byte slice. Serialization starts from an already parsed derivation
and returns a newly allocated byte string. `nix-derivation` fully validates
structured JSON during parsing without materializing its value tree; the first
serialization, typed accessor, or structured-file request builds and sorts
that tree once. The separate corpus benchmark above reports this one-time cost.
Every process was restricted to the same CPU core. This comparison covers only
the common traditional ATerm subset; it does not compare every implementation's
supported features.

[nix-benchmark]: https://github.com/NixOS/nix/blob/2.34.4/src/libstore-tests/derivation-parser-bench.cc
[nix-fixtures]: https://github.com/NixOS/nix/tree/2.34.4/src/libstore-tests/data/derivation
[antithesis-rust-instrumentation]: https://antithesis.com/docs/using_antithesis/sdk/rust/instrumentation
[nix-modulo-refactor]: https://github.com/NixOS/nix/pull/16191
