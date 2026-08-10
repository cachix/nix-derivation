# Benchmark corpus

`structured-attrs.drv`, `many-inputs.drv`, `fixed-output.drv`, and
`escapes.drv` are instantiated by Nix from the expressions beside them. The
expressions are part of `nix-derivation` and use no nixpkgs or network input.

Regenerate those fixtures and fetch the pinned dynamic-derivation fixture with:

```console
./regenerate.sh
```

Run the corpus benchmark from the workspace root with:

```console
cargo bench -p nix-derivation --bench corpus
```

`dynamic-derivation.drv` is copied verbatim from the Nix 2.34.4 unit-test
corpus:

<https://github.com/NixOS/nix/blob/2.34.4/src/libstore-tests/data/derivation/dyn-dep-derivation.drv>

That fixture remains copyright the Nix contributors and is redistributed
under Nix's LGPL-2.1-or-later license. The other corpus files are generated
data from the expressions in this directory.
