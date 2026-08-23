let
  system = builtins.currentSystem;
  leaf = derivation {
    name = "try-resolve-generated";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" "printf resolved > $out" ];
  };
  producer = derivation {
    name = "try-resolve-generated.drv";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" "IFS= read -r value < ${leaf.drvPath}; printf %s \"$value\" > $out" ];
    __contentAddressed = true;
    outputHashMode = "text";
    outputHashAlgo = "sha256";
  };
  dynamicLeaf = builtins.outputOf producer.outPath "out";
in
derivation {
  name = "try-resolve-consumer";
  inherit system;
  builder = "/bin/sh";
  args = [ "-c" "IFS= read -r value < ${dynamicLeaf}; printf %s \"$value\" > $out" ];
  inherit dynamicLeaf;
}
