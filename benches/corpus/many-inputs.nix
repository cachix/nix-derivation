let
  inputs = builtins.genList
    (index: builtins.toFile "bench-input-${toString index}" "payload ${toString index}\n")
    128;
in
derivation {
  name = "bench-many-inputs";
  builder = "/bin/sh";
  system = "x86_64-linux";
  args = [ "-c" "printf inputs > $out" ];
  inherit inputs;
}
