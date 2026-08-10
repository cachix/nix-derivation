derivation {
  name = "bench-fixed-output";
  builder = "/bin/sh";
  system = "x86_64-linux";
  args = [ "-c" "printf fixed > $out" ];
  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
  outputHash = "0000000000000000000000000000000000000000000000000000000000000000";
}
