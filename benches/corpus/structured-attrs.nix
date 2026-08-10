derivation {
  name = "bench-structured-attrs";
  builder = "/bin/sh";
  system = "x86_64-linux";
  __structuredAttrs = true;
  args = [ "-c" "printf structured > $out" ];
  flags = {
    enabled = true;
    retries = 7;
    labels = [ "alpha" "beta" "gamma" ];
  };
  matrix = builtins.genList
    (row: builtins.genList (column: { inherit row column; }) 12)
    12;
  nested = {
    a.b.c = [ null false true (-42) "héllö λ" ];
    z = "last";
  };
}
