derivation {
  name = "bench-escapes";
  builder = "/bin/sh";
  system = "x86_64-linux";
  args = [
    "-c"
    "printf '%s\\n' \"quoted\" 'single' back\\slash > $out\nnext-line"
    "tab\tcarriage\rreturn"
    "héllö λ"
  ];
  message = ''
    first line
    "quoted line"
    path\\with\\slashes
    tab	and carriagemarkers
    unicode: héllö λ
  '';
}
