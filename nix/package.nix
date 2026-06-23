{ pkgs }:

let
  lib = pkgs.lib;
  root = toString ../.;
  relPath = path:
    let
      pathStr = toString path;
    in
    if pathStr == root then
      ""
    else
      lib.removePrefix (root + "/") pathStr;

  filteredSrc = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let
        rel = relPath path;
      in
      if type == "directory" then
        rel == "" || rel == "src" || lib.hasPrefix "src/" rel
      else
        (lib.hasPrefix "src/" rel && lib.hasSuffix ".nim" rel)
        || rel == "tyr_crypto.nimble"
        || rel == "README.md"
        || rel == "UNLICENSE"
        || rel == "LICENSE"
        || rel == "config.nims";
  };
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "tyr-crypto";
  version = "0.1.0";
  src = filteredSrc;

  installPhase = ''
    mkdir -p "$out/share/nimble/pkgs/tyr_crypto"
    cp -R src "$out/share/nimble/pkgs/tyr_crypto/"
    cp tyr_crypto.nimble "$out/share/nimble/pkgs/tyr_crypto/"
    cp README.md "$out/share/nimble/pkgs/tyr_crypto/"
  '';
}
