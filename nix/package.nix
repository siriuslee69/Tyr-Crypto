{ pkgs }:

let
  ## One source: [project] in configs/default.toml names the package.
  project = (builtins.fromTOML (builtins.readFile ../configs/default.toml)).project;
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
        rel == "" || rel == "src" || lib.hasPrefix "src/" rel || rel == "configs"
      else
        (lib.hasPrefix "src/" rel && lib.hasSuffix ".nim" rel)
        || rel == "tyr.nimble"
        || rel == "README.md"
        || rel == "UNLICENSE"
        || rel == "LICENSE"
        || rel == "config.nims"
        || rel == "tyr_simd.nims"
        || (lib.hasPrefix "configs/" rel && lib.hasSuffix ".toml" rel);
  };
in
pkgs.stdenvNoCC.mkDerivation {
  pname = project.name;
  version = project.version;
  meta.description = project.description;
  src = filteredSrc;

  installPhase = ''
    mkdir -p "$out/share/nimble/pkgs/tyr"
    cp -R src "$out/share/nimble/pkgs/tyr/"
    cp tyr.nimble "$out/share/nimble/pkgs/tyr/"
    cp README.md tyr_simd.nims "$out/share/nimble/pkgs/tyr/"
    cp -r configs "$out/share/nimble/pkgs/tyr/"
  '';
}
