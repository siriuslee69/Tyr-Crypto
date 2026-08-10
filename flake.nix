{
  description = "Tyr-Crypto";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/package.nix { };
        tyr-crypto = pkgs.callPackage ./nix/package.nix { };
      });

      devShells = forAllSystems (pkgs:
        let
          sodiumLibPath = pkgs.lib.makeLibraryPath [ pkgs.libsodium ];
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              nim
              git
              gcc
              binutils
              gnumake
              pkg-config
              cmake
              autoconf
              automake
              libtool
              zig
              libsodium
            ];

            shellHook = ''
              export CC=${pkgs.gcc}/bin/gcc
              export AR=${pkgs.binutils}/bin/ar
              export LIBSODIUM_LIB_DIRS=${pkgs.libsodium}/lib
              export LD_LIBRARY_PATH=${sodiumLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
              echo "Tyr-Crypto Nix shell ready."
              echo "libsodium: $LIBSODIUM_LIB_DIRS"
            '';
          };
        });

      nixosModules.default = import ./nix/module.nix;
      nixosModules.tyr-crypto = import ./nix/module.nix;
    };
}
