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

      nixosModules.default = import ./nix/module.nix;
      nixosModules.tyr-crypto = import ./nix/module.nix;
    };
}
