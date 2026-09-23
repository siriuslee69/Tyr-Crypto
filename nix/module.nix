{ config, lib, pkgs, ... }:

let
  cfg = config.programs.tyr-crypto;
  project = (builtins.fromTOML (builtins.readFile ../configs/default.toml)).project;
  tomlFormat = pkgs.formats.toml { };

  ## Presets: configs/<name>.toml. Tyr compiles nothing on its own, so the
  ## chosen preset becomes the consumer profile: the build switches a
  ## service that uses Tyr should compile with. default.toml first, the
  ## named preset over it, `settings` over both.
  presetNames = map (lib.removeSuffix ".toml")
    (builtins.filter (lib.hasSuffix ".toml")
      (builtins.attrNames (builtins.readDir ../configs)));

  presetTable = name: builtins.removeAttrs
    (builtins.fromTOML (builtins.readFile (../configs + "/${name}.toml")))
    [ "project" "preset" ];

  effectiveGlobalSettings = lib.recursiveUpdate
    (lib.recursiveUpdate (presetTable "default") (presetTable cfg.preset))
    cfg.settings;

  hasSettings = settings: settings != { };

  generatedToml = name: settings:
    tomlFormat.generate "tyr-crypto-${name}.toml" settings;

  effectiveProfileSettings = profileCfg:
    if profileCfg.mode == "replace" then
      profileCfg.settings
    else
      lib.recursiveUpdate effectiveGlobalSettings profileCfg.settings;

  mkProfileOptions = with lib; { name, ... }: {
    options = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Generate this named Tyr consumer profile.";
      };

      mode = mkOption {
        type = types.enum [ "merge" "replace" ];
        default = "merge";
        description = "Merge global profile settings into this profile, or replace them.";
      };

      target = mkOption {
        type = types.str;
        default = "tyr-crypto/profiles/${name}.toml";
        description = "Path below /etc for this declarative consumer profile.";
      };

      settings = mkOption {
        type = tomlFormat.type;
        default = { };
        description = "Declarative profile values for downstream Tyr consumers.";
      };

      configFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "External profile file. Mutually exclusive with settings.";
      };
    };
  };
in
{
  options.programs.tyr-crypto = with lib; {
    enable = mkEnableOption "${project.name} ${project.version}: ${project.description}";

    preset = mkOption {
      type = types.enum presetNames;
      default = "default";
      example = "iot";
      description = "Build preset from configs/, written out as the consumer profile.";
    };

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "Tyr-Crypto source package.";
    };

    installPackage = mkOption {
      type = types.bool;
      default = true;
      description = "Add the Tyr source package to environment.systemPackages.";
    };

    target = mkOption {
      type = types.str;
      default = "tyr-crypto/profile.toml";
      description = "Path below /etc for the global Tyr consumer profile.";
    };

    settings = mkOption {
      type = tomlFormat.type;
      default = { };
      example = {
        pqProfile = "portable";
        simd = "auto";
        kdfMemoryKiB = 65536;
      };
      description = ''
        Declarative global profile values for services that consume Tyr.
        Tyr itself remains an import-only library and does not read this file.
      '';
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "External global profile file. Mutually exclusive with settings.";
    };

    profiles = mkOption {
      type = types.attrsOf (types.submodule mkProfileOptions);
      default = { };
      description = "Named frontend/client/server profiles for Tyr consumers.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = !(cfg.configFile != null && hasSettings cfg.settings);
          message = "programs.tyr-crypto: configFile and settings are mutually exclusive.";
        }
      ]
      ++
      (lib.mapAttrsToList (name: profileCfg: {
        assertion = !(profileCfg.configFile != null && hasSettings profileCfg.settings);
        message = "programs.tyr-crypto.profiles.${name}: configFile and settings are mutually exclusive.";
      }) cfg.profiles);

    environment.systemPackages = lib.mkIf cfg.installPackage [ cfg.package ];

    environment.etc =
      {
        "${cfg.target}".source =
          if cfg.configFile != null then cfg.configFile
          else generatedToml "global" effectiveGlobalSettings;
      }
      //
      (lib.mapAttrs'
        (name: profileCfg:
          lib.nameValuePair profileCfg.target {
            source =
              if profileCfg.configFile != null then
                profileCfg.configFile
              else
                generatedToml name (effectiveProfileSettings profileCfg);
          })
        (lib.filterAttrs (_: profileCfg: profileCfg.enable) cfg.profiles));
  };
}
