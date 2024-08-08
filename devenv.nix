{ pkgs, lib, config, inputs, ... }:

let
  orDefault = s: default: if builtins.stringLength s == 0 then default else s;
in
{
  cachix.enable = false;

  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.figlet pkgs.openssl pkgs.pkg-config ]
             ++ lib.optionals pkgs.stdenv.targetPlatform.isDarwin [
               pkgs.libiconv
               pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
               pkgs.darwin.apple_sdk.frameworks.AppKit
             ];

  dotenv.enable = true;

  # https://devenv.sh/basics/
  env.RUST_BACKTRACE = 1;
  # Make Go dependencies RW
  env.GOFLAGS = "-modcacherw";
  env.OPENSSL_DEV = pkgs.openssl.dev;

  # https://devenv.sh/tests/
  enterTest = ''
    cargo test --features ci -- --test-threads 16
  '';

  # https://devenv.sh/services/
  services.postgres = {
    enable = true;
    listen_addresses = "127.0.0.1";
    port = lib.strings.toInt (orDefault config.env.PGSQL_PORT "5432");
    settings = {
      log_connections = false;
      log_statement = "all";
    };
    initialDatabases = [{
      name = "storage";
    }];
  };

  enterShell = ''
  figlet -f slant "MR2 loaded"
  figlet -f standard -w200 "PgSQL on port ${builtins.toString config.env.PGSQL_PORT}"
  '';

  scripts.db.exec = "psql storage -h localhost -p ${builtins.toString config.env.PGPORT}";

  # https://devenv.sh/languages/
  languages.rust = {
    enable = true;
    channel = "nightly";
  };
  languages.go.enable = true;

  # https://devenv.sh/pre-commit-hooks/
  pre-commit.hooks = {
    # cargo-check.enable = true;
    check-merge-conflicts.enable = true;
    # clippy.enable = true;
    # commitizen.enable = true;
    # rustfmt.enable = true;
  };

  # https://devenv.sh/processes/
  # processes.ping.exec = "ping example.com";

  # See full reference at https://devenv.sh/reference/options/
}
