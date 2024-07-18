{ pkgs, lib, config, inputs, ... }:

{
  cachix.enable = false;

  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.figlet pkgs.openssl pkgs.pkg-config ]
             ++ lib.optionals pkgs.stdenv.targetPlatform.isDarwin [
               pkgs.libiconv
               pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
               pkgs.darwin.apple_sdk.frameworks.AppKit
             ];

  # https://devenv.sh/basics/
  env.RUST_BACKTRACE = 1;
  # Make Go dependencies RW
  env.GOFLAGS = "-modcacherw";
  env.OPENSSL_DEV = pkgs.openssl.dev;

  enterShell = ''
  figlet -f slant "MR2 loaded"
  '';

  # https://devenv.sh/tests/
  enterTest = ''
    cargo test --features ci -- --test-threads 16
  '';

  # https://devenv.sh/services/
  services.postgres = {
    enable = true;
    listen_addresses = "127.0.0.1";
    settings = {
      log_connections = false;
      log_statement = "all";
    };
    initialDatabases = [{
      name = "storage";
    }];
  };

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
    rustfmt.enable = true;
  };

  # https://devenv.sh/processes/
  # processes.ping.exec = "ping example.com";

  # See full reference at https://devenv.sh/reference/options/
}
