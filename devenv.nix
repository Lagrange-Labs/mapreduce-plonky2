{ pkgs, lib, config, inputs, ... }:

let
  # return `s` if it not empty, `default` otherwise.
  orDefault = s: default: if builtins.stringLength s == 0 then default else s;
in
{
  cachix.enable = false;

  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.figlet pkgs.openssl pkgs.pkg-config pkgs.cargo-limit pkgs.awscli2 pkgs.perl ]
             ++ lib.optionals config.devenv.isTesting [ pkgs.docker ]
             ++ lib.optionals pkgs.stdenv.targetPlatform.isDarwin [
               pkgs.libiconv
               pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
               pkgs.darwin.apple_sdk.frameworks.AppKit
             ];

  dotenv.enable = true;

  enterShell = ''figlet -f slant "MR2 loaded"'';

  # Env. variables
  env = {
    # Rust debuggingin
    RUST_BACKTRACE = 1;
    RUST_LOG = "debug";

    # Required for Rust linking to OpenSSL
    OPENSSL_DEV = pkgs.openssl.dev;

    # Make Go dependencies RW
    GOFLAGS = "-modcacherw";

    DB_URL = "host=localhost dbname=storage port=${builtins.toString config.env.PGPORT}";
  };

  # Use a DB_URL tuned for the dockerized processes.postgres-ci
  enterTest = ''
    cargo test --features ci -- --test-threads 16
  '';

  # Spawn a local PgSQL instance iff we are not in test mode (e.g. when running
  # `devenv up`) for development purposes.
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

  scripts = {
    # Open a shell to the DB
    db.exec = "psql storage -h localhost -p ${builtins.toString config.env.PGPORT}";

    # Wipe out the database
    reset-db.exec = "rm -rf ${config.env.DEVENV_STATE}/postgres";
  };

  # https://devenv.sh/languages/
  languages.rust = {
    enable = true;
    channel = "nightly";
  };
  languages.go.enable = true;

  # https://devenv.sh/pre-commit-hooks/
  ## pre-commit.hooks = {
  ##   # cargo-check.enable = true;
  ##   # check-merge-conflicts.enable = true;
  ##   # clippy.enable = true;
  ##   # commitizen.enable = true;
  ##   # rustfmt.enable = true;
  ## };
}
