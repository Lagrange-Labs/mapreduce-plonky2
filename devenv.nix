{ pkgs, lib, config, inputs, ... }:

let
  orDefault = s: default: if builtins.stringLength s == 0 then default else s;
in
{
  cachix.enable = false;

  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.figlet pkgs.openssl pkgs.pkg-config ]
             ++ lib.optionals config.devenv.isTesting [ pkgs.docker ]
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
  env.DB_URL = "host=localhost dbname=storage port=${builtins.toString config.env.PGPORT}";

  # https://devenv.sh/tests/
  enterTest = ''
    cargo test --features ci -- --test-threads 16
  '';

  # Spawn a local PgSQL instance iff we are not in test mode (e.g. when running
  # `devenv up`) for development purposes.
  services.postgres = {
    enable = !config.devenv.isTesting;
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
  '';

  scripts.db.exec = "psql storage -h localhost -p ${builtins.toString config.env.PGPORT}";

  # Run PgSQL in a container iff we are running `devenv test`. The goal is to be
  # able to run multiple PgSQL at once on the same machine for concurrent CI
  # runs on beefy servers.
  processes.postgres-ci = lib.mkIf config.devenv.isTesting {
    exec = (lib.concatStringsSep " " [
      "${pkgs.docker}/bin/docker"
      "--name postgres-${config.env.PGPORT}"
      "run"
      "-p ${config.env.PGPORT}:5432"
      "postgres"
    ]
    );

    process-compose = {
      description = "docker container of postgres";
      shutdown = {
        command = "${pkgs.docker}/bin/docker rm -f postgres-${config.env.PGPORT}";
      };
      environment = [
        "POSTGRES_DB=storage"
      ];
    };
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
    # rustfmt.enable = true;
  };
}
