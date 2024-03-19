//! This script builds the Groth16 prover from the Go code.

use std::{env, fs, path::Path, process::Command};

const GROTH16_PROVER_DIR: &str = "gnark-plonky2-verifier";

/// Build main entry point.
fn main() {
    check_go_command();
    check_groth16_prover_path();
    build_groth16_prover();
}

/// Ensure must have Go command.
fn check_go_command() {
    let output = Command::new("go")
        .arg("version")
        .output()
        .expect("An exception occurred when executing 'go version'.");

    if !output.status.success() {
        panic!("Failed to execute 'go version'.");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("go version") {
        panic!("Failed to find Go. Please install Go 1.20.");
    }
}

/// Ensure the Groth16 prover path must exist.
fn check_groth16_prover_path() {
    let path = Path::new(GROTH16_PROVER_DIR).join("prover.go");
    fs::metadata(path).unwrap_or_else(|_| panic!("Failed to find {GROTH16_PROVER_DIR}. Please run 'git submodule update --init --recursive'"));
}

/// Build the Groth16 prover command.
fn build_groth16_prover() {
    // Cache the work dir.
    let old_work_dir = env::current_dir().expect("Failed to get the work dir from ENV");

    // Build the Groth16 prover.
    env::set_current_dir(GROTH16_PROVER_DIR)
        .expect("Failed to set work dir to Groth16 prover path");
    let output = Command::new("go")
        .arg("build")
        .arg("prover.go")
        .output()
        .expect("Failed to execute 'go build'.");
    if !output.status.success() {
        panic!(
            "Failed to build Groth16 prover: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Restore the work dir.
    env::set_current_dir(old_work_dir).expect("Failed to restore the work dir");
}
