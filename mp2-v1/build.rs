//! Generate test contract Rust bindings

use std::process::Command;

fn main() {
    // The Solidity source files are depended on that should regenerate the bindings.
    let dep_files = glob::glob("./test-contracts/src/*.sol")
        .unwrap()
        .filter_map(|v| v.ok());
    dep_files.for_each(|file| {
        println!("cargo:rerun-if-changed={}", file.to_str().unwrap());
    });

    // Regenerate the Rust bindings.
    Command::new("make")
        .arg("int_bind")
        .output()
        .expect("Failed to regenerate the Rust bindings. Please install Foundry: https://github.com/foundry-rs/foundry");
}
