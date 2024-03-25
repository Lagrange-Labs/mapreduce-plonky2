//! Compile Go functions

use std::{
    env,
    io::{self, Write},
};

fn main() {
    let lib_name = "go-gnark-utils";
    let out_dir = env::var("OUT_DIR").unwrap();

    if let Err(e) = gobuild::Build::new()
        .files(
            glob::glob("./lib/*.go")
                .unwrap()
                .map(|p| p.unwrap().to_string_lossy().to_string()),
        )
        .try_compile(lib_name)
    {
        if format!("{}", e).starts_with("Failed to find tool.") {
            fail(" Failed to find Go. Please install Go 1.20.".to_string());
        } else {
            fail(format!("{}", e));
        }
    }

    // Files of the lib depends on that should recompile the lib.
    println!("cargo:rerun-if-changed=go.mod");
    let dep_files = glob::glob("./lib/*.go").unwrap().filter_map(|v| v.ok());
    for file in dep_files {
        println!("cargo:rerun-if-changed={}", file.to_str().unwrap());
    }

    // Links
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static={}", lib_name);
}

fn fail(message: String) {
    let _ = writeln!(
        io::stderr(),
        "\n\nError while building gnark-utils: {}\n\n",
        message
    );
    std::process::exit(1);
}
