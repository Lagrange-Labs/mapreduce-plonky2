//! EVM utility functions
//! Copied and modified from [snark-verifier](https://github.com/privacy-scaling-explorations/snark-verifier).

use std::{
    io::{ErrorKind, Write},
    process::{Command, Stdio},
};

/// Compile given Solidity `code` into deployment bytecode.
pub fn compile_solidity(code: &[u8]) -> Vec<u8> {
    let mut cmd = match Command::new("solc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("--bin")
        .arg("-")
        .spawn()
    {
        Ok(cmd) => cmd,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            panic!("Command 'solc' not found");
        }
        Err(err) => {
            panic!("Failed to spawn cmd with command 'solc':\n{err}");
        }
    };

    cmd.stdin.take().unwrap().write_all(code).unwrap();
    let output = cmd.wait_with_output().unwrap().stdout;
    let binary = *split_by_ascii_whitespace(&output).last().unwrap();
    hex::decode(binary).unwrap()
}

fn split_by_ascii_whitespace(bytes: &[u8]) -> Vec<&[u8]> {
    let mut split = Vec::new();
    let mut start = None;
    for (idx, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_whitespace() {
            if let Some(start) = start.take() {
                split.push(&bytes[start..idx]);
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }
    split
}
