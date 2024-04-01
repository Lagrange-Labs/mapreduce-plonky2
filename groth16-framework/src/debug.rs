//! Debug configurations

use anyhow::Result;
use std::env;

/// Groth16 debug configuration
#[derive(Debug)]
enum Groth16DebugConfig {
    /// No debug info to output
    None,
    /// Only output the debug info for the errors
    Error,
    /// Always output the debug info
    All,
}

impl From<String> for Groth16DebugConfig {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "all" => Self::All,
            "error" => Self::Error,
            _ => Self::None,
        }
    }
}

/// Get the Groth16 debug configuration from ENV.
fn get_debug_config() -> Groth16DebugConfig {
    env::var("GROTH16_DEBUG_CONFIG").unwrap_or_default().into()
}

/// Get the Groth16 debug output dir from ENV.
pub fn get_debug_output_dir<T>(result_to_debug: &Result<T>) -> Option<String> {
    let dir = env::var("GROTH16_DEBUG_DIR").ok();
    if dir.is_none() {
        return None;
    }

    let config = get_debug_config();
    match config {
        // Return the output dir if it's an error.
        Groth16DebugConfig::Error => result_to_debug.as_ref().map_or(None, |_| dir),
        // Always return the output dir.
        Groth16DebugConfig::All => dir,
        _ => None,
    }
}
