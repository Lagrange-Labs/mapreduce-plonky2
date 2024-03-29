/// Utility functions
use crate::go;
use anyhow::{bail, Result};
use std::ffi::CStr;
use std::os::raw::c_char;

/// Convert a C result of string pointer to a Rust result. It's OK if the
/// pointer is null.
pub fn handle_c_result(result: *const c_char) -> Result<()> {
    if result.is_null() {
        return Ok(());
    }

    let c_result = unsafe { CStr::from_ptr(result) };
    let error = c_result.to_str()?.to_string();

    unsafe { go::FreeString(c_result.as_ptr()) };

    bail!(error);
}
