use std::env;

use log::{log_enabled, Level, LevelFilter};
use std::io::Write;
mod array_access;
#[cfg(test)]
mod recursion;

/// Sets RUST_LOG=debug and initializes the logger
/// if it hasn't been enabled already.
pub(crate) fn init_logging() {
    if !log_enabled!(Level::Debug) {
        env::set_var("RUST_LOG", "debug");
        env_logger::builder()
            .format(|buf, record| writeln!(buf, "    {}", record.args()))
            .init();
        log::set_max_level(LevelFilter::Debug);
    }
}
