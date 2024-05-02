use log::{log_enabled, Level, LevelFilter};
use std::{env, io::Write};

/// Sets RUST_LOG=debug and initializes the logger
/// if it hasn't been enabled already.
pub fn init_logging() {
    if !log_enabled!(Level::Debug) {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder()
            .format(|buf, record| writeln!(buf, "    {}", record.args()))
            .try_init();
        log::set_max_level(LevelFilter::Debug);
    }
}
