use anyhow::Result;
use envconfig::Envconfig;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

use super::context::TestContextConfig;

pub struct Benchmarker {
    csv_path: PathBuf,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Record {
    name: String,
    time: u128,
}
const DEFAULT_BENCH_FILE: &str = "bench.csv";

impl Benchmarker {
    pub fn new_from_env() -> Result<Self> {
        let cfg = TestContextConfig::init_from_env()?;
        let path = cfg
            .params_dir
            .expect("we need a config folder to run the integrated test");
        let mut path = PathBuf::from(path);
        path.push(DEFAULT_BENCH_FILE);
        Self::new_from_path(path)
    }

    pub fn new_from_path(path: PathBuf) -> Result<Self> {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(Self { csv_path: path })
    }

    pub fn bench<F, O>(&self, name: &str, f: F) -> Result<O>
    where
        F: FnOnce() -> Result<O>,
    {
        let now = std::time::Instant::now();
        let output = f()?;
        let elapsed = now.elapsed().as_millis();
        self.write_to_csv(name, elapsed)?;
        Ok(output)
    }

    pub fn write_to_csv(&self, name: &str, elapsed: u128) -> Result<()> {
        let record = Record {
            name: name.to_string(),
            time: elapsed,
        };
        let writer = File::open(&self.csv_path)?;
        let mut wtr = csv::Writer::from_writer(writer);
        wtr.serialize(record)?;
        wtr.flush()?;
        Ok(())
    }
}
