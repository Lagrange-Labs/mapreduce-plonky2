use anyhow::Result;
use envconfig::Envconfig;
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

use super::context::TestContextConfig;

pub struct Benchmarker {
    csv_path: PathBuf,
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
        let writer = File::options().append(true).open(&path)?;
        let mut wtr = csv::Writer::from_writer(writer);
        wtr.write_record(&["name", "time"]);
        info!("Benchmarker setup to write output in {:?}", path);
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
        let writer = File::options().append(true).open(&self.csv_path)?;
        let mut wtr = csv::Writer::from_writer(writer);
        wtr.write_record([name, &elapsed.to_string()])?;
        wtr.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Benchmarker;
    use anyhow::Result;
    #[test]
    fn benchmarker() -> Result<()> {
        let path = testfile::generate_name();
        let b = Benchmarker::new_from_path(path)?;
        b.bench("test_fun", || {
            let _total: u32 = (0..10000).sum();
            Ok(())
        })?;
        Ok(())
    }
}
