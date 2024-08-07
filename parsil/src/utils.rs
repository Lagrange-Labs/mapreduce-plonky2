use std::str::FromStr;

use alloy::primitives::U256;
use anyhow::*;

pub fn parse_string(s: &str) -> Result<U256> {
    let s = s.to_lowercase();
    U256::from_str(&s).map_err(|e| anyhow!("{s}: invalid U256: {e}"))
}
