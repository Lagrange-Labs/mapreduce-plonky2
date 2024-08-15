use alloy::primitives::U256;
use anyhow::*;
use std::str::FromStr;
use verifiable_db::query::computational_hash_ids::PlaceholderIdentifier;

/// This register handle all operations related to placeholder registration,
/// lookup an validation.
#[derive(Debug)]
pub(crate) struct PlaceholderRegister {
    /// The set of available placeholders.
    register: Vec<(String, PlaceholderIdentifier)>,
}
impl std::default::Default for PlaceholderRegister {
    /// Instantiate a test-appropriate register with block, block max, and three
    /// freestanding placeholders.
    fn default() -> Self {
        PlaceholderRegister {
            register: vec![
                ("$min_block".into(), PlaceholderIdentifier::MinQueryOnIdx1),
                ("$max_block".into(), PlaceholderIdentifier::MaxQueryOnIdx1),
                ("$1".into(), PlaceholderIdentifier::Generic(1)),
                ("$2".into(), PlaceholderIdentifier::Generic(1)),
                ("$3".into(), PlaceholderIdentifier::Generic(1)),
            ],
        }
    }
}
impl PlaceholderRegister {
    /// Given a placeholder name, return, if it exists, the associated
    /// [`Placeholder`].
    pub(crate) fn resolve(&self, s: &str) -> Option<PlaceholderIdentifier> {
        self.register
            .iter()
            .find(|(name, _)| name == s)
            .map(|(_, placeholder)| placeholder.to_owned())
    }

    /// Given a placeholder name, return, if it exists, its unique ID.
    pub(crate) fn id(&self, s: &str) -> Option<usize> {
        self.register
            .iter()
            .enumerate()
            .find(|(_, (name, _))| name == s)
            .map(|(i, _)| i)
    }
}

#[derive(Debug, Default)]
pub struct ParsingSettings {
    pub(crate) placeholders: PlaceholderRegister,
}

/// Convert a string to a U256. Case is not conserved, and the string may be
/// prefixed by a radix indicator.
pub fn str_to_u256(s: &str) -> Result<U256> {
    let s = s.to_lowercase();
    U256::from_str(&s).map_err(|e| anyhow!("{s}: invalid U256: {e}"))
}
