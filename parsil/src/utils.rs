use alloy::primitives::U256;
use anyhow::*;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placeholder {
    LowerBlock(usize),
    HigherBlock(usize),
    Standard(usize),
}
impl Placeholder {
    pub(crate) fn id(&self) -> usize {
        match self {
            Placeholder::LowerBlock(id)
            | Placeholder::HigherBlock(id)
            | Placeholder::Standard(id) => *id,
        }
    }
}

/// This register handle all operations related to placeholder registration,
/// lookup an validation.
#[derive(Debug)]
pub(crate) struct PlaceholderRegister {
    /// The set of available placeholders.
    register: Vec<(String, Placeholder)>,
}
impl std::default::Default for PlaceholderRegister {
    /// Instantiate a test-appropriate register with block, block max, and three
    /// freestanding placeholders.
    fn default() -> Self {
        PlaceholderRegister {
            register: vec![
                ("$min_block".into(), Placeholder::LowerBlock(0)),
                ("$max_block".into(), Placeholder::HigherBlock(1)),
                ("$1".into(), Placeholder::Standard(2)),
                ("$2".into(), Placeholder::Standard(3)),
                ("$3".into(), Placeholder::Standard(4)),
            ],
        }
    }
}
impl PlaceholderRegister {
    /// Given a placeholder name, return, if it exists, the associated
    /// [`Placeholder`].
    pub(crate) fn resolve(&self, s: &str) -> Option<Placeholder> {
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

#[derive(Debug)]
pub struct ParsingSettings {
    pub(crate) placeholders: PlaceholderRegister,
}
impl std::default::Default for ParsingSettings {
    fn default() -> Self {
        Self {
            placeholders: Default::default(),
        }
    }
}

/// Convert a string to a U256. Case is not conserved, and the string may be
/// prefixed by a radix indicator.
pub fn str_to_u256(s: &str) -> Result<U256> {
    let s = s.to_lowercase();
    U256::from_str(&s).map_err(|e| anyhow!("{s}: invalid U256: {e}"))
}
