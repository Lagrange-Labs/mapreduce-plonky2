//! This module defines ports that should be implemented to feed data into the update planner.

/// This trait is implemented by anything that we can generate a value extraction proof for.
pub trait Extractable {
    /// This method returns the MPT inclusion proof that the data must have to be extractable.
    fn to_path(&self) -> Vec<Vec<u8>>;
}
