//! Merkle tree implementation

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

/// Merkle tree structure
#[derive(Clone, Debug)]
pub struct MerkleTree<F, C, const D: usize, Output>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    Output: Clone,
{
    /// The root of Merkle tree
    root: MerkleNode<F, C, D, Output>,
    /// Maximum level of Merkle tree and levels start from zero. It's used to
    /// avoid recalculation.
    max_level: u64,
}

impl<F, C, const D: usize, Output> MerkleTree<F, C, D, Output>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    Output: Clone,
{
    /// Create a Merkle tree by the root node.
    pub fn new(root: MerkleNode<F, C, D, Output>) -> Self {
        let max_level = root.max_level(0);
        Self { root, max_level }
    }

    /// Return the root.
    pub fn root(&self) -> &MerkleNode<F, C, D, Output> {
        &self.root
    }

    /// Return the maximum level of Merkle tree.
    pub fn max_level(&self) -> u64 {
        self.max_level
    }

    /// Return the all leaves.
    pub fn all_leaves(&mut self) -> Vec<&mut MerkleNode<F, C, D, Output>> {
        self.root.all_leaves()
    }

    /// Return the all branches (without leaves) at the specified level.
    pub fn branches_at_level(&mut self, level: u64) -> Vec<&mut MerkleNode<F, C, D, Output>> {
        self.root.branches_at_level(level)
    }
}

/// Define the value type of Merkle tree leaves.
pub type MerkleLeafValue = [u8; 32];

/// Merkle node structure
#[derive(Clone, Debug)]
pub enum MerkleNode<F, C, const D: usize, Output>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// A Merkle tree branch including child nodes, output value and proof of
    /// this node.
    Branch(Vec<Self>, Output, Option<ProofWithPublicInputs<F, C, D>>),
    /// A Merkle tree leaf including original value, output value and proof of
    /// this node.
    Leaf(
        MerkleLeafValue,
        Output,
        Option<ProofWithPublicInputs<F, C, D>>,
    ),
}

impl<F, C, const D: usize, Output> MerkleNode<F, C, D, Output>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// Get the maximum level of this node, and it starts from zero.
    pub fn max_level(&self, current: u64) -> u64 {
        match self {
            Self::Branch(children, ..) => {
                // Calculate the maximum level recursively.
                let current = current + 1;
                children.iter().map(|n| n.max_level(current)).max().unwrap()
            }
            Self::Leaf(..) => current,
        }
    }

    /// Get the all leaf nodes.
    /// The return nodes are mutable and could be used to set the proof result
    /// to the nodes.
    pub fn all_leaves(&mut self) -> Vec<&mut MerkleNode<F, C, D, Output>> {
        match self {
            Self::Branch(children, ..) => {
                // Get the leaves recursively.
                children.iter_mut().flat_map(|n| n.all_leaves()).collect()
            }
            Self::Leaf(..) => vec![self],
        }
    }

    /// Get branches at the specified level.
    /// The return nodes are mutable and could be used to set the proof result
    /// to the nodes.
    pub fn branches_at_level(&mut self, current: u64) -> Vec<&mut MerkleNode<F, C, D, Output>> {
        // Return this branch directly if the current level is zero.
        if current == 0 {
            if let Self::Branch(..) = self {
                return vec![self];
            }
        }

        match self {
            Self::Branch(children, ..) => {
                // Get the branches recursively.
                let current = current - 1;
                children
                    .iter_mut()
                    .flat_map(|n| n.branches_at_level(current))
                    .collect()
            }
            Self::Leaf(..) => vec![],
        }
    }

    /// Get the output value of this node.
    pub fn output(&self) -> &Output {
        match self {
            Self::Branch(_, output, ..) => output,
            Self::Leaf(_, output, ..) => output,
        }
    }

    /// Get the proof of this node.
    pub fn proof(&self) -> &Option<ProofWithPublicInputs<F, C, D>> {
        match self {
            Self::Branch(.., proof) => proof,
            Self::Leaf(.., proof) => proof,
        }
    }
}
