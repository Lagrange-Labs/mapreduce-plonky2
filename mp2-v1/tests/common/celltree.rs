use anyhow::*;
use ethers::types::{Address, U256};
use hashbrown::HashMap;
use mp2_common::{
    eth::ProofQuery, poseidon::empty_poseidon_hash, proof::ProofWithVK, utils::ToFields, CHasher, F,
};
use mp2_v1::values_extraction::compute_leaf_single_id;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad},
    plonk::config::Hasher,
};
use ryhope::{
    hasher::TreeHasher,
    storage::{memory::InMemory, updatetree::UpdateTree, EpochKvStorage, TreeTransactionalStorage},
    tree::{sbbst, TreeTopology},
    MerkleTreeKvDb,
};
use std::str::FromStr;
use verifiable_db::api::CircuitInput;

use crate::common::TestContext;

pub struct PoseidonTreeHasher;
impl TreeHasher for PoseidonTreeHasher {
    type Input = (F, U256);

    type Hashed = HashOut<F>;

    fn empty_hash() -> Self::Hashed {
        *empty_poseidon_hash()
    }

    fn hash_node<I: IntoIterator<Item = Self::Hashed>>(
        children_hashes: I,
        (identifier, value): &Self::Input,
    ) -> Self::Hashed {
        // P(L || R || ID || value)
        let fs =
                // Take 2 elts (# of children), filling empty slots with P("")
                children_hashes
                .into_iter()
                .chain(std::iter::repeat_with(Self::empty_hash))
                .take(2)
                .flat_map(|x| x.elements.into_iter())
                // ID
                .chain(std::iter::once(*identifier))
                // Value
                .chain(value.to_fields().into_iter())
                .collect::<Vec<_>>();

        hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&fs)
    }
}

// (identifier, value)
type Cell = (F, U256);
pub struct Row {
    cells: Vec<Cell>,
    // NOTE: more to come later on
}
type CellTree = sbbst::Tree;
type CellStorage = InMemory<CellTree, Cell, <PoseidonTreeHasher as TreeHasher>::Hashed>;
pub type MerkleCellTree = MerkleTreeKvDb<CellTree, Cell, CellStorage, PoseidonTreeHasher>;

// NOTE: this is not really aync for now, but will be in the future when Ryhope
// turns async.
pub async fn build_cell_tree(
    row: &Row,
) -> Result<(MerkleCellTree, UpdateTree<<CellTree as TreeTopology>::Key>)> {
    let mut cell_tree = MerkleCellTree::create((0, 0), ()).unwrap();
    let update_tree = cell_tree
        .in_transaction(|t| {
            for (i, (identifier, value)) in row.cells.iter().enumerate() {
                // SBBST starts at 1, not 0. Note though this index is not important
                // since at no point we are looking up value per index in the cells
                // tree we always look at the entire row at the row tree level.
                t.store(i + 1, (identifier.to_owned(), value.to_owned()))?;
            }
            Ok(())
        })
        .context("while building tree")?;

    Ok((cell_tree, update_tree))
}

impl TestContext {
    /// Fetch the values and build the identifiers from a list of slots to
    /// generate a [`Row`] that will then be encoded as a [`MerkleCellTree`].
    pub async fn build_row(&self, contract_address: &str, slots: &[u8]) -> Row {
        let contract_address = Address::from_str(contract_address).unwrap();
        let mut cells = Vec::new();
        for slot in slots {
            let query = ProofQuery::new_simple_slot(contract_address, *slot as usize);
            let identifier = GoldilocksField::from_canonical_u64(compute_leaf_single_id(
                *slot,
                &contract_address,
            ));
            let value = self
                .query_mpt_proof(&query, self.get_block_number())
                .await
                .storage_proof[0]
                .value;
            cells.push((identifier, value));
        }

        Row { cells }
    }

    /// Given a [`MerkleCellTree`], recursively prove its hash.
    pub async fn prove_cell_tree(
        &self,
        t: &MerkleCellTree,
        ut: UpdateTree<<CellTree as TreeTopology>::Key>,
    ) -> HashOut<F> {
        // Store the proofs here for the tests; will probably be done in S3 for
        // prod.
        let mut proofs = HashMap::<<CellTree as TreeTopology>::Key, Vec<u8>>::new();
        let mut workplan = ut.into_workplan();

        while let Some(todos) = workplan.next() {
            for k in todos {
                let (context, (identifier, value)) = t.fetch_with_context(&k);

                let proof = if context.is_leaf() {
                    // Prove a leaf
                    let inputs = CircuitInput::CellsTree(
                        verifiable_db::cells_tree::CircuitInput::new_leaf(identifier, value),
                    );
                    self.params()
                        .zkdb
                        .generate_proof(inputs)
                        .expect("while proving leaf")
                } else if context.right.is_none() {
                    // Prove a partial node
                    let left_proof = proofs
                        .get(&context.left.unwrap())
                        .expect("UT guarantees proving in order")
                        .to_owned();
                    let inputs = CircuitInput::CellsTree(
                        verifiable_db::cells_tree::CircuitInput::new_partial_node(
                            identifier, value, left_proof,
                        ),
                    );
                    self.params()
                        .zkdb
                        .generate_proof(inputs)
                        .expect("while proving partial node")
                } else {
                    // Prove a full node.
                    let left_proof = proofs
                        .get(&context.left.unwrap())
                        .expect("UT guarantees proving in order")
                        .to_vec();
                    let right_proof = proofs
                        .get(&context.right.unwrap())
                        .expect("UT guarantees proving in order")
                        .to_vec();
                    let inputs = CircuitInput::CellsTree(
                        verifiable_db::cells_tree::CircuitInput::new_full_node(
                            identifier,
                            value,
                            [left_proof, right_proof],
                        ),
                    );
                    self.params()
                        .zkdb
                        .generate_proof(inputs)
                        .expect("while proving full node")
                };
                proofs.insert(k, proof);

                workplan.done(&k).unwrap();
            }
        }
        let root = t.tree().root().unwrap();
        let root_proof = proofs.get(&root).unwrap().to_vec();
        let root_pi = ProofWithVK::deserialize(&root_proof)
            .expect("while deserializing proof")
            .proof
            .public_inputs;
        let root_pi = verifiable_db::cells_tree::PublicInputs::from_slice(&root_pi);
        root_pi.root_hash_hashout()
    }

    /// Generate and prove a [`MerkleCellTree`] encoding the content of the
    /// given slots for the contract located at `contract_address`.
    pub async fn proven_celltree_for_slots(
        &self,
        contract_address: &str,
        slots: &[u8],
    ) -> MerkleCellTree {
        let row = self.build_row(contract_address, slots).await;
        let (cell_tree, cell_tree_ut) = build_cell_tree(&row)
            .await
            .expect("failed to create cell tree");
        let proved_hash = self.prove_cell_tree(&cell_tree, cell_tree_ut).await;

        assert_eq!(
            cell_tree.root_hash().unwrap(),
            proved_hash,
            "mismatch between cell tree root hash as computed by ryhope {:?} and mp2 {:?}",
            cell_tree.root_hash().unwrap(),
            proved_hash
        );

        cell_tree
    }
}
