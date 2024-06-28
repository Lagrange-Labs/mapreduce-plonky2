use ethers::types::{Address, U256};
use mp2_common::{
    eth::ProofQuery, poseidon::empty_poseidon_hash, proof::ProofWithVK, utils::ToFields, F,
};
use mp2_v1::values_extraction::compute_leaf_single_id;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
};
use ryhope::{
    hasher::TreeHasher,
    storage::{memory::InMemory, EpochKvStorage, TreeTransactionalStorage},
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

        hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&fs)
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

pub async fn build_cell_tree(row: &Row) -> MerkleCellTree {
    let mut cell_tree = MerkleCellTree::create((0, 0), ()).unwrap();
    cell_tree
        .start_transaction()
        .expect("while opening cell tree");
    for (i, (identifier, value)) in row.cells.iter().enumerate() {
        cell_tree
            // SBBST starts at 1, not 0. Note though this index is not important
            // since at no point we are looking up value per index in the cells
            // tree we always look at the entire row at the row tree level.
            .store(i + 1, (identifier.to_owned(), value.to_owned()))
            .expect("while inserting nodes in cell tree");
    }
    cell_tree
        .commit_transaction()
        .expect("while building cell tree");

    cell_tree
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
    pub async fn prove_cell_tree(&self, t: &MerkleCellTree) -> HashOut<F> {
        fn rec_prove(
            ctx: &TestContext,
            t: &MerkleCellTree,
            current: <CellTree as TreeTopology>::Key,
        ) -> Vec<u8> {
            let (context, (identifier, value)) = t.fetch_with_context(&current);

            if context.is_leaf() {
                // Prove a leaf
                let inputs = CircuitInput::CellsTree(
                    verifiable_db::cells_tree::CircuitInput::new_leaf(identifier, value),
                );
                ctx.params()
                    .zkdb
                    .generate_proof(inputs)
                    .expect("while proving leaf")
            } else if context.right.is_none() {
                // Prove a partial node
                let left_proof = rec_prove(ctx, t, context.left.unwrap());
                let inputs = CircuitInput::CellsTree(
                    verifiable_db::cells_tree::CircuitInput::new_partial_node(
                        identifier, value, left_proof,
                    ),
                );
                ctx.params()
                    .zkdb
                    .generate_proof(inputs)
                    .expect("while proving partial node")
            } else {
                // Prove a partial node. Since the tree is SBBST, by
                // construction, there is only one case possible for the order
                // of the child when there is onle one: child is always the left
                // child.
                let left_proof = rec_prove(ctx, t, context.left.unwrap());
                let right_proof = rec_prove(ctx, t, context.right.unwrap());
                let inputs = CircuitInput::CellsTree(
                    verifiable_db::cells_tree::CircuitInput::new_full_node(
                        identifier,
                        value,
                        [left_proof, right_proof],
                    ),
                );
                ctx.params()
                    .zkdb
                    .generate_proof(inputs)
                    .expect("while proving full node")
            }
        }

        let root = t.tree().root().unwrap();
        let root_proof = rec_prove(self, t, root);
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
        let cell_tree = build_cell_tree(&row).await;
        let proved_hash = self.prove_cell_tree(&cell_tree).await;

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
