use crate::{
    array::{Vector, VectorWire},
    utils::{find_index_subvector, keccak256},
};
use anyhow::{anyhow, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::keccak::{compute_size_with_padding, KeccakCircuit, OutputHash};

/// a simple alias to keccak::compute_size_with_padding to make the code a bit
/// more tiny with all these const generics
#[allow(non_snake_case)]
const fn PADDING_LEN(d: usize) -> usize {
    compute_size_with_padding(d)
}
/// Circuit that simoply proves the inclusion of a value inside a MPT tree.
/// * DEPTH is the maximal depth of the tree. If the tree is smaller, the circuit
/// will continue proving for "imaginary" nodes
/// * NODE_LEN is the max length of a node in the list of MPT nodes that form
/// the MPT proof. For example, in storage trie, a leaf is 32 bytes max, and a
/// branch node can be up to 32 * 17 = 544 bytes.
///     - Note since it uses keccak, the array being hashed is larger because
/// keccak requires padding.
#[derive(Clone, Debug)]
struct Circuit<const DEPTH: usize, const NODE_LEN: usize> {
    /// for ease of usage, we take vector here and the circuit is doing the padding
    nodes: Vec<Vec<u8>>,
}

struct Wires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PADDING_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// a vector of buffers whose size is the padded size of the maximum node length
    /// the padding may occur anywhere in the array but it can fit the maximum node size
    /// NOTE: this makes the code a bit harder grasp at first, but it's a straight
    /// way to define everything according to max size of the data and
    /// "not care" about the padding size (almost!)
    nodes: [VectorWire<{ PADDING_LEN(NODE_LEN) }>; DEPTH],

    /// in the case of a fixed circuit, the actual tree depth might be smaller.
    /// In this case, we set false on the part of the path we should not process.
    /// NOTE: for node at index i in the path, the boolean indicating if we should
    /// process it is at index i-1
    should_process: [BoolTarget; DEPTH - 1],
    /// At each intermediate node up to the root, we should find the hash of the children
    /// in its byte representation. That array indicates where the hash is located in the
    /// node.
    /// NOTE: for node at index  i in the path, the index where to find the children hash is
    /// located at index i-1.
    child_hash_index: [Target; DEPTH - 1],
}

impl<const DEPTH: usize, const NODE_LEN: usize> Circuit<DEPTH, NODE_LEN>
where
    [(); PADDING_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
    // bound required from keccak
    [(); PADDING_LEN(NODE_LEN) / 4]:,
{
    pub fn new(nodes: Vec<Vec<u8>>) -> Self {
        Self { nodes }
    }
    /// Build the sequential hashing of nodes. It returns the wires that contains
    /// the root hash (according to the "should_process" array) and the wires
    /// to assign during proving time, including each of the nodes in the path.
    pub fn build<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
    ) -> (OutputHash, Wires<DEPTH, NODE_LEN>)
    where
        F: RichField + Extendable<D>,
    {
        let should_process: [BoolTarget; DEPTH - 1] =
            core::array::from_fn(|_| b.add_virtual_bool_target_safe());
        let index_hashes: [Target; DEPTH - 1] = core::array::from_fn(|_| b.add_virtual_target());
        // nodes should be ordered from leaf to root and padded at the end
        let nodes: [VectorWire<_>; DEPTH] = (0..DEPTH)
            .map(|_| VectorWire::<{ PADDING_LEN(NODE_LEN) }>::new(b))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // hash the leaf first
        let mut last_hash_output =
            KeccakCircuit::<{ PADDING_LEN(NODE_LEN) }>::hash_vector(b, &nodes[0]).output_array;
        let t = b._true();
        // we skip the first node which is the leaf
        for i in 1..DEPTH {
            let is_real = should_process[i - 1];
            // hash the next node first. We do this so we can get the U32 equivalence of the node
            let hash_wires = KeccakCircuit::<{ PADDING_LEN(NODE_LEN) }>::hash_vector(b, &nodes[i]);
            // look if hash is inside the node (in u32 format)
            let at = index_hashes[i - 1];
            let found_hash_in_parent = hash_wires
                .padded_u32 // this is the node but in u32 format
                .contains_array(b, &last_hash_output, at);

            // if we don't have to process it, then circuit should never fail at that step
            // otherwise, we should always enforce finding the hash in the parent node
            let is_parent = b.select(is_real, found_hash_in_parent.target, t.target);
            b.connect(is_parent, t.target);

            // and select whether we should update or not
            last_hash_output = hash_wires
                .output_array
                .select(is_real, &last_hash_output, b);
        }
        (
            last_hash_output,
            Wires {
                nodes,
                should_process,
                child_hash_index: index_hashes,
            },
        )
    }

    /// Assign the nodes to the wires, assign which nodes in the full length array
    /// should we look at (i.e. padding), and the indices where to find the children
    /// hash in the parent hashes.
    fn assign<F: RichField + Extendable<D>, const D: usize>(
        &self,
        p: &mut PartialWitness<F>,
        wires: &Wires<DEPTH, NODE_LEN>,
    ) -> Result<()> {
        // convert nodes to array and pad with empty array if needed
        for i in 0..DEPTH {
            let node = if i < self.nodes.len() {
                p.set_bool_target(wires.should_process[i], true);
                self.nodes[i].clone()
            } else {
                p.set_bool_target(wires.should_process[i], false);
                vec![]
            };
            let padded_vector = Vector::<{ PADDING_LEN(NODE_LEN) }>::from_vec(node)?;
            wires.nodes[i].assign(p, &padded_vector);
        }
        // find the index of the child hash in the parent nodes for all nodes in the path
        for i in 1..self.nodes.len() {
            let child_hash = keccak256(&self.nodes[i - 1]);
            let idx = find_index_subvector(&self.nodes[i], &child_hash)
                .ok_or(anyhow!("can't find hash in parent node!"))?;
            p.set_target(wires.child_hash_index[i - 1], F::from_canonical_usize(idx));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Trie};
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};

    use crate::{
        array::VectorWire,
        circuit::{test::test_simple_circuit, UserCircuit},
        keccak::OutputHash,
    };

    use super::{Circuit, Wires, PADDING_LEN};
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestCircuit<const DEPTH: usize, const NODE_LEN: usize> {
        c: Circuit<DEPTH, NODE_LEN>,
        exp_root: [u8; 32],
    }
    impl<F, const D: usize, const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D>
        for TestCircuit<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PADDING_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
        [(); PADDING_LEN(NODE_LEN) / 4]:,
    {
        type Wires = (OutputHash, Wires<DEPTH, NODE_LEN>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let leaf = VectorWire::<{ PADDING_LEN(NODE_LEN) }>::new(c);
            Circuit::build(c)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.1).unwrap();
        }
    }

    #[test]
    fn test_mpt_proof_verification() {
        // max depth of the trie
        const DEPTH: usize = 5;
        // leave one for padding
        const ACTUAL_DEPTH: usize = DEPTH - 1;
        // max len of a node
        const NODE_LEN: usize = 144;
        // build a random MPT trie
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let mut n: u32 = 1;
        // loop: insert elements as long as a random selected proof is not of the right length
        loop {
            println!("-> Insertion of {} elements so far...", n);
            let key = n.to_le_bytes();
            let random_len = thread_rng().gen_range(64..NODE_LEN);
            let random_bytes = (0..random_len)
                .map(|_| thread_rng().gen::<u8>())
                .collect::<Vec<_>>();
            trie.insert(&key, &random_bytes).expect("can't insert");
            trie.root_hash().expect("root hash problem");
            let proof = trie.get_proof(&key).unwrap();
            if proof.len() >= ACTUAL_DEPTH {
                break;
            }
            n += 1;
        }
        let root = trie.root_hash().unwrap();
        // root is first so we reverse the order as in circuit we prove the opposite way
        let mut proof = trie.get_proof(&n.to_le_bytes()).unwrap();
        proof.reverse();
        // println!(
        //     "first item {:?} vs root {:} vs last item {:?}",
        //     hex::encode(keccak256(proof.first().unwrap())),
        //     hex::encode(root.to_fixed_bytes()),
        //     hex::encode(keccak256(proof.last().unwrap()))
        // );
        let circuit = TestCircuit::<DEPTH, NODE_LEN> {
            c: Circuit::<DEPTH, NODE_LEN>::new(proof),
            exp_root: root.to_fixed_bytes(),
        };
        test_simple_circuit::<F, D, C, _>(circuit);
    }
}
