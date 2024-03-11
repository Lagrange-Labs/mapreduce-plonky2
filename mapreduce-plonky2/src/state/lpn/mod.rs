//! Circuit to prove the correct formation of the leaf node and its intermediate nodes that
//! describes a Merkle opening.

use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};

use crate::{
    array::Array,
    keccak::OutputHash,
    state::BlockLinkingPublicInputs,
    utils::{AddressTarget, ADDRESS_LEN},
};

mod public_inputs;

/// The wires structure of [LeafCircuit].
#[derive(Clone, Debug)]
pub struct LeafWires {
    preimage_a: AddressTarget,
    preimage_c: HashOutTarget,
    preimage_s: U32Target,
    preimage_m: U32Target,
    root: HashOutTarget,
    block_header: OutputHash,
    block_number: U32Target,
    prev_block_header: OutputHash,
}

/// Circuit to prove the correct formation of the leaf node.
///
/// Will take the [BlockLinkingPublicInputs] as argument.
///
/// # Circuit description
///
/// +--------------------------------------+
/// | block linking.smart contract address +---------+
/// +--------------------------------------+         |
/// +---------------------------------------------+  |
/// | block linking.merkle root of the storage db +--|-+
/// +---------------------------------------------+  | |
/// +------------------------------------------+     | |
/// | block linking.storage slot of the length +-----|-|-+
/// +------------------------------------------+     | | |
/// +-------------------------------------------+    | | |
/// | block linking.storage slot of the mapping +----|-|-|-+
/// +-------------------------------------------+    | | | |
/// +--------------------------+                     | | | |
/// | block linking.block hash +----------+          | | | |
/// +--------------------------+          |          | | | |
/// +----------------------------+        |          | | | |
/// | block linking.block number +--------|-+        | | | |
/// +----------------------------+        | |        | | | |
/// +-----------------------------------+ | |        | | | |
/// | block linking.previous block hash +-|-|-+      | | | |
/// +-----------------------------------+ | | |      | | | |
///                                       | | |      | | | |
/// +----------------+                    | | |      | | | |
/// | leaf.node root +--------------------------+H(1,+,+,+,+)
/// +----------------+                    | | |
/// +-----------------+                   | | |
/// | leaf.block hash +-------------------+ | |
/// +-----------------+                     | |
/// +-------------------+                   | |
/// | leaf.block number +-------------------+ |
/// +-------------------+                     |
/// +--------------------------+              |
/// | leaf.previous block hash +--------------+
/// +--------------------------+
pub struct LeafCircuit<'a, F>
where
    F: Clone,
{
    block_linking: BlockLinkingPublicInputs<'a, F>,
}

impl<'a, F> LeafCircuit<'a, F>
where
    F: Clone,
{
    /// Composes the circuit structure by assigning the virtual targets and performing the
    /// constraints.
    pub fn build<const D: usize>(b: &mut CircuitBuilder<F, D>) -> LeafWires
    where
        F: RichField + Extendable<D>,
    {
        let preimage_a = Array::new(b);
        let preimage_c = b.add_virtual_hash();
        let preimage_s = b.add_virtual_u32_target();
        let preimage_m = b.add_virtual_u32_target();
        let root = b.add_virtual_hash();
        let block_header = OutputHash::new(b);
        let block_number = b.add_virtual_u32_target();
        let prev_block_header = OutputHash::new(b);

        let wires = LeafWires {
            preimage_a,
            preimage_c,
            preimage_s,
            preimage_m,
            root,
            block_header,
            block_number,
            prev_block_header,
        };

        public_inputs::PublicInputs::register(b, &wires);

        // constrain the merkle root preimage

        // "LEAF", a(address len), c(elements), s(1), m(1)
        let preimage_len = 3 + wires.preimage_c.elements.len() + ADDRESS_LEN;
        let mut preimage = Vec::with_capacity(preimage_len);
        preimage.push(b.one());
        preimage.extend_from_slice(&wires.preimage_a.arr);
        preimage.extend_from_slice(&wires.preimage_c.elements);
        preimage.push(wires.preimage_s.0);
        preimage.push(wires.preimage_m.0);

        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.to_vec());
        root.elements
            .iter()
            .zip(wires.root.elements.iter())
            .for_each(|(r, w)| b.connect(*r, *w));

        wires
    }

    /// Assigns the data of [BlockLinkingPublicInputs] into the circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires)
    where
        F: RichField,
    {
        wires
            .preimage_a
            .arr
            .iter()
            .zip(self.block_linking.a().iter())
            .for_each(|(&t, &v)| pw.set_target(t, v));

        wires
            .preimage_c
            .elements
            .iter()
            .zip(self.block_linking.merkle_root().iter())
            .for_each(|(&t, &v)| pw.set_target(t, v));

        let len = 2
            + self.block_linking.a().len()
            + self.block_linking.merkle_root().len()
            + self.block_linking.s().len();

        let mut node = Vec::with_capacity(len);

        node.push(F::ONE); // "LEAF"
        node.extend_from_slice(self.block_linking.a());
        node.extend_from_slice(self.block_linking.merkle_root());
        node.extend_from_slice(self.block_linking.s());

        // FIXME check if `M` storage slot of the mapping is a single target
        pw.set_target(wires.preimage_s.0, self.block_linking.s()[0]);
        pw.set_target(wires.preimage_m.0, self.block_linking.m()[0]);
        node.push(self.block_linking.m()[0]);

        let root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&node);

        wires
            .root
            .elements
            .iter()
            .zip(root.elements.iter())
            .for_each(|(&t, &v)| pw.set_target(t, v));

        wires
            .block_header
            .arr
            .iter()
            .zip(self.block_linking.block_hash().iter())
            .for_each(|(&t, &v)| pw.set_target(t.0, v));

        pw.set_target(wires.block_number.0, self.block_linking.block_number()[0]);

        wires
            .prev_block_header
            .arr
            .iter()
            .zip(self.block_linking.prev_block_hash().iter())
            .for_each(|(&t, &v)| pw.set_target(t.0, v));
    }
}
