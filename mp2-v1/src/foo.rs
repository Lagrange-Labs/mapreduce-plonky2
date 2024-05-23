use mp2_common::{
    array::Vector,
    mpt_sequential::{
        MPTLeafOrExtensionNode, MPTLeafOrExtensionWires, MAX_LEAF_VALUE_LEN, PAD_LEN,
    },
    storage_key::{SimpleSlot, SimpleSlotWires},
    types::{CBuilder, GFp},
    D,
};
use plonky2::{field::types::Field, iop::witness::PartialWitness};

const NODE_LEN: usize = 532;

#[derive(Debug, Clone)]
pub struct FooWires {
    pub slot: SimpleSlotWires,
    pub mpt: MPTLeafOrExtensionWires<NODE_LEN, MAX_LEAF_VALUE_LEN>,
}

#[derive(Debug, Clone)]
pub struct FooCircuit {
    pub slot: SimpleSlot,
    pub node: Vector<u8, { PAD_LEN(NODE_LEN) }>,
}

#[cfg(test)]
impl mp2_test::circuit::UserCircuit<GFp, D> for FooCircuit {
    type Wires = FooWires;

    fn build(cb: &mut CBuilder) -> Self::Wires {
        let slot = SimpleSlot::build(cb);
        let mpt = MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
            cb,
            &slot.mpt_key,
        );

        mpt.value.register_as_public_input(cb);

        FooWires { slot, mpt }
    }

    fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
        self.slot.assign(pw, &wires.slot);
        wires.mpt.assign(pw, &self.node);
    }
}

#[test]
fn xxxyyy() {
    use eth_trie::Trie;

    let slot = 118;
    let key = [
        181, 115, 39, 5, 245, 36, 19, 112, 162, 137, 8, 194, 254, 19, 3, 203, 34, 63, 3, 185, 13,
        133, 127, 208, 87, 63, 0, 63, 121, 254, 254, 212,
    ];
    let value = [132, 255, 255, 255, 255];
    let key_p = [
        181, 115, 39, 5, 245, 36, 19, 112, 162, 137, 8, 194, 254, 19, 3, 203, 34, 63, 3, 185, 13,
        133, 127, 208, 87, 63, 0, 63, 121, 254, 254, 84,
    ];
    let value_p = [132, 0, 0, 0, 255];

    let memdb = std::sync::Arc::new(eth_trie::MemoryDB::new(true));
    let mut trie = eth_trie::EthTrie::new(std::sync::Arc::clone(&memdb));

    trie.insert(&key, &value).unwrap();

    // !!!! Comment this line to make the test pass
    trie.insert(&key_p, &value_p).unwrap();

    trie.root_hash().unwrap();

    let node = trie.get_proof(&key).unwrap().last().unwrap().clone();
    let circuit = FooCircuit {
        slot: SimpleSlot::new(slot),
        node: Vector::from_vec(&node).unwrap(),
    };

    let pi = mp2_test::circuit::run_circuit::<
        _,
        D,
        plonky2::plonk::config::PoseidonGoldilocksConfig,
        _,
    >(circuit)
    .public_inputs;

    let value: Vec<_> = value.into_iter().map(GFp::from_canonical_u8).collect();

    assert_eq!(&value, &pi[..value.len()]);
}
