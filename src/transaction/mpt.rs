use std::cmp::Ordering;

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    hash::hash_array,
    rlp::{decode_fixed_list, decode_tuple, extract_array},
    utils::convert_u8_to_u32,
    ProofTuple,
};

use super::PACKED_HASH_LEN;

/// The maximum length of a RLP encoded leaf node in a MPT tree holding a legacy tx.
pub(crate) const MAX_LEGACY_TX_NODE_LENGTH: usize = 532;
/// The maximum size a RLP encoded legacy tx can take. This is different from
/// `LEGACY_TX_NODE_LENGTH` because the latter contains the key in the path
/// as well.
pub(crate) const MAX_LEGACY_TX_LENGTH: usize = 532;
/// Maximum size the gas value can take in bytes.
pub(crate) const MAX_GAS_VALUE_LEN: usize = 32;

/// Size of an intermediate (branch or leaf) node in the MPT trie.
/// A branch node can take up to 17*32 = 544 bytes.
pub(crate) const MAX_INTERMEDIATE_NODE_LENGTH: usize = 544;

/// Length of a "key" (a hash) in the MPT trie.
const HASH_LENGTH: usize = 32;

/// There are different ways to extract values from a transaction. This enum
/// list some.
pub(crate) enum ExtractionMethod {
    /// RLPBased decodes each header consecutively and extract the gas value
    /// TODO: Currently hardcode that the gas value is 3rd item in the tx list
    /// because we use const generics and can't pass the index as a parameter.
    RLPBased,
    /// Directly reads at the specified offset.
    /// Offset of the item in the tx list - length is assumed to be constant
    /// OffsetBased is NOT secure, it is only useful for testing & quick prototyping purposes.
    OffsetBased(usize),
}

struct NodeProofInputs<'a, X> {
    elems: &'a [X],
}

impl<'a, X> NodeProofInputs<'a, X> {
    fn new(elems: &'a [X]) -> Result<Self> {
        // at least one element of computation output
        if elems.len() < PACKED_HASH_LEN + 1 {
            return Err(anyhow::anyhow!(
                "NodeProofInputs: elems length is too small"
            ));
        }
        Ok(Self { elems })
    }

    fn hash(&self) -> &'a [X] {
        &self.elems[0..PACKED_HASH_LEN]
    }
    // NOTE: TODO: should make a wrapper on top to provide specific interpretation
    // of the output
    fn outputs(&self) -> &'a [X] {
        &self.elems[PACKED_HASH_LEN..]
    }
}

impl<'a> NodeProofInputs<'a, Target> {
    fn register_inputs<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        hash: &[Target],
        outputs: &[Target],
    ) {
        b.register_public_inputs(hash);
        b.register_public_inputs(outputs);
    }
}

/// Provides a proof for a leaf node in a MPT tree holding a legacy tx. It exposes
/// the hash of the node as public input, as well as the gas value of the tx.
pub fn legacy_tx_leaf_node_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
    mut node: Vec<u8>,
    extract: ExtractionMethod,
) -> Result<ProofTuple<F, C, D>> {
    let mut b = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let node_length = node.len();
    node.resize(MAX_LEGACY_TX_NODE_LENGTH, 0);
    let node_targets = b.add_virtual_targets(MAX_LEGACY_TX_NODE_LENGTH);

    // Witness assignement
    for i in 0..MAX_LEGACY_TX_NODE_LENGTH {
        pw.set_target(node_targets[i], F::from_canonical_u8(node[i]));
    }

    // Hash computation and exposing as public input
    let length_target = b.add_virtual_target();
    pw.set_target(length_target, F::from_canonical_usize(node_length));
    let hash = hash_array(&mut b, &mut pw, &node_targets, length_target, node_length);

    // Gas value extraction and exposing as public input
    let gas_value_array = match extract {
        // gas is at 3rd position
        ExtractionMethod::RLPBased => {
            extract_item_from_tx_list::<F, D, 3, MAX_GAS_VALUE_LEN>(&mut b, &node_targets)
        }
        ExtractionMethod::OffsetBased(offset) => {
            // NOTE: It does NOT guarantee the offset is _correct_. The prover CAN give
            // any offset within the given slice that has been hashed, and claim it is
            // the gas value.
            let gas_offset_target = b.add_virtual_target();
            pw.set_target(gas_offset_target, F::from_canonical_usize(offset));
            extract_array::<F, D, MAX_GAS_VALUE_LEN>(&mut b, &node_targets, gas_offset_target)
        }
    };
    // maximum length that the RLP(gas) == RLP(U256) can take:
    // * 32 bytes for the value (U256 = 32 bytes)
    // TODO: pack the gas value into U32Target - more compact
    NodeProofInputs::register_inputs(&mut b, &hash, &gas_value_array);

    // proving part
    let data = b.build::<C>();
    let proof = data.prove(pw)?;

    Ok((proof, data.verifier_only, data.common))
}

pub fn recursive_node_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
    mut node: Vec<u8>,
    inner_proofs: &[ProofTuple<F, InnerC, D>],
    hash_offsets: &[usize],
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let node_length = node.len();
    node.resize(MAX_INTERMEDIATE_NODE_LENGTH, 0);
    assert_ne!(inner_proofs.len(), 0);
    assert_eq!(inner_proofs.len(), hash_offsets.len());
    assert!(node_length <= MAX_INTERMEDIATE_NODE_LENGTH);

    let mut b = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let offset_targets = b.add_virtual_targets(hash_offsets.len());
    let node_targets = b.add_virtual_targets(MAX_INTERMEDIATE_NODE_LENGTH);
    let length_target = b.add_virtual_target();

    pw.set_target(length_target, F::from_canonical_usize(node_length));
    for (offset_tgt, offset) in offset_targets.iter().zip(hash_offsets) {
        pw.set_target(*offset_tgt, F::from_canonical_u32(*offset as u32));
    }
    for i in 0..MAX_INTERMEDIATE_NODE_LENGTH {
        pw.set_target(node_targets[i], F::from_canonical_u8(node[i]));
    }

    // Hash the RLP encoding and expose the hash of this node
    let hash = hash_array(&mut b, &mut pw, &node_targets, length_target, node_length);

    // verify all children proofs.
    // TODO: make it constant size
    // TODO: allow giving dumb proofs to be able to select which children to verify
    // for some cases we don't need to verify all of them
    verify_children_proofs(
        &mut b,
        &mut pw,
        &node_targets,
        &offset_targets,
        inner_proofs,
    );

    // TODO: gas extraction and reduction
    NodeProofInputs::register_inputs(&mut b, &hash, &[b.one()]);

    let data = b.build::<C>();
    let proof = data.prove(pw)?;

    Ok((proof, data.verifier_only, data.common))
}

/// verify each inner proof - can be up to 16 if a branch node is full
pub(super) fn verify_children_proofs<
    F: RichField + Extendable<D>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    b: &mut CircuitBuilder<F, D>,
    pw: &mut PartialWitness<F>,
    node_targets: &[Target],
    offset_targets: &[Target],
    inner_proofs: &[ProofTuple<F, InnerC, D>],
) where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    for (offset, prooft) in offset_targets.iter().zip(inner_proofs.iter()) {
        let children_hash = extract_array::<F, D, HASH_LENGTH>(b, node_targets, *offset);
        // connect the lookup hash to the proof hash
        // hash is exposed as 8 target elements so need to convert from u8 array to u32
        // 32 bytes hash output = 256 bits = 32 bits * 8 => 8 u32 targets exposed
        let extracted_hash = convert_u8_to_u32(b, &children_hash);
        let (inner_proof, inner_vd, inner_cd) = prooft;
        let pt = b.add_virtual_proof_with_pis(inner_cd);
        pw.set_proof_with_pis_target(&pt, inner_proof);

        // nikko: historically been done like this - we could just connect the extract hash directly
        extracted_hash
            .iter()
            .zip(pt.public_inputs[0..8].iter())
            .for_each(|(l, r)| {
                b.connect(l.0, *r);
            });

        let inner_data = b.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);
        // nikko: XXX WHy do we need these two lines ?
        // In plonky2 benchmarks they dont use it but if we remove them from here
        // it just fails
        // See https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/examples/bench_recursion.rs#L212-L217
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);
        b.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    }
}
/// Reads the header of the RLP node, then reads the header of the TX item
/// then reads all headers of the items in the list until it reaches the given
/// header at position N. It reads that header and returns the offset from the array
/// where the data is starting
fn extract_item_from_tx_list<
    F: RichField + Extendable<D>,
    const D: usize,
    const N_FIELDS: usize,
    const MAX_VALUE_SIZE: usize,
>(
    b: &mut CircuitBuilder<F, D>,
    node: &[Target],
    // TODO: make that const generic
) -> [Target; MAX_VALUE_SIZE] {
    // First, decode headers of RLP ( RLP (key), RLP(tx) )
    let tuple_headers = decode_tuple(b, node);
    let rlp_tx_index = 1;
    // extract the RLP(tx) from the node encoding
    let tx_offset = tuple_headers.offset[rlp_tx_index];
    let rlp_tx = extract_array::<F, D, MAX_LEGACY_TX_LENGTH>(b, node, tx_offset);

    // then extract the gas fees: it's the third item in the tx list (out of 9 for legacy tx)
    // NOTE: we should only decode the things we need, so for example here
    // the gas fee is at the 3rd position then we only need to decode up to the 3rd
    // headers in the list and keep the rest untouched. However, later user query might
    // want the whole thing.
    let tx_list = decode_fixed_list::<F, D, N_FIELDS>(b, &rlp_tx);
    let item_index = N_FIELDS - 1;
    let item_offset = tx_list.offset[item_index];
    extract_array::<F, D, MAX_VALUE_SIZE>(b, &rlp_tx, item_offset)
}

/// Function that returns the offset of the gas value in the RLP encoded
/// node containing a transaction. It also returns the gas length.
pub(super) fn gas_offset_from_rlp_node(node: &[u8]) -> (usize, usize) {
    let node_rlp = rlp::Rlp::new(node);
    let tuple_info = node_rlp.payload_info().unwrap();
    let tuple_offset = tuple_info.header_len;
    assert_eq!(node_rlp.item_count().unwrap(), 2);
    let tx_index = 1;
    let gas_index = 2;
    let mut tx_offset = tuple_offset;
    let mut gas_value_len = 0;
    let mut gas_offset = 0;
    node_rlp.iter().enumerate().for_each(|(i, r)| {
        let h = r.payload_info().unwrap();
        tx_offset += h.header_len;
        match i.cmp(&tx_index) {
            Ordering::Less => tx_offset += h.value_len,
            Ordering::Greater => panic!("node should not have more than 2 items"),
            Ordering::Equal => {
                let tx_rlp = rlp::Rlp::new(r.data().unwrap());
                gas_offset += tx_rlp.payload_info().unwrap().header_len;
                tx_rlp.iter().enumerate().for_each(|(j, rr)| {
                    let hh = rr.payload_info().unwrap();
                    match j.cmp(&gas_index) {
                        Ordering::Less => {
                            gas_offset += hh.header_len;
                            gas_offset += hh.value_len;
                        }
                        // do nothing as we don't care about the other items
                        Ordering::Greater => {}
                        Ordering::Equal => {
                            // we want the value directly - we skip the header
                            gas_offset += hh.header_len;
                            gas_value_len = hh.value_len;
                        }
                    }
                });
            }
        }
    });
    (tx_offset + gas_offset, gas_value_len)
}
#[cfg(test)]
mod test {
    use anyhow::Result;
    use ethers::types::Transaction;
    use plonky2::field::extension::Extendable;
    use plonky2::hash::hash_types::RichField;
    use plonky2::plonk::config::AlgebraicHasher;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, VerifierCircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rlp::{Decodable, Encodable, Rlp};
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    const STRING: usize = 0;
    const LIST: usize = 1;

    use super::{gas_offset_from_rlp_node, recursive_node_proof, MAX_LEGACY_TX_NODE_LENGTH};
    use crate::hash::hash_to_fields;
    use crate::rlp::{decode_header, decode_tuple};
    use crate::utils::find_index_subvector;
    use crate::utils::test::{data_to_constant_targets, hash_output_to_field};
    use crate::utils::{keccak256, test::connect};
    use crate::ProofTuple;

    use super::{legacy_tx_leaf_node_proof, ExtractionMethod};

    #[test]
    fn test_legacy_full_proof() -> Result<()> {
        run_legacy_mpt_proof::<F, C, D>()
    }
    fn run_legacy_mpt_proof<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >() -> Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let mpt_proof_hex = ["f851a098f3110a26a9ee7d32d5da055ebd725f09d6b5223aaa66a1f46382262830895680808080808080a00e6e346926890fbe0443125f7eed828ab63e0f4ebcd37722254eb097bac002528080808080808080","f87180a02675bad1a2403f7724522e6105b2279e66791dcd4a8a2165480b199d4cea6594a0fed7ac70c74e6148971bca70502ce65d28fd4060d8d4fa3acb29a5f84faff324a07f009b48d17653d95d8fd7974e26e03083d84f6a1262d03c076b272f545af3e580808080808080808080808080","f87420b871f86f826b2585199c82cc0083015f9094e955ede0a3dbf651e2891356ecd0509c1edb8d9c8801051fdc4efdc0008025a02190f26e70a82d7f66354a13cda79b6af1aa808db768a787aeb348d425d7d0b3a06a82bd0518bc9b69dc551e20d772a1b06222edfc5d39b6973e4f4dc46ed8b196"];
        let mpt_proof = mpt_proof_hex
            .iter()
            .map(|hex| hex::decode(hex).unwrap())
            .collect::<Vec<_>>();
        let root_hash_hex = "ab41f886be23cd786d8a69a72b0f988ea72e0b2e03970d0798f5e03763a442cc";
        let root_hash = hex::decode(root_hash_hex).unwrap();
        let config = CircuitConfig::standard_recursion_config();

        let mut last_proof = None;
        let mut last_hash = vec![];
        for (i, node) in mpt_proof.into_iter().rev().enumerate() {
            let node_hash = keccak256(&node);
            let proof = if i == 0 {
                legacy_tx_leaf_node_proof::<F, C, D>(&config, node, ExtractionMethod::RLPBased)?
            } else {
                let hash_offset = find_index_subvector(&node, &last_hash).unwrap();
                let p = last_proof.unwrap();
                recursive_node_proof(&config, node, &[p], &[hash_offset])?
            };

            let vcd = VerifierCircuitData {
                verifier_only: proof.1.clone(),
                common: proof.2.clone(),
            };
            println!("[+] Proof index {} computed", i);
            vcd.verify(proof.0.clone())?;
            println!("[+] Proof index {} verified", i);
            let expected_hash = hash_output_to_field::<F>(&node_hash);
            let proof_hash = &proof.0.public_inputs[0..8];
            assert!(expected_hash == proof_hash, "hashes not equal?");

            last_proof = Some(proof);
            last_hash = node_hash;
        }
        assert_eq!(last_hash, root_hash);
        Ok(())
    }
    fn run_leaf_proof_test<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
        Circuit,
    >(
        circuit: Circuit,
    ) -> Result<()>
    where
        Circuit: FnOnce(&CircuitConfig, &[u8]) -> Result<ProofTuple<F, C, D>>,
    {
        // The following test data comes from:
        // ```
        //     let block_number = 10593417;
        //     let tx_index = U64::from(3);
        // ```
        let leaf_node_hex= "f87420b871f86f826b2585199c82cc0083015f9094e955ede0a3dbf651e2891356ecd0509c1edb8d9c8801051fdc4efdc0008025a02190f26e70a82d7f66354a13cda79b6af1aa808db768a787aeb348d425d7d0b3a06a82bd0518bc9b69dc551e20d772a1b06222edfc5d39b6973e4f4dc46ed8b196";
        let leaf_node_buff = hex::decode(leaf_node_hex).unwrap();
        let node_hash = keccak256(&leaf_node_buff);
        let tx_hex = "f86f826b2585199c82cc0083015f9094e955ede0a3dbf651e2891356ecd0509c1edb8d9c8801051fdc4efdc0008025a02190f26e70a82d7f66354a13cda79b6af1aa808db768a787aeb348d425d7d0b3a06a82bd0518bc9b69dc551e20d772a1b06222edfc5d39b6973e4f4dc46ed8b196";
        let tx_buff = hex::decode(tx_hex).unwrap();
        let tx = Transaction::decode(&Rlp::new(&tx_buff)).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let leaf_proof = circuit(&config, &leaf_node_buff)?;
        let vcd = VerifierCircuitData {
            verifier_only: leaf_proof.1.clone(),
            common: leaf_proof.2.clone(),
        };

        vcd.verify(leaf_proof.0.clone())?;
        // verify hash of the node
        let expected_hash = hash_to_fields::<F>(&node_hash);
        let proof_hash = &leaf_proof.0.public_inputs[0..8];
        assert!(expected_hash == proof_hash, "hashes not equal?");
        // verify gas value
        let gas_buff = tx.gas.rlp_bytes();
        let gas_rlp = rlp::Rlp::new(&gas_buff);
        let gas_header = gas_rlp.payload_info()?;
        let gas_value = gas_rlp.data().unwrap().to_vec();
        assert_eq!(
            &leaf_proof.0.public_inputs[8..8 + gas_header.value_len],
            gas_value
                .iter()
                .take(gas_header.value_len)
                .map(|byte| F::from_canonical_u8(*byte))
                .collect::<Vec<_>>()
                .as_slice()
        );
        Ok(())
    }
    #[test]
    fn test_legacy_tx_leaf_proof_rlp_extract() -> Result<()> {
        run_leaf_proof_test(|c, n| {
            legacy_tx_leaf_node_proof::<F, C, D>(c, n.to_vec(), ExtractionMethod::RLPBased)
        })
    }
    #[test]
    fn test_legacy_tx_leaf_proof_offset() -> Result<()> {
        run_leaf_proof_test(|c, n| {
            let (gas_offset, _) = gas_offset_from_rlp_node(n);
            legacy_tx_leaf_node_proof::<F, C, D>(
                c,
                n.to_vec(),
                ExtractionMethod::OffsetBased(gas_offset),
            )
        })
    }
    #[test]
    fn test_rlp_mpt_node_list() -> Result<()> {
        // come from last tx in block 10593417, leaf node for tx idx 03 in the MPT
        let data_str = "f87420b871f86f826b2585199c82cc0083015f9094e955ede0a3dbf651e2891356ecd0509c1edb8d9c8801051fdc4efdc0008025a02190f26e70a82d7f66354a13cda79b6af1aa808db768a787aeb348d425d7d0b3a06a82bd0518bc9b69dc551e20d772a1b06222edfc5d39b6973e4f4dc46ed8b196";
        let mut data = hex::decode(data_str).unwrap();
        assert!(data.len() > 55);

        let r = rlp::Rlp::new(&data);
        let prototype = r.prototype().expect("error reading prototype");
        assert!(
            matches!(prototype, rlp::Prototype::List(2)),
            "prototype is {:?}",
            prototype
        );
        let header = r.payload_info().expect("can't get payload info");
        let key_rlp = r.at(0).expect("can't get key rlp");
        let value_rlp = r.at(1).expect("can't get value rlp");
        let key_header = key_rlp.payload_info().expect("can't get key payload info");
        let value_header = value_rlp
            .payload_info()
            .expect("can't get value payload info");
        assert!(key_header.header_len == 0); // this is short value so directly single byte! 0x20
        assert!(key_header.value_len > 0); // there is a value to be read
        assert!(value_header.header_len > 0); // tx is more than 55 bytes long
        assert!(key_header.value_len > 0);

        // check total value checks out for sub items length
        let computed_len = header.header_len
            + key_header.value_len
            + value_header.value_len
            + key_header.header_len
            + value_header.header_len;
        // add redundant header_len to mimick the circuit function
        assert!(header.value_len + header.header_len == computed_len);

        let config = CircuitConfig::standard_recursion_config();

        let mut pw = PartialWitness::new();
        let mut b = CircuitBuilder::<F, D>::new(config);

        // before transforming to targets, we pad to constant size so circuit always work for different sizes
        // Note we can't do it when reading rlp data offcircuit because rlp library continues to read until the
        // end of the array so it's not gonna be a list(2) anymore but much longer list.
        data.resize(MAX_LEGACY_TX_NODE_LENGTH, 0);
        let node_targets = data_to_constant_targets(&mut b, &data);

        // check the header of the list is correctly decoded
        let rlp_header = decode_header(&mut b, &node_targets);
        connect(&mut b, &mut pw, rlp_header.offset, header.header_len as u32);
        connect(&mut b, &mut pw, rlp_header.len, header.value_len as u32);
        // it's a list so type = 1
        connect(&mut b, &mut pw, rlp_header.data_type, LIST as u32);

        // decode all the sub headers now, we know there are only two
        let rlp_list = decode_tuple(&mut b, &node_targets);
        // check the first sub header which is the key of the MPT leaf node
        // value of the key header starts after first header and after header of the key item
        let expected_key_value_offset = key_header.header_len + header.header_len;

        connect(
            &mut b,
            &mut pw,
            rlp_list.offset[0],
            expected_key_value_offset as u32,
        );
        connect(&mut b, &mut pw, rlp_list.data_type[0], STRING as u32);
        connect(
            &mut b,
            &mut pw,
            rlp_list.len[0],
            key_header.value_len as u32,
        );
        // check the second sub header which is the key of the MPT leaf node
        // value starts after first header, after key header, after key value and after value header
        let expected_value_value_offset = value_header.header_len
            + key_header.header_len
            + key_header.value_len
            + header.header_len;
        connect(
            &mut b,
            &mut pw,
            rlp_list.offset[1],
            expected_value_value_offset as u32,
        );
        connect(&mut b, &mut pw, rlp_list.data_type[1], STRING as u32);
        connect(
            &mut b,
            &mut pw,
            rlp_list.len[1],
            value_header.value_len as u32,
        );

        let data = b.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
