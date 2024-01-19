use anyhow::Result;
use ethers::utils::keccak256;
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
    rlp::extract_array,
    transaction::{
        mpt::{verify_children_proofs, MAX_INTERMEDIATE_NODE_LENGTH},
        HASH_LEN, PACKED_HASH_LEN,
    },
    utils::{convert_u8_to_u32, less_than, IntTargetWriter},
    ProofTuple,
};

/// Maximum length of a RLP encoded header.
/// TODO verify assumption
const MAX_HEADER_LEN: usize = 680;

/// Helper structure to extract the public inputs of the header proof and
/// to insert them when creating an aggregation proof.
pub struct HeaderProofInputs<'a, X> {
    elems: &'a [X],
}

impl<'a, X> HeaderProofInputs<'a, X> {
    pub fn new(elems: &'a [X]) -> Self {
        Self { elems }
    }
    pub fn nb_aggregated(&self) -> &'a X {
        &self.elems[0]
    }
    pub fn previous_hash(&self) -> &'a [X] {
        &self.elems[1..1 + PACKED_HASH_LEN]
    }
    pub fn hash(&self) -> &'a [X] {
        &self.elems[1 + PACKED_HASH_LEN..1 + 2 * PACKED_HASH_LEN]
    }
}
impl<'a> HeaderProofInputs<'a, Target> {
    fn insert<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        nb_aggregated: &Target,
        previous_hash: &[Target],
        hash: &[Target],
    ) {
        b.register_public_input(*nb_aggregated);
        b.register_public_inputs(previous_hash);
        b.register_public_inputs(hash);
    }
}
/// Offset where to find the parent hash of the header in the RLP encoding.
/// Given the parent hash is the first field present in the header, a header
/// is always a "long list" type, and the hash is constant size, then the offset
/// where it starts is always constant as well.
const PARENT_HASH_INDEX: usize = 4;

/// Takes a RLP encoded header, an item to match in the header, and its offset.
/// It
/// * Exposes the hash of the header as a public output
/// * enforces that the given item is at the correct encoded offset in the block for the
/// given length.
/// For example, for verifying a tx root hash, the item is the root hash of the tx trie,
/// the offset is where the hash starts in RLP encoded data.
/// NOTE: this circuit directly reads into the block array to extract the item value
/// and compare it against the one given. This is secure because we rely on the hash
/// of the block to ensure that prover is looking at the right content. The circuit
/// makes sure the offset given is within range of what has been passed to the hashing
/// gadget.
fn prove_header_inclusion<F, const D: usize, const ITEM_LEN: usize>(
    b: &mut CircuitBuilder<F, D>,
    pw: &mut PartialWitness<F>,
    header: &[Target],  // RLP encoding of the header
    header_len: Target, // length of the RLP encoding of the block
    item: &[Target],    // item to match in the block RLP encoding
    item_offset: usize, // offset where to look for the value in block
) where
    F: RichField + Extendable<D>,
{
    // tx root hash verification
    let offset_target = b.add_virtual_target();
    pw.set_target(offset_target, F::from_canonical_usize(item_offset));
    // 10 = 2^1024 -> header should not go above that
    let within_range = less_than(b, offset_target, header_len, 10);
    let t = b._true();
    b.connect(t.target, within_range.target);
    let arr = extract_array::<F, D, ITEM_LEN>(b, header, offset_target);
    // make sure the hash given is correct
    for i in 0..ITEM_LEN {
        b.connect(arr[i], item[i]);
    }
}

/// This function does both the final MPT verification and inclusion in block proof.
/// * It verifies the root node of the MPT (i.e. it hashes the given buffer, and verifies
/// any children proofs given).
/// * It checks the resulting hash is correctly included in the header given (at a given offset).
/// * It hashes the block and exposes the hash as a public input.
/// ITEM_LEN is the length of the item to match in the header - normally to verify
/// the tx root hash for example, it is 32.
/// The public inputs exposed are:
/// [u32, previousHeaderHash, headerHash]
///  * The first u32 represents how many "header proofs" have been aggregated so far. Since
/// this proof is only for one header, this is always 1.
///  * reason for the previous header hash is to allow verification of the sequentiality of
/// the headers when aggregating such proofs later on.
pub(crate) fn mpt_root_in_header<F, C, InnerC, const D: usize>(
    config: &CircuitConfig,
    mut header: Vec<u8>,                       // RLP encoding of the block header
    mut root_node: Vec<u8>,                    // root node to verify
    inner_proofs: &[ProofTuple<F, InnerC, D>], // children proofs
    children_offsets: &[usize],                // where each hash is included in this node
    root_offset: usize,                        // where the root hash is included in the header
) -> Result<ProofTuple<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    InnerC::Hasher: AlgebraicHasher<F>,
{
    assert!(header.len() < MAX_HEADER_LEN);
    let header_len = header.len();
    header.resize(MAX_HEADER_LEN, 0);
    // ------------ node preparation ------------------
    // TODO: this is extracted from mpt.rs
    // --> Refactor this into re-usable code with struct
    let node_length = root_node.len();
    // NOTE: this is a "shortcut" to avoid doing expensive transformation
    // of U32 -> u8. The hashing gadgets packs everything in u32 thus we
    // can simply take this root_hash, convert to u32 (cheap) and compare
    // with the output of the hash gadget.
    let root_hash = keccak256(&root_node);
    root_node.resize(MAX_INTERMEDIATE_NODE_LENGTH, 0);
    //assert_ne!(inner_proofs.len(), 0);
    assert_eq!(inner_proofs.len(), children_offsets.len());
    assert!(node_length <= MAX_INTERMEDIATE_NODE_LENGTH);

    let mut b = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let offset_targets = b.add_virtual_targets(children_offsets.len());
    let node_targets = b.add_virtual_targets(MAX_INTERMEDIATE_NODE_LENGTH);
    let node_len_tgt = b.add_virtual_target();
    let root_hash_target = b.add_virtual_targets(HASH_LEN);

    pw.set_target(node_len_tgt, F::from_canonical_usize(node_length));
    for (offset_tgt, offset) in offset_targets.iter().zip(children_offsets) {
        pw.set_target(*offset_tgt, F::from_canonical_u32(*offset as u32));
    }
    pw.set_int_targets(&node_targets, &root_node);
    pw.set_int_targets(&root_hash_target, &root_hash);

    // ------------ end node preparation ------------------

    // Fill the RLP header bytes
    let header_targets = b.add_virtual_targets(MAX_HEADER_LEN);
    pw.set_int_targets(&header_targets, &header);
    let header_len_tgt = b.add_virtual_target();
    pw.set_target(header_len_tgt, F::from_canonical_usize(header_len));

    // hash the root node and compare with witness given by prover
    // We compare on packed u32 because going from u8 -> u32 is cheap, but reverse
    // is less.
    let packed_root_hash = hash_array(&mut b, &mut pw, &node_targets, node_len_tgt, node_length);
    let exp_packed_root_hash = convert_u8_to_u32(&mut b, &root_hash_target);
    for i in 0..PACKED_HASH_LEN {
        b.connect(packed_root_hash[i], exp_packed_root_hash[i].0);
    }
    // verify any children proofs
    verify_children_proofs(
        &mut b,
        &mut pw,
        &node_targets,
        &offset_targets,
        inner_proofs,
    );
    // prove the root hash is included in the RLP header at the given offset
    prove_header_inclusion::<F, D, HASH_LEN>(
        &mut b,
        &mut pw,
        &header_targets,
        header_len_tgt,
        &root_hash_target, // node hash == root hash in header !
        root_offset,
    );

    // hashing the header & expose public inputs [1, previousHash, hash]
    let hash = hash_array(&mut b, &mut pw, &header_targets, header_len_tgt, header_len);
    // we can directly extract the parent hash without "reading the array in circuit" because attacker won't
    // be able to link the previous header proof with a different hash (which is constrained in the circuit).
    let uncompressed_previous_hash =
        &header_targets[PARENT_HASH_INDEX..PARENT_HASH_INDEX + HASH_LEN];
    let packed_prev_hash = convert_u8_to_u32(&mut b, uncompressed_previous_hash);
    let one = b.one();
    HeaderProofInputs::<Target>::insert(
        &mut b,
        &one,
        &packed_prev_hash.iter().map(|x| x.0).collect::<Vec<_>>(),
        &hash,
    );
    let data = b.build::<C>();
    let proof = data.prove(pw)?;

    Ok((proof, data.verifier_only, data.common))
}

/// Takes N "header" proofs, verifies them, check the sequentiality of the hashes (i.e.
/// proof for block header i+1 has a previous hash equal to the hash in proof block header i).
/// Then it exposes the hash of the smallest height header and the hash of the highest height header
/// as well as the number of aggregated proofs so far.
pub(crate) fn aggregate_sequential_headers<F, C, InnerC, const D: usize, const ARITY: usize>(
    config: &CircuitConfig,
    inner_proofs: &[ProofTuple<F, InnerC, D>],
) -> Result<ProofTuple<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    InnerC::Hasher: AlgebraicHasher<F>,
{
    assert!(inner_proofs.len() == ARITY);
    let mut b = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    // verify all the proofs first
    let mut pts = Vec::new();
    for proof in inner_proofs {
        let (iproof, ivd, icd) = proof;
        let pt = b.add_virtual_proof_with_pis(icd);
        pw.set_proof_with_pis_target(&pt, iproof);
        let inner_data = b.add_virtual_verifier_data(icd.config.fri_config.cap_height);
        pw.set_cap_target(&inner_data.constants_sigmas_cap, &ivd.constants_sigmas_cap);
        pw.set_hash_target(inner_data.circuit_digest, ivd.circuit_digest);
        b.verify_proof::<InnerC>(&pt, &inner_data, icd);
        pts.push(pt);
    }
    // then verify sequentiality of the hashes and extract the number of proofs
    for i in 0..ARITY - 1 {
        let previous_header = &pts[i];
        let next_header = &pts[i + 1];
        // the hash of the previous header
        let previous_hash = &HeaderProofInputs::new(&previous_header.public_inputs).hash();
        // the previous hash field of the current header
        let next_header_prev_hash =
            HeaderProofInputs::new(&next_header.public_inputs).previous_hash();
        for j in 0..PACKED_HASH_LEN {
            b.connect(previous_hash[j], next_header_prev_hash[j]);
        }
    }
    // compute how many proofs have been aggregated up to this point
    let nb_aggregated = pts
        .iter()
        .fold(b.zero(), |acc, pt| b.add(acc, pt.public_inputs[0]));

    // then exposes the hash corresponding to the smallest height headers
    // and then the highest height header hash
    let smallest_hash = HeaderProofInputs::new(&pts[0].public_inputs).hash();
    let largest_hash = HeaderProofInputs::new(&pts[ARITY - 1].public_inputs).hash();
    HeaderProofInputs::insert(&mut b, &nb_aggregated, smallest_hash, largest_hash);

    let data = b.build::<C>();
    let proof = data.prove(pw)?;
    Ok((proof, data.verifier_only, data.common))
}
#[cfg(test)]
mod test {
    use std::time::Instant;

    use anyhow::Result;
    use eth_trie::Trie;
    use ethers::types::{Block, H256, U64};
    use itertools::Itertools;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::RichField;
    use plonky2::plonk::config::AlgebraicHasher;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::RngCore;
    use rlp::Encodable;

    use crate::eth::{BlockData, RLPBlock};
    use crate::transaction::header::{
        mpt_root_in_header, prove_header_inclusion, HeaderProofInputs, HASH_LEN, PACKED_HASH_LEN,
    };
    use crate::utils::test::hash_output_to_field;
    use crate::utils::{find_index_subvector, keccak256, verify_proof_tuple, IntTargetWriter};

    use super::aggregate_sequential_headers;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_header_aggregation() -> Result<()> {
        let create_proof = |nb: usize, prev_hash: &[u32], hash: &[u32]| {
            let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let mut pw = PartialWitness::new();
            let nb_tgt = b.add_virtual_target();
            let prev_hash_tgt = b.add_virtual_targets(PACKED_HASH_LEN);
            let hash_tgt = b.add_virtual_targets(PACKED_HASH_LEN);
            HeaderProofInputs::insert(&mut b, &nb_tgt, &prev_hash_tgt, &hash_tgt);
            pw.set_target(nb_tgt, F::from_canonical_usize(nb));
            pw.set_int_targets(&prev_hash_tgt, prev_hash);
            pw.set_int_targets(&hash_tgt, hash);
            let data = b.build::<C>();
            let proof = data.prove(pw).unwrap();
            (proof, data.verifier_only, data.common)
        };
        const N_PROOFS: usize = 3;
        let hashes = (0..=N_PROOFS)
            .map(|_| {
                (0..PACKED_HASH_LEN)
                    .map(|_| rand::thread_rng().next_u32())
                    .collect::<Vec<_>>()
            })
            .collect_vec();
        let proofs = (0..N_PROOFS)
            .map(|i| create_proof(1, &hashes[i], &hashes[i + 1]))
            .collect_vec();
        let config = CircuitConfig::standard_recursion_config();
        let result = aggregate_sequential_headers::<F, C, C, D, N_PROOFS>(&config, &proofs)?;

        verify_proof_tuple(&result)?;
        Ok(())
    }

    #[tokio::test]
    async fn tx_root_to_header() {
        prove_root_mpt_in_block::<F, C, D>().await.unwrap();
    }

    async fn prove_root_mpt_in_block<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >() -> Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let block_number = 10593417;
        let tx_index = U64::from(3);
        let mut data = BlockData::fetch(block_number).await?;
        let mpt_proof = data.tx_trie.get_proof(&tx_index.rlp_bytes())?;
        let tx_root_hash = data.tx_trie.root_hash()?;
        let header_hash = data.block.hash.unwrap();
        let header_rlp = rlp::encode(&RLPBlock(&data.block)).to_vec();
        // figure out the offset of the previous hash
        let previous_hash = data.block.parent_hash;
        let prev_hash_offset = find_index_subvector(&header_rlp, previous_hash.as_bytes()).unwrap();
        println!("prev hash offset: {}", prev_hash_offset);
        let config = CircuitConfig::standard_recursion_config();
        // directly provides the root node of the tx trie
        let root_node = mpt_proof[0].clone();
        assert!(keccak256(&root_node) == tx_root_hash.as_bytes());
        // find where the tx root hash sits in the block header encoding
        let root_offset = find_index_subvector(&header_rlp, tx_root_hash.as_bytes()).unwrap();
        assert!(&header_rlp[root_offset..root_offset + HASH_LEN] == tx_root_hash.as_bytes());
        // In this test, we "cheat" by giving no proofs for the children of the root node
        // this is tested in other places so test runs faster, no need to prove the whole MPT proof.
        let inner_proofs = vec![];
        let inner_offsets = vec![];
        let start = Instant::now();
        let block_proof = mpt_root_in_header::<F, C, C, D>(
            &config,
            header_rlp,
            root_node,
            &inner_proofs,
            &inner_offsets,
            root_offset,
        )?;
        println!(
            "[+] Block Header Proof computed (in {}s)",
            start.elapsed().as_secs()
        );
        verify_proof_tuple(&block_proof)?;
        println!("[+] Block Header Proof Verified");
        // Verify if public inputs are correctly set:
        // [1, prevHash, hash]
        // TODO: for next version, we put the [height, hash] as public inputs
        let expected_hash = hash_output_to_field::<F>(header_hash.as_bytes());
        let previous_exp_hash = hash_output_to_field::<F>(previous_hash.as_bytes());
        assert_eq!(F::from_canonical_u8(1), block_proof.0.public_inputs[0]);
        assert_eq!(
            previous_exp_hash,
            block_proof.0.public_inputs[1..1 + PACKED_HASH_LEN],
            "prev hashes not equal?"
        );
        assert_eq!(
            expected_hash,
            block_proof.0.public_inputs[1 + PACKED_HASH_LEN..1 + 2 * PACKED_HASH_LEN],
            "hashes not equal?"
        );
        Ok(())
    }

    #[test]
    fn test_header_inclusion_alone() -> Result<()> {
        let block_str = "7b2268617368223a22307834343162636461323939363966653463393437393062383533386237306533306236366336326236396665363531366265613939363334643239306431366337222c22706172656e7448617368223a22307838323139636261363732353034353438343230343430656531613339396663623235656536323133383862333838653965613639663536663930363130643031222c2273686133556e636c6573223a22307831646363346465386465633735643761616238356235363762366363643431616433313234353162393438613734313366306131343266643430643439333437222c226d696e6572223a22307834346664336162383338316363336431346166613763346166376664313363646336353032366531222c227374617465526f6f74223a22307837356430653937303463336661336635633232643330373862386232643036636266656537663061363233643932386235373232346332363539663534633833222c227472616e73616374696f6e73526f6f74223a22307861623431663838366265323363643738366438613639613732623066393838656137326530623265303339373064303739386635653033373633613434326363222c227265636569707473526f6f74223a22307836376563346533623238626636373964626431306233636139636232356162376433656662643334646239333866623138386663643635633861316230343036222c226e756d626572223a223078613161343839222c2267617355736564223a2230783135633038222c226761734c696d6974223a223078626561343035222c22657874726144617461223a2230783730373037393635323037373632222c226c6f6773426c6f6f6d223a2230783030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c2274696d657374616d70223a2230783566323935626139222c22646966666963756c7479223a22307838613838643536313132396166222c22746f74616c446966666963756c7479223a22307833383736663032306432656332323638316666222c227365616c4669656c6473223a5b5d2c22756e636c6573223a5b5d2c227472616e73616374696f6e73223a5b22307862306334333231336338366332636163636538636565663936356238383135323964333165356265393361643663656663656632663331396132306566316235222c22307835626262663634626430663038343635616362653330616462326265383037343838633338343763393461376466616261666661336532356162336136303461222c22307837643936356131303364626238653230323736383265343562643337316366393262623965313562383464356232666130646661343533333338373965643132222c22307830623431666334633164383531386364656461393831323236393437373235366264633431356562333963343533313838356666393732386436616430393662225d2c2273697a65223a223078343463222c226d697848617368223a22307864653961653931633830613866643134643563653332323032623966666361613839623863353931393938343037333539663138363033313463313066383632222c226e6f6e6365223a22307831316566633637313536336235366339222c2262617365466565506572476173223a6e756c6c7d";
        let block: Block<H256> = serde_json::from_slice(&hex::decode(block_str).unwrap()).unwrap();
        let mut block_rlp = rlp::encode(&RLPBlock(&block)).to_vec();
        let block_rlp_len = block_rlp.len();
        let _ = "441bcda29969fe4c94790b8538b70e30b66c62b69fe6516bea99634d290d16c7";
        let block_tx_root_hash_str =
            "ab41f886be23cd786d8a69a72b0f988ea72e0b2e03970d0798f5e03763a442cc";
        let tx_root = hex::decode(block_tx_root_hash_str).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let mut pw = PartialWitness::new();

        // TODO: have one for the newest blocks headers
        const MAX_HEADER_LEN: usize = 600;
        assert!(block_rlp_len < MAX_HEADER_LEN);
        let rlp_len_tgt = builder.add_virtual_target();
        pw.set_target(rlp_len_tgt, F::from_canonical_usize(block_rlp_len));
        block_rlp.resize(MAX_HEADER_LEN, 0);
        let block_tgt = builder.add_virtual_targets(MAX_HEADER_LEN);
        for i in 0..MAX_HEADER_LEN {
            pw.set_target(block_tgt[i], F::from_canonical_u8(block_rlp[i]));
        }
        const HASH_LEN: usize = 32;
        assert!(tx_root.len() == HASH_LEN);
        let item = builder.add_virtual_targets(HASH_LEN);
        for i in 0..HASH_LEN {
            pw.set_target(item[i], F::from_canonical_u8(tx_root[i]));
        }
        let item_offset = find_index_subvector(&block_rlp, &tx_root).unwrap();
        println!("[+] Starting proving now");
        let start = Instant::now();
        prove_header_inclusion::<F, D, HASH_LEN>(
            &mut builder,
            &mut pw,
            &block_tgt,
            rlp_len_tgt,
            &item,
            item_offset,
        );
        let data = builder.build::<C>();
        let end = start.elapsed();
        println!("[+] building circuit {:?}s", end.as_secs());
        let start = Instant::now();
        let proof = data.prove(pw)?;
        let end = start.elapsed();
        println!("[+] proving proof {:?}s", end.as_secs());
        data.verify(proof)?;
        Ok(())
    }
}
