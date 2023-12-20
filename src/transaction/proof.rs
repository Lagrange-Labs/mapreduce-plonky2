use anyhow::Result;
use ethers::types::{Transaction, U64};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::CircuitConfig,
        config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
    },
};

use crate::{
    utils::{find_index_subvector, keccak256, verify_proof_tuple},
    ByteProofTuple, ProofTuple,
};

use super::{
    header::{aggregate_sequential_headers, mpt_root_in_header},
    mpt::{
        gas_offset_from_rlp_node, recursive_node_proof, tx_leaf_node_proof, ExtractionMethod,
        NodeProofInputs, TxType,
    },
};

pub enum ProofType {
    TransactionMPT(TransactionMPT),
    IntermediateMPT(IntermediateMPT),
    RootMPTHeader(RootMPTHeader),
    HeaderAggregation(HeaderAggregation),
}

impl ProofType {
    fn compute_proof_raw<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        self,
    ) -> Result<ProofTuple<F, C, D>>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        match self {
            Self::TransactionMPT(p) => p.compute_proof(),
            Self::IntermediateMPT(p) => p.compute_proof(),
            Self::RootMPTHeader(p) => p.compute_proof(),
            Self::HeaderAggregation(p) => p.compute_proof(),
        }
    }
    pub fn compute_proof(self) -> Result<Vec<u8>> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let proof = self.compute_proof_raw::<F, C, D>()?;
        ByteProofTuple::from_proof_tuple(proof)
    }
}

pub struct TransactionMPT {
    pub leaf_node: Vec<u8>,
    pub quick_check: bool,
    /// The raw transaction that is being proven. Necessary to lookup specific
    /// fields easily (simpler than decoding RLP).
    pub transaction: Transaction,
}

impl TransactionMPT {
    fn compute_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        self,
    ) -> Result<ProofTuple<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let e = if self.quick_check {
            let (gas_offset, _) = gas_offset_from_rlp_node(&self.leaf_node);
            ExtractionMethod::OffsetBased(gas_offset)
        } else {
            ExtractionMethod::RLPBased
        };

        let tx_type = match self.transaction.transaction_type {
            Some(x) if x == U64::from(0x01) => TxType::EIP2930,
            Some(x) if x == U64::from(0x02) => TxType::EIP1559,
            _ => TxType::Legacy,
        };
        tx_leaf_node_proof(&config, self.leaf_node, tx_type, e)
    }
}

pub struct IntermediateMPT {
    pub intermediate_node: Vec<u8>,
    pub children_proofs: Vec<Vec<u8>>,
}
impl IntermediateMPT {
    fn compute_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        self,
    ) -> Result<ProofTuple<F, C, D>>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let children_proofs_tuple = deserialize_proofs(&self.children_proofs)?;
        // compute the offsets of the hashes of the children proofs/nodes inside this intermediate node
        let hash_offsets =
            compute_hash_offsets_from_proofs(&self.intermediate_node, &children_proofs_tuple)?;
        recursive_node_proof::<F, C, C, D>(
            &CircuitConfig::standard_recursion_config(),
            self.intermediate_node,
            &children_proofs_tuple,
            &hash_offsets,
        )
    }
}

pub struct RootMPTHeader {
    pub header_node: Vec<u8>,
    pub root_node: Vec<u8>,
    pub inner_proofs: Vec<Vec<u8>>,
}

impl RootMPTHeader {
    fn compute_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        self,
    ) -> Result<ProofTuple<F, C, D>>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // same as intermediate but for root node
        let children_proofs_tuple = deserialize_proofs::<F, C, D>(&self.inner_proofs)?;
        let children_offsets =
            compute_hash_offsets_from_proofs(&self.root_node, &children_proofs_tuple)?;
        // we also now need to look at block header and find the offset where the root node hash is
        let root_hash = keccak256(&self.root_node);
        let root_offset = find_index_subvector(&self.header_node, &root_hash)
            .ok_or(anyhow::anyhow!("no subvector found"))?;
        let config = CircuitConfig::standard_recursion_config();
        mpt_root_in_header(
            &config,
            self.header_node,
            self.root_node,
            &children_proofs_tuple,
            &children_offsets,
            root_offset,
        )
    }
}

struct HeaderAggregation {
    header_proofs: Vec<Vec<u8>>,
}

impl HeaderAggregation {
    fn compute_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        self,
    ) -> Result<ProofTuple<F, C, D>>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let decoded_proofs = self
            .header_proofs
            .iter()
            .map(|buff| ByteProofTuple::into_proof_tuple::<F, C, D>(buff))
            .collect::<Result<Vec<_>>>()?;
        let config = CircuitConfig::standard_recursion_config();
        // TODO: remove the const generic, too painful to work with and just go with
        // dynamic arity
        aggregate_sequential_headers::<F, C, C, D, 2>(&config, &decoded_proofs)
    }
}

// compute the offsets of the hashes of the children proofs/nodes inside this intermediate node
fn compute_hash_offsets_from_proofs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    node: &[u8],
    children_proofs: &[ProofTuple<F, C, D>],
) -> Result<Vec<usize>> {
    children_proofs
        .iter()
        .map(|child_proof| {
            // extract hash from child proof public inputs
            let packed_child_hash = NodeProofInputs::new(&child_proof.0.public_inputs)?.hash();
            // convert it to u8 bytes array
            let child_hash = packed_child_hash
                .iter()
                // We can cast to u32 here because valid public input hashes
                // are packed into u32s limbs
                .map(|d| d.to_canonical_u64() as u32)
                .flat_map(|d| d.to_le_bytes())
                .collect::<Vec<_>>();
            // find the offset of the child hash inside the intermediate node
            let hash_offset = find_index_subvector(node, &child_hash)
                .ok_or(anyhow::anyhow!("child hash not found in intermediate node"))?;
            Ok(hash_offset)
        })
        .collect::<Result<Vec<_>>>()
}

fn deserialize_proofs<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    proofs: &[Vec<u8>],
) -> Result<Vec<ProofTuple<F, C, D>>> {
    proofs
        .iter()
        .map(|buff| {
            let tuple = ByteProofTuple::into_proof_tuple(buff)?;
            verify_proof_tuple(&tuple)?;
            Ok(tuple)
        })
        .collect::<Result<Vec<_>>>()
}
