#[derive(Clone, Debug, Serialize, Deserialize)]
struct ByteProofTuple {
    proof: Vec<u8>,
    verification_data: Vec<u8>,
    common_data: Vec<u8>,
}

impl ByteProofTuple {
    fn serialize<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        proof: ProofTuple<F, C, D>,
    ) -> Result<Vec<u8>> {
        let (proof, vd, cd) = proof;
        let compressed_proof = proof.compress(&vd.circuit_digest, &cd)?;
        let proof_bytes = compressed_proof.to_bytes()?;
        let verification_data = vd.to_bytes()?;
        let common_data = cd.to_bytes()?;
        let btp = ByteProofTuple {
            proof: proof_bytes,
            verification_data,
            common_data,
        };
        bincode::serialize(&btp)
    }

    fn deserialize<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        proof_bytes: &[u8],
    ) -> Result<ProofTuple<F, C, D>> {
        let btp: ByteProofTuple = bincode::deserialize(proof_bytes)?;
        let vd = VerifierOnlyCircuitData::from_bytes(&btp.verification_data)?;
        let cd = CommonCircuitData::from_bytes(&btp.common_data)?;
        let compressed_proof = CompressedProofWithPublicInputs::from_bytes(&btp.proof, &cd)?;
        let proof = compressed_proof.decompress(&vd.circuit_digest, &cd)?;
        Ok((proof, vd, cd))
    }
}

pub enum ProofType {
    TransactionMPT(TransactionMPT),
    IntermediateMPT(IntermediateMPT),
    RootMPTHeader(RootMPTHeader),
    HeaderAggregation(HeaderAggregation),
}

impl ProofType {
    fn compute_proof_raw<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &self,
    ) -> Result<ProofTuple<F, C, D>> {
        match self {
            Self::TransactionMPT(p) => p.compute_proof(),
            Self::IntermediateMPT(p) => p.compute_proof(),
            Self::RootMPTHeader(p) => p.compute_proof(),
            Self::HeaderAggregation(p) => p.compute_proof(),
        }
    }
    pub fn compute_proof(&self) -> Result<()> {
        let proof = self.compute_proof_raw::<F, C, D>()?;
        ByteProofTuple::serialize(proof)
    }
}

pub struct TransactionMPT {
    leaf_node: Vec<u8>,
    tx: Transaction,
    quick_check: bool,
}

impl TransactionMPT {
    fn compute_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
    ) -> Result<ProofTuple<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let e = if self.quick_check {
            let (gas_offset, _) = gas_offset_from_rlp_node(&self.leaf_node);
            ExtractionMethod::OffsetBased(gas_offset)
        } else {
            ExtractionMethod::RLPBased
        };
        legacy_tx_leaf_node_proof(&config, self.leaf_node, e)
    }
}

struct IntermediateMPT {
    intermediate_node: Vec<u8>,
    children_proofs: Vec<Vec<u8>>,
}
impl IntermediateMPT {
    fn compute_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
    ) -> Result<ProofTuple<F, C, D>> {
        // compute the offsets of the hashes of the children proofs/nodes inside this intermediate node
        let hash_offsets = self.compute_hash_offsets()?;
        Ok(())
    }

    // compute the offsets of the hashes of the children proofs/nodes inside this intermediate node
    fn compute_hash_offsets(&self) -> Result<Vec<usize>> {
        self.children_proofs
            .iter()
            .map(|child_proof| {
                // extract hash from child proof public inputs
                let packed_child_hash = NodeProofInputs::new(&child_proof.public_inputs)?.hash();
                // convert it to u8 bytes array
                let child_hash = packed_child_hash
                    .iter()
                    .map(|d| d.to_le_bytes())
                    .flatten()
                    .collect::<Vec<_>>();
                // find the offset of the child hash inside the intermediate node
                let hash_offset = find_index_subvector(&self.intermediate_node, &child_hash)?;
                Ok(hash_offset)
            })
            .collect::<Result<Vec<_>>>()
    }
}

struct RootMPTHeader {}

impl RootMPTHeader {
    fn compute_proof(&self) -> Result<()> {
        Ok(())
    }
}

struct HeaderAggregation {}

impl HeaderAggregation {
    fn compute_proof(&self) -> Result<()> {
        Ok(())
    }
}
