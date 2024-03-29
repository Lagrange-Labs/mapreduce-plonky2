// Copied from PR [succinctx#353](https://github.com/succinctlabs/succinctx/pull/353)
// directly with no changes.

package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
)

type VerifierCircuit struct {
	// A digest of the plonky2x circuit that is being verified.
	VerifierDigest frontend.Variable `gnark:"verifierDigest,public"`

	// The input hash is the hash of all onchain inputs into the function.
	InputHash frontend.Variable `gnark:"inputHash,public"`

	// The output hash is the hash of all outputs from the function.
	OutputHash frontend.Variable `gnark:"outputHash,public"`

	// Private inputs to the circuit
	ProofWithPis variables.ProofWithPublicInputs
	VerifierData variables.VerifierOnlyCircuitData

	// Circuit configuration that is not part of the circuit itself.
	CommonCircuitData types.CommonCircuitData `gnark:"-"`
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	// initialize the verifier chip
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	// verify the plonky2 proofD
	verifierChip.Verify(c.ProofWithPis.Proof, c.ProofWithPis.PublicInputs, c.VerifierData)

	// We assume that the publicInputs have 64 bytes
	// publicInputs[0:32] is a big-endian representation of a SHA256 hash that has been truncated to 253 bits.
	// Note that this truncation happens in the `WrappedCircuit` when computing the `input_hash`
	// The reason for truncation is that we only want 1 public input on-chain for the input hash
	// to save on gas costs
	publicInputs := c.ProofWithPis.PublicInputs

	if len(publicInputs) != 64 {
		return fmt.Errorf("expected 64 public inputs, got %d", len(publicInputs))
	}

	inputDigest := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		pubByte := publicInputs[31-i].Limb
		inputDigest = api.Add(inputDigest, api.Mul(pubByte, frontend.Variable(new(big.Int).Lsh(big.NewInt(1), uint(8*i)))))

	}
	api.AssertIsEqual(c.InputHash, inputDigest)

	outputDigest := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		pubByte := publicInputs[63-i].Limb
		outputDigest = api.Add(outputDigest, api.Mul(pubByte, frontend.Variable(new(big.Int).Lsh(big.NewInt(1), uint(8*i)))))
	}
	api.AssertIsEqual(c.OutputHash, outputDigest)

	// We have to assert that the VerifierData we verified the proof with
	// matches the VerifierDigest public input.
	api.AssertIsEqual(c.VerifierDigest, c.VerifierData.CircuitDigest)

	return nil
}

// Build a `ProofWithPublicInputs` variable to be employed in `VerifierCircuit` to verify a proof for a circuit
// with `commonCircuitData` 
func NewProofWithPublicInputs(commonCircuitData *types.CommonCircuitData) variables.ProofWithPublicInputs {
	proof := newProof(commonCircuitData)
	public_inputs := make([]gl.Variable, commonCircuitData.NumPublicInputs)
	return variables.ProofWithPublicInputs{
		Proof: proof,
		PublicInputs: public_inputs,
	}
}

const SALT_SIZE = 4; // same as SALT_SIZE constant in Plonky2

func newOpeningSet(commonCircuitData *types.CommonCircuitData) variables.OpeningSet {
		constants := make([]gl.QuadraticExtensionVariable, commonCircuitData.NumConstants)
		plonk_sigmas := make([]gl.QuadraticExtensionVariable, commonCircuitData.Config.NumRoutedWires)
		wires := make([]gl.QuadraticExtensionVariable, commonCircuitData.Config.NumWires)
		plonk_zs := make([]gl.QuadraticExtensionVariable, commonCircuitData.Config.NumChallenges)
		plonk_zs_next := make([]gl.QuadraticExtensionVariable, commonCircuitData.Config.NumChallenges)
		partial_products := make([]gl.QuadraticExtensionVariable, commonCircuitData.Config.NumChallenges * commonCircuitData.NumPartialProducts)
		quotient_polys := make([]gl.QuadraticExtensionVariable, commonCircuitData.Config.NumChallenges * commonCircuitData.QuotientDegreeFactor)
		return variables.OpeningSet{
			Constants:       constants,
			PlonkSigmas:     plonk_sigmas,
			Wires:           wires,
			PlonkZs:         plonk_zs,
			PlonkZsNext:     plonk_zs_next,
			PartialProducts: partial_products,
			QuotientPolys:   quotient_polys,
		}
}

func newFriQueryRound(commonCircuitData *types.CommonCircuitData) variables.FriQueryRound {
	params := &commonCircuitData.FriParams
	salt_size := func() uint64 {
		if params.Hiding {
			return SALT_SIZE
		} else {
			return 0
		}
	}
	cap_height := params.Config.CapHeight
	num_leaves_per_oracle := [4]uint64{
		commonCircuitData.NumConstants + commonCircuitData.Config.NumRoutedWires,
		commonCircuitData.Config.NumWires + salt_size(),
		commonCircuitData.Config.NumChallenges*(1 + commonCircuitData.NumPartialProducts) + salt_size(),
		commonCircuitData.QuotientDegreeFactor* commonCircuitData.Config.NumChallenges + salt_size(),
	}
	merkle_proof_len := params.LdeBits() - int(cap_height)
	if merkle_proof_len < 0 {
		panic("Invalid configuration: cap_height is greater than LDE bits")
	}
	// build `FriInitialTreeProof`
	eval_proofs := make([]variables.FriEvalProof, len(num_leaves_per_oracle))
	for j := 0; j < len(eval_proofs); j++ {
		eval_proofs[j] = variables.NewFriEvalProof(
				make([]gl.Variable, num_leaves_per_oracle[j]),
				variables.NewFriMerkleProof(uint64(merkle_proof_len)),
			)
	}
	initial_trees := variables.NewFriInitialTreeProof(eval_proofs)
	// build `FriQueryStep`
	query_steps := make([]variables.FriQueryStep, len(params.ReductionArityBits))
	for j := 0; j < len(params.ReductionArityBits); j++ {
		arity_bits := params.ReductionArityBits[j]
		merkle_proof_len -= int(arity_bits)
		if merkle_proof_len < 0 {
			panic("Invalid configuration: arity_bits greater than merkle_proof_len")
		}
		query_steps[j] = variables.NewFriQueryStep(arity_bits, uint64(merkle_proof_len))
	}

	return variables.NewFriQueryRound(
		query_steps,
		initial_trees,
	)
}

func newFriProof(commonCircuitData *types.CommonCircuitData) variables.FriProof {
	params := &commonCircuitData.FriParams
	cap_height := params.Config.CapHeight
	commit_phase_merkle_caps := make([]variables.FriMerkleCap, len(params.ReductionArityBits))
	for i := 0; i < len(commit_phase_merkle_caps); i++ {
		commit_phase_merkle_caps[i] = variables.NewFriMerkleCap(cap_height)
	}
	query_round_proofs := make([]variables.FriQueryRound, params.Config.NumQueryRounds)
	for i := 0; i < len(query_round_proofs); i++ {
		// build the i-th `FriQueryRound` struct
		query_round_proofs[i] = newFriQueryRound(commonCircuitData)
	}
	polynomial_coeffs := variables.NewPolynomialCoeffs(uint64(params.FinalPolyLen()))
	var witness gl.Variable
	return variables.FriProof{
		CommitPhaseMerkleCaps: commit_phase_merkle_caps,
		QueryRoundProofs:      query_round_proofs,
		FinalPoly:             polynomial_coeffs,
		PowWitness:            witness,
	}
}

func newProof(commonCircuitData *types.CommonCircuitData) variables.Proof {
	cap_height := commonCircuitData.FriParams.Config.CapHeight
	wires_cap := variables.NewFriMerkleCap(cap_height)
	partial_products_cap := variables.NewFriMerkleCap(cap_height)
	quotients_cap := variables.NewFriMerkleCap(cap_height)
	opening := newOpeningSet(commonCircuitData)
	fri_proof := newFriProof(commonCircuitData)
	return variables.Proof{
		WiresCap:                  wires_cap,
		PlonkZsPartialProductsCap: partial_products_cap,
		QuotientPolysCap:          quotients_cap,
		Openings:                  opening,
		OpeningProof:              fri_proof,
	}
}

