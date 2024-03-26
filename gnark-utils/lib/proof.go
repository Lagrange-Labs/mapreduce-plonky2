// Groth16 proof struct

package main

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Groth16Proof struct {
	Inputs           []string      `json:"inputs"`
	Proofs           []string      `json:"proofs"`
	RawProof         hexutil.Bytes `json:"raw_proof"`
	RawPublicWitness hexutil.Bytes `json:"raw_public_witness"`
}
