// Deserialization functions

package main

import "C"
import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk/gates"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

// Deserialize the proof with public inputs.
func DeserializeProofWithPublicInputs(str string) (*variables.ProofWithPublicInputs, error) {
	var raw types.ProofWithPublicInputsRaw
	err := json.Unmarshal([]byte(str), &raw)
	if err != nil {
		return nil, err
	}

	proofWithPublicInputs := variables.DeserializeProofWithPublicInputs(raw)
	return &proofWithPublicInputs, nil
}

// Deserialize the verifier data.
func DeserializeVerifierOnlyCircuitData(str string) (*variables.VerifierOnlyCircuitData, error) {
	var raw types.VerifierOnlyCircuitDataRaw
	err := json.Unmarshal([]byte(str), &raw)
	if err != nil {
		return nil, err
	}

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(raw)
	return &verifierOnlyCircuitData, nil
}

// Deserialize the circuit data. Reference gnark-plonky2-verifier
// [ReadCommonCircuitData](https://github.com/succinctlabs/gnark-plonky2-verifier/blob/7025b2efd67b5ed30bd85f93c694774106d21b3d/types/common_data.go#L61)
// function, it reads the circuit data from a file, but we want to deserialize
// from a string here.
func DeserializeCommonCircuitData(str string) (*types.CommonCircuitData, error) {
	var raw types.CommonCircuitDataRaw
	err := json.Unmarshal([]byte(str), &raw)
	if err != nil {
		return nil, err
	}

	var commonCircuitData types.CommonCircuitData
	commonCircuitData.Config.NumWires = raw.Config.NumWires
	commonCircuitData.Config.NumRoutedWires = raw.Config.NumRoutedWires
	commonCircuitData.Config.NumConstants = raw.Config.NumConstants
	commonCircuitData.Config.UseBaseArithmeticGate = raw.Config.UseBaseArithmeticGate
	commonCircuitData.Config.SecurityBits = raw.Config.SecurityBits
	commonCircuitData.Config.NumChallenges = raw.Config.NumChallenges
	commonCircuitData.Config.ZeroKnowledge = raw.Config.ZeroKnowledge
	commonCircuitData.Config.MaxQuotientDegreeFactor = raw.Config.MaxQuotientDegreeFactor

	commonCircuitData.Config.FriConfig.RateBits = raw.Config.FriConfig.RateBits
	commonCircuitData.Config.FriConfig.CapHeight = raw.Config.FriConfig.CapHeight
	commonCircuitData.Config.FriConfig.ProofOfWorkBits = raw.Config.FriConfig.ProofOfWorkBits
	commonCircuitData.Config.FriConfig.NumQueryRounds = raw.Config.FriConfig.NumQueryRounds

	commonCircuitData.FriParams.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.FriParams.Config.RateBits = raw.FriParams.Config.RateBits
	commonCircuitData.FriParams.Config.CapHeight = raw.FriParams.Config.CapHeight
	commonCircuitData.FriParams.Config.ProofOfWorkBits = raw.FriParams.Config.ProofOfWorkBits
	commonCircuitData.FriParams.Config.NumQueryRounds = raw.FriParams.Config.NumQueryRounds
	commonCircuitData.FriParams.ReductionArityBits = raw.FriParams.ReductionArityBits

	commonCircuitData.GateIds = raw.Gates

	selectorGroupStart := []uint64{}
	selectorGroupEnd := []uint64{}
	for _, group := range raw.SelectorsInfo.Groups {
		selectorGroupStart = append(selectorGroupStart, group.Start)
		selectorGroupEnd = append(selectorGroupEnd, group.End)
	}

	commonCircuitData.SelectorsInfo = *gates.NewSelectorsInfo(
		raw.SelectorsInfo.SelectorIndices,
		selectorGroupStart,
		selectorGroupEnd,
	)

	commonCircuitData.QuotientDegreeFactor = raw.QuotientDegreeFactor
	commonCircuitData.NumGateConstraints = raw.NumGateConstraints
	commonCircuitData.NumConstants = raw.NumConstants
	commonCircuitData.NumPublicInputs = raw.NumPublicInputs
	commonCircuitData.KIs = raw.KIs
	commonCircuitData.NumPartialProducts = raw.NumPartialProducts

	// Don't support circuits that have hiding enabled
	if raw.FriParams.Hiding {
		return nil, errors.New("Circuit has hiding enabled, which is not supported")
	}

	return &commonCircuitData, nil
}
