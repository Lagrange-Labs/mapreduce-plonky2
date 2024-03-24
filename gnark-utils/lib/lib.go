package main

/*
   #include <stdlib.h>
*/
import "C"
import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk/gates"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

/*
"io"
"strings"

"github.com/consensys/gnark/backend/witness"
"github.com/ethereum/go-ethereum/common/hexutil"
"github.com/rs/zerolog"

*/

var R1CS constraint.ConstraintSystem
var PK groth16.ProvingKey
var VK groth16.VerifyingKey

var Logger = logger.Logger()

type Groth16Proof struct {
	Inputs           []string      `json:"inputs"`
	Proofs           []string      `json:"proofs"`
	RawProof         hexutil.Bytes `json:"raw_proof"`
	RawPublicWitness hexutil.Bytes `json:"raw_public_witness"`
}

//export CompileAndGenerateAssets
func CompileAndGenerateAssets(
	commonCircuitData *C.char,
	verifierOnlyCircuitData *C.char,
	proofWithPublicInputs *C.char,
	dstAssetDir *C.char,
) *C.char {
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")

	Logger.Info().Msg("starting compiling verifier circuit")

	r1cs, pk, vk, err := CompileVerifierCircuit(
		C.GoString(commonCircuitData),
		C.GoString(verifierOnlyCircuitData),
		C.GoString(proofWithPublicInputs))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to compile verifier circuit: %v", err))
	}

	err = SaveVerifierCircuit(C.GoString(dstAssetDir), r1cs, pk, vk)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to save verifier circuit: %v", err))
	}

	Logger.Info().Msg("successfully compiled verifier circuit")

	return nil
}

//export InitProver
func InitProver(assetDirStr *C.char) *C.char {
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")

	var err error
	assetDir := C.GoString(assetDirStr)
	R1CS, err = LoadCircuit(assetDir)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load verifier circuit: %v", err))
	}
	PK, err = LoadProvingKey(assetDir)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load proving key: %v", err))
	}

	return nil
}

//export Prove
func Prove(
	verifierOnlyCircuitData *C.char,
	proofWithPublicInputs *C.char,
) (*C.char, *C.char) {
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")

	Logger.Info().Msg("starting prove -- loading verifier circuit and proving key")

	Logger.Info().Msg("generating proof")
	proof, err := ProveCircuit(C.GoString(verifierOnlyCircuitData), C.GoString(proofWithPublicInputs))
	if err != nil {
		return nil, C.CString(fmt.Sprintf("failed to create proof: %v", err))
	}

	Logger.Info().Msg("successfully created proof")

	return C.CString(proof), nil
}

//export InitVerifier
func InitVerifier(assetDir *C.char) *C.char {
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")

	var err error
	VK, err = LoadVerifierKey(C.GoString(assetDir))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load verifier key: %v", err))
	}

	return nil
}

//export Verify
func Verify(proofStr *C.char) *C.char {
	os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true")
	Logger.Info().Msg("starting verify -- loading verifier key, public witness, and proof")

	var groth16Proof Groth16Proof
	err := json.Unmarshal([]byte(C.GoString(proofStr)), &groth16Proof)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to unmarshal Groth16 proof: %v", err))
	}

	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(bytes.NewReader(groth16Proof.RawProof))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load proof: %v", err))
	}

	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return C.CString(fmt.Sprintf("failed to create public witness: %v", err))
	}

	_, err = publicWitness.ReadFrom(bytes.NewReader(groth16Proof.RawPublicWitness))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load public witness: %v", err))
	}

	err = groth16.Verify(proof, VK, publicWitness)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to verify proof: %v", err))
	}

	Logger.Info().Msg("successfully verified proof")
	return nil
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func CompileVerifierCircuit(
	commonCircuitDataStr string,
	verifierOnlyCircuitDataStr string,
	proofWithPublicInputsStr string,
) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	verifierOnlyCircuitData, err := DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataStr)
	if err != nil {
		return nil, nil, nil, err
	}
	proofWithPis, err := DeserializeProofWithPublicInputs(proofWithPublicInputsStr)
	if err != nil {
		return nil, nil, nil, err
	}
	commonCircuitData, err := DeserializeCommonCircuitData(commonCircuitDataStr)
	if err != nil {
		return nil, nil, nil, err
	}

	circuit := VerifierCircuit{
		ProofWithPis:      *proofWithPis,
		VerifierData:      *verifierOnlyCircuitData,
		VerifierDigest:    new(frontend.Variable),
		InputHash:         new(frontend.Variable),
		OutputHash:        new(frontend.Variable),
		CommonCircuitData: *commonCircuitData,
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "compile verifier circuit")
	}

	Logger.Info().Msg("Running circuit setup")
	start := time.Now()
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return nil, nil, nil, err
	}
	elapsed := time.Since(start)
	Logger.Info().Msg("Successfully ran circuit setup in " + elapsed.String())

	return r1cs, pk, vk, nil
}

func SaveVerifierCircuit(assetDir string, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	os.MkdirAll(assetDir, 0755)

	r1csFile, err := os.Create(assetDir + "/r1cs.bin")
	if err != nil {
		return errors.Wrap(err, "create r1cs file")
	}
	r1cs.WriteTo(r1csFile)
	r1csFile.Close()
	Logger.Info().Msg("Successfully saved circuit constraints to r1cs.bin")

	Logger.Info().Msg("Saving proving key to pk.bin")
	pkFile, err := os.Create(assetDir + "/pk.bin")
	if err != nil {
		return errors.Wrap(err, "create pk file")
	}
	pk.WriteRawTo(pkFile)
	pkFile.Close()
	Logger.Info().Msg("Successfully saved proving key to pk.bin")

	vkFile, err := os.Create(assetDir + "/vk.bin")
	if err != nil {
		return errors.Wrap(err, "create vk file")
	}
	vk.WriteRawTo(vkFile)
	vkFile.Close()
	Logger.Info().Msg("Successfully saved verifying key to vk.bin")

	err = ExportVerifierSolidity(assetDir, vk)
	if err != nil {
		return err
	}

	return nil
}

func ExportVerifierSolidity(assetDir string, vk groth16.VerifyingKey) error {
	// Create a new buffer and export the VerifyingKey into it as a Solidity contract and
	// convert the buffer content to a string for further manipulation.
	buf := new(bytes.Buffer)
	err := vk.ExportSolidity(buf)
	if err != nil {
		return errors.Wrap(err, "export verifying key to solidity")
	}
	content := buf.String()

	contractFile, err := os.Create(assetDir + "/verifier.sol")
	if err != nil {
		return errors.Wrap(err, "create verifier.sol file")
	}
	defer contractFile.Close()

	w := bufio.NewWriter(contractFile)
	// write the new content to the writer
	if _, err = w.Write([]byte(content)); err != nil {
		return errors.Wrap(err, "write to verifier.sol")
	}

	return nil
}

func LoadCircuit(assetDir string) (constraint.ConstraintSystem, error) {
	r1cs := groth16.NewCS(ecc.BN254)
	f, err := os.Open(assetDir + "/r1cs.bin")
	if err != nil {
		return nil, errors.Wrap(err, "open r1cs file")
	}
	r1csReader := bufio.NewReader(f)
	_, err = r1cs.ReadFrom(r1csReader)
	if err != nil {
		return nil, errors.Wrap(err, "read r1cs file")
	}
	f.Close()

	return r1cs, nil
}

func LoadProvingKey(assetDir string) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	f, err := os.Open(assetDir + "/pk.bin")
	if err != nil {
		return pk, errors.Wrap(err, "open pk file")
	}
	_, err = pk.ReadFrom(f)
	if err != nil {
		return pk, errors.Wrap(err, "read pk file")
	}
	f.Close()

	return pk, nil
}

func LoadVerifierKey(assetDir string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	f, err := os.Open(assetDir + "/vk.bin")
	if err != nil {
		return nil, errors.Wrap(err, "open vk file")
	}
	_, err = vk.ReadFrom(f)
	if err != nil {
		return nil, errors.Wrap(err, "read vk file")
	}
	f.Close()

	return vk, nil
}

func ProveCircuit(
	verifierOnlyCircuitDataStr string,
	proofWithPublicInputsStr string,
) (string, error) {
	Logger.Info().Msg("Loading verifier only circuit data and proof with public inputs")
	verifierOnlyCircuitData, err := DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataStr)
	if err != nil {
		return "", err
	}
	var proofWithPisRaw types.ProofWithPublicInputsRaw
	err = json.Unmarshal([]byte(proofWithPublicInputsStr), &proofWithPisRaw)
	proofWithPis, err := DeserializeProofWithPublicInputs(proofWithPublicInputsStr)
	if err != nil {
		return "", err
	}

	inputHash, outputHash := GetInputHashOutputHash(proofWithPisRaw)

	// Circuit assignment
	assignment := &VerifierCircuit{
		ProofWithPis:   *proofWithPis,
		VerifierData:   *verifierOnlyCircuitData,
		VerifierDigest: verifierOnlyCircuitData.CircuitDigest,
		InputHash:      frontend.Variable(inputHash),
		OutputHash:     frontend.Variable(outputHash),
	}

	Logger.Info().Msg("Generating witness")
	start := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", errors.Wrap(err, "generate witness")
	}
	elapsed := time.Since(start)
	Logger.Info().Msg("Successfully generated witness in " + elapsed.String())

	Logger.Info().Msg("Creating proof")
	start = time.Now()
	proof, err := groth16.Prove(R1CS, PK, witness)
	if err != nil {
		return "", errors.Wrap(err, "create proof")
	}

	elapsed = time.Since(start)
	Logger.Info().Msg("Successfully created proof in " + elapsed.String())

	_proof := proof.(*groth16_bn254.Proof)
	Logger.Info().Msg("Saving proof to proof.json")

	var buf bytes.Buffer
	_, err = _proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	Logger.Info().Msg("len(proofBytes) =" + strconv.Itoa(len(proofBytes)))

	const fpSize = 4 * 8

	// Ensure proofBytes contains enough data for the expected operation
	expectedLength := fpSize * 8
	if len(proofBytes) < expectedLength {
		return "", fmt.Errorf("proofBytes length is %d, expected at least %d", len(proofBytes), expectedLength)
	}

	proofs := make([]string, 8)
	for i := 0; i < 8; i++ {
		start := i * fpSize
		end := (i + 1) * fpSize
		// Additional check to prevent slice bounds out of range panic
		if end > len(proofBytes) {
			return "", fmt.Errorf("attempt to slice beyond proofBytes length at segment %d", i)
		}
		proofs[i] = "0x" + hex.EncodeToString(proofBytes[start:end])
	}

	publicWitness, _ := witness.Public()
	rawPublicWitnessBytes, _ := publicWitness.MarshalBinary()
	publicWitnessBytes := rawPublicWitnessBytes[12:] // We cut off the first 12 bytes because they encode length information

	inputs := make([]string, 3)
	// Print out the public witness bytes
	for i := 0; i < 3; i++ {
		inputs[i] = "0x" + hex.EncodeToString(publicWitnessBytes[i*fpSize:(i+1)*fpSize])
	}

	// Write proof with all the public inputs and save to disk.
	jsonProofWithWitness, err := json.Marshal(Groth16Proof{
		Inputs:           inputs,
		Proofs:           proofs,
		RawProof:         proofBytes,
		RawPublicWitness: rawPublicWitnessBytes,
	})
	if err != nil {
		return "", errors.Wrap(err, "marshal proof with witness")
	}

	return string(jsonProofWithWitness), nil
}

func GetInputHashOutputHash(proofWithPis types.ProofWithPublicInputsRaw) (*big.Int, *big.Int) {
	publicInputs := proofWithPis.PublicInputs
	if len(publicInputs) != 64 {
		panic("publicInputs must be 64 bytes")
	}
	publicInputsBytes := make([]byte, 64)
	for i, v := range publicInputs {
		publicInputsBytes[i] = byte(v & 0xFF)
	}
	inputHash := new(big.Int).SetBytes(publicInputsBytes[0:32])
	outputHash := new(big.Int).SetBytes(publicInputsBytes[32:64])
	if inputHash.BitLen() > 253 {
		panic("inputHash must be at most 253 bits")
	}
	if outputHash.BitLen() > 253 {
		panic("outputHash must be at most 253 bits")
	}
	return inputHash, outputHash
}

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

func DeserializeVerifierOnlyCircuitData(str string) (*variables.VerifierOnlyCircuitData, error) {
	var raw types.VerifierOnlyCircuitDataRaw
	err := json.Unmarshal([]byte(str), &raw)
	if err != nil {
		return nil, err
	}

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(raw)
	return &verifierOnlyCircuitData, nil
}

func DeserializeProofWithPublicInputs(str string) (*variables.ProofWithPublicInputs, error) {
	var raw types.ProofWithPublicInputsRaw
	err := json.Unmarshal([]byte(str), &raw)
	if err != nil {
		return nil, err
	}

	proofWithPublicInputs := variables.DeserializeProofWithPublicInputs(raw)
	return &proofWithPublicInputs, nil
}

/*

func (s *Groth16System) Verify() error {
}

func (s *Groth16System) Export() error {
	s.logger.Info().Msg("starting export -- loading verifier key and exporting Verifier solidity")

	vk, err := s.LoadVerifierKey()
	if err != nil {
		return errors.Wrap(err, "load verifier key")
	}

	err = s.ExportVerifierJSON(vk)
	if err != nil {
		return errors.Wrap(err, "export Verifier JSON")
	}

	err = s.ExportVerifierSolidity(vk)
	if err != nil {
		return errors.Wrap(err, "export Verifier solidity")
	}

	s.logger.Info().Msg("successfully exported Verifier solidity")

	return nil
}



func (s *Groth16System) LoadProof() (proof groth16.Proof, err error) {
	proof = groth16.NewProof(ecc.BN254)
	f, err := os.Open(s.dataPath + "/proof.json")
	if err != nil {
		return proof, errors.Wrap(err, "open proof file")
	}
	jsonProof, err := io.ReadAll(f)
	if err != nil {
		return proof, errors.Wrap(err, "read proof file")
	}
	err = json.Unmarshal(jsonProof, proof)
	if err != nil {
		return proof, errors.Wrap(err, "read proof file")
	}
	f.Close()

	return proof, nil
}

func (s *Groth16System) LoadPublicWitness() (witness.Witness, error) {
	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return publicWitness, errors.Wrap(err, "create public witness")
	}
	f, err := os.Open(s.dataPath + "/public_witness.bin")
	if err != nil {
		return publicWitness, errors.Wrap(err, "open public witness file")
	}
	_, err = publicWitness.ReadFrom(f)
	if err != nil {
		return publicWitness, errors.Wrap(err, "read public witness file")
	}
	f.Close()

	return publicWitness, nil
}

/*



// gupeng
type Config struct {
	NodeUrl  string   `json:"NodeUrl"`
	BlockNum int      `json:"BlockNum"`
	Addr     string   `json:"Addr"`
	Keys     []string `json:"Keys"`
	Values   []string `json:"Values"`
}
*/

func main() {}
