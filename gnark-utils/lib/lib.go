package main

/*
   #include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/pkg/errors"
	"github.com/succinctlabs/gnark-plonky2-verifier/trusted_setup"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// Global variables for the proving process are only necessary to initialize
// once by InitProver function.
var (
	R1CS constraint.ConstraintSystem
	PK   plonk.ProvingKey
)

// Global variables for the verifying process are only necessary to initialize
// once by InitVerifier function.
var VK plonk.VerifyingKey

// Global logger
var Logger = logger.Logger()

//export CompileAndGenerateAssets
func CompileAndGenerateAssets(
	commonCircuitData *C.char,
	verifierOnlyCircuitData *C.char,
	dstAssetDirStr *C.char,
) *C.char {
	dstAssetDir := C.GoString(dstAssetDirStr)

	// Check if the asset dir exists.
	_, err := os.Stat(dstAssetDir)
	if err != nil {
		return C.CString(fmt.Sprintf("destination asset dir doesn't exist: %v", err))
	}

	Logger.Info().Msg("starting compiling verifier circuit")

	// Compile the verifier circuit and generate the assets (R1CS, PK and VK).
	r1cs, pk, vk, err := CompileVerifierCircuit(
		C.GoString(commonCircuitData),
		C.GoString(verifierOnlyCircuitData))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to compile verifier circuit: %v", err))
	}

	// Save the asset files for further proving and verifying processes. These
	// asset files are only related with the common circuit data.
	err = SaveVerifierCircuit(dstAssetDir, r1cs, pk, vk)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to save verifier circuit: %v", err))
	}

	Logger.Info().Msg("successfully compiled verifier circuit")

	return nil
}

func CompileVerifierCircuit(
	commonCircuitDataStr string,
	verifierOnlyCircuitDataStr string,
) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey, error) {
	verifierOnlyCircuitData, err := DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataStr)
	if err != nil {
		return nil, nil, nil, err
	}
	commonCircuitData, err := DeserializeCommonCircuitData(commonCircuitDataStr)
	if err != nil {
		return nil, nil, nil, err
	}
	proofWithPis := NewProofWithPublicInputs(commonCircuitData)

	circuit := VerifierCircuit{
		ProofWithPis:      proofWithPis,
		VerifierData:      *verifierOnlyCircuitData,
		VerifierDigest:    new(frontend.Variable),
		InputHash:         new(frontend.Variable),
		OutputHash:        new(frontend.Variable),
		CommonCircuitData: *commonCircuitData,
	}

	scs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "compile verifier circuit")
	}
	Logger.Info().Msg("Successfully compiled verifier circuit")

	fileName := "srs_setup"
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		trusted_setup.DownloadAndSaveAztecIgnitionSrs(174, fileName)
	}
	fSRS, err := os.Open(fileName)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "open srs file")
	}

	var srs kzg.SRS = kzg.NewSRS(ecc.BN254)
	_, err = srs.ReadFrom(fSRS)
	fSRS.Close()
	Logger.Info().Msg("Successfully loaded SRS")

	start := time.Now()
	pk, vk, err := plonk.Setup(scs, srs)
	if err != nil {
		return nil, nil, nil, err
	}
	elapsed := time.Since(start)
	Logger.Info().Msg("Successfully ran circuit setup in " + elapsed.String())

	return scs, pk, vk, nil
}

func SaveVerifierCircuit(assetDir string, r1cs constraint.ConstraintSystem, pk plonk.ProvingKey, vk plonk.VerifyingKey) error {
	// Create the asset dir if not exists.
	os.MkdirAll(assetDir, 0755)

	// Save the R1CS.
	r1csFile, err := os.Create(assetDir + "/r1cs.bin")
	if err != nil {
		return errors.Wrap(err, "create r1cs file")
	}
	r1cs.WriteTo(r1csFile)
	r1csFile.Close()
	Logger.Info().Msg("Successfully saved circuit constraints to r1cs.bin")

	// Save the PK.
	Logger.Info().Msg("Saving proving key to pk.bin")
	pkFile, err := os.Create(assetDir + "/pk.bin")
	if err != nil {
		return errors.Wrap(err, "create pk file")
	}
	pk.WriteRawTo(pkFile)
	pkFile.Close()
	Logger.Info().Msg("Successfully saved proving key to pk.bin")

	// Save the VK.
	vkFile, err := os.Create(assetDir + "/vk.bin")
	if err != nil {
		return errors.Wrap(err, "create vk file")
	}
	vk.WriteRawTo(vkFile)
	vkFile.Close()
	Logger.Info().Msg("Successfully saved verifying key to vk.bin")

	// Save the Solidity verifier contract.
	err = SaveVerifierSolidity(assetDir, vk)
	if err != nil {
		return err
	}

	return nil
}

//export InitProver
func InitProver(assetDirStr *C.char) *C.char {
	var err error
	assetDir := C.GoString(assetDirStr)
	R1CS, err = LoadCircuitFromFile(assetDir)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load verifier circuit: %v", err))
	}
	PK, err = LoadProvingKeyFromFile(assetDir)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load proving key: %v", err))
	}

	return nil
}

//export InitProverFromBytes
func InitProverFromBytes(base64R1CS *C.char, base64PK *C.char) *C.char {
	r1csBytes, err := base64.StdEncoding.DecodeString(C.GoString(base64R1CS))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to decode Base64 R1CS: %v", err))
	}

	pkBytes, err := base64.StdEncoding.DecodeString(C.GoString(base64PK))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to decode Base64 PK: %v", err))
	}

	R1CS, err = LoadCircuitFromBytes(r1csBytes)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load verifier circuit: %v", err))
	}
	PK, err = LoadProvingKeyFromBytes(pkBytes)
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load proving key: %v", err))
	}

	return nil
}

//export InitVerifier
func InitVerifier(assetDir *C.char) *C.char {
	var err error
	VK, err = LoadVerifierKey(C.GoString(assetDir))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to load verifier key: %v", err))
	}

	return nil
}

//export Prove
func Prove(
	verifierOnlyCircuitData *C.char,
	proofWithPublicInputs *C.char,
) *C.char {
	Logger.Info().Msg("starting prove -- generating proof")
	proof, err := ProveCircuit(C.GoString(verifierOnlyCircuitData), C.GoString(proofWithPublicInputs))
	if err != nil {
		// TODO: we only log the error here, since no tuple in C and we don't
		// want to make it complicated.
		Logger.Info().Msgf("failed to generate proof: %v", err)
		return nil
	}

	Logger.Info().Msg("successfully created proof")

	return C.CString(proof)
}

//export Verify
func Verify(proofStr *C.char) *C.char {
	Logger.Info().Msg("nothing to do for now")
	return nil
}

func LoadCircuitFromBytes(r1csBytes []byte) (constraint.ConstraintSystem, error) {
	r1cs := plonk.NewCS(ecc.BN254)
	r1csReader := bytes.NewReader(r1csBytes)
	_, err := r1cs.ReadFrom(r1csReader)
	if err != nil {
		return nil, errors.Wrap(err, "read r1cs bytes")
	}

	return r1cs, nil
}

func LoadCircuitFromFile(assetDir string) (constraint.ConstraintSystem, error) {
	r1cs := plonk.NewCS(ecc.BN254)
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

func LoadProvingKeyFromBytes(pkBytes []byte) (plonk.ProvingKey, error) {
	pk := plonk.NewProvingKey(ecc.BN254)
	pkReader := bytes.NewReader(pkBytes)
	_, err := pk.ReadFrom(pkReader)
	if err != nil {
		return pk, errors.Wrap(err, "read pk bytes")
	}

	return pk, nil
}

func LoadProvingKeyFromFile(assetDir string) (plonk.ProvingKey, error) {
	pk := plonk.NewProvingKey(ecc.BN254)
	f, err := os.Open(assetDir + "/pk.bin")
	if err != nil {
		return pk, errors.Wrap(err, "open pk file")
	}
	pkReader := bufio.NewReader(f)
	_, err = pk.ReadFrom(pkReader)
	if err != nil {
		return pk, errors.Wrap(err, "read pk file")
	}
	f.Close()

	return pk, nil
}

func LoadVerifierKey(assetDir string) (plonk.VerifyingKey, error) {
	vk := plonk.NewVerifyingKey(ecc.BN254)
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

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func SaveVerifierSolidity(assetDir string, vk plonk.VerifyingKey) error {
	// Create a new buffer and export the VerifyingKey into it as a Solidity
	// contract and convert the buffer content to a string for further
	// manipulation.
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

func ProveCircuit(
	verifierOnlyCircuitDataStr string,
	proofWithPublicInputsStr string,
) (string, error) {
	Logger.Info().Msg("loading verifier only circuit data and proof with public inputs")
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

	Logger.Info().Msg("generating witness")
	start := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", errors.Wrap(err, "generate witness")
	}
	elapsed := time.Since(start)
	Logger.Info().Msg("successfully generated witness in " + elapsed.String())

	Logger.Info().Msg("creating proof")
	start = time.Now()
	proof, err := plonk.Prove(R1CS, PK, witness)
	if err != nil {
		return "", errors.Wrap(err, "create proof")
	}

	elapsed = time.Since(start)
	Logger.Info().Msg("successfully created proof in " + elapsed.String())

	_proof := proof.(*plonk_bn254.Proof)
	var buf bytes.Buffer
	_, err = _proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	Logger.Info().Msg("proof byte length: " + strconv.Itoa(len(proofBytes)))

	const fpSize = 4 * 8

	// Ensure proofBytes contains enough data for the expected operation.
	expectedLength := fpSize * 8
	if len(proofBytes) < expectedLength {
		return "", fmt.Errorf("proofBytes length is %d, expected at least %d", len(proofBytes), expectedLength)
	}

	proofs := make([]string, 8)
	for i := 0; i < 8; i++ {
		start := i * fpSize
		end := (i + 1) * fpSize
		// Additional check to prevent slice bounds out of range panic.
		if end > len(proofBytes) {
			return "", fmt.Errorf("attempt to slice beyond proofBytes length at segment %d", i)
		}
		proofs[i] = "0x" + hex.EncodeToString(proofBytes[start:end])
	}

	publicWitness, _ := witness.Public()
	rawPublicWitnessBytes, _ := publicWitness.MarshalBinary()
	// We cut off the first 12 bytes because they encode length information.
	publicWitnessBytes := rawPublicWitnessBytes[12:]

	inputs := make([]string, 3)
	// Print out the public witness bytes.
	for i := 0; i < 3; i++ {
		inputs[i] = "0x" + hex.EncodeToString(publicWitnessBytes[i*fpSize:(i+1)*fpSize])
	}

	// Format the Plonk proof.
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

// Necessary for go-build
func main() {}
