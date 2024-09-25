module main

go 1.22

toolchain go1.22.7

require (
	github.com/consensys/gnark v0.11.0
	github.com/consensys/gnark-crypto v0.14.1-0.20240909142611-e6b99e74cec1
	github.com/ethereum/go-ethereum v1.13.14
	github.com/pkg/errors v0.9.1
	github.com/succinctlabs/gnark-plonky2-verifier v0.1.0
)

require (
	github.com/bits-and-blooms/bitset v1.14.2 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/holiman/uint256 v1.2.4 // indirect
	github.com/ingonyama-zk/icicle v1.1.0 // indirect
	github.com/ingonyama-zk/iciclegnark v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/ronanh/intcomp v1.1.0 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/consensys/gnark => ../../gnark

replace github.com/succinctlabs/gnark-plonky2-verifier => ../../gnark-plonky2-verifier
