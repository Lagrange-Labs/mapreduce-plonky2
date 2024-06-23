#! /bin/bash

set -x

# Anvil local RPC URL
ANVIL_RPC_URL="http://localhost:8545"

# Anvil testing private key for signing the transcations
ANVIL_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Simple contract address
SIMPLE_CONTRACT=0xc7994C8FF4EA625359236cE5f9aEEE01881b29fb

# Arguments for getting values from the contract
GET_ARGS="--rpc-url ${ANVIL_RPC_URL}"

# Arguments for sending the transactions
SET_ARGS="${GET_ARGS} --private-key ${ANVIL_PRIVATE_KEY}"

# `setSimples` function signature
SET_SIMPLES_FUN="setSimples(bool,uint256,string,address)"

# `setMapping` function signature
SET_MAPPING_FUN="setMapping(address,uint256)"

# `addToArray` function signature
ADD_TO_ARRAY_FUN="addToArray(uint256)"

# Call `setSimples(...)`
echo "Set simples..."
cast send ${SIMPLE_CONTRACT} ${SET_SIMPLES_FUN} \
    true "100" "test" 0xb90ed61bffed1df72f2ceebd965198ad57adfcbd \
    ${SET_ARGS}

# Call `setMapping(...)`
echo "Set mappings..."
cast send ${SIMPLE_CONTRACT} ${SET_MAPPING_FUN} \
    0x3bf5733f695b2527acc7bd4c5350e57acfd9fbb5 100 \
    ${SET_ARGS}
cast send ${SIMPLE_CONTRACT} ${SET_MAPPING_FUN} \
    0x6cac7190535f4908d0524e7d55b3750376ea1ef7 200 \
    ${SET_ARGS}

# Call `addToArray(...)`
echo "Add values to array ..."
cast send ${SIMPLE_CONTRACT} ${ADD_TO_ARRAY_FUN} 1111 ${SET_ARGS}
cast send ${SIMPLE_CONTRACT} ${ADD_TO_ARRAY_FUN} 2222 ${SET_ARGS}
cast send ${SIMPLE_CONTRACT} ${ADD_TO_ARRAY_FUN} 3333 ${SET_ARGS}
cast send ${SIMPLE_CONTRACT} ${ADD_TO_ARRAY_FUN} 4444 ${SET_ARGS}

echo "Get s1, s2, s3, s4:"
cast call ${SIMPLE_CONTRACT} "s1()" ${GET_ARGS}
cast call ${SIMPLE_CONTRACT} "s2()" ${GET_ARGS}
cast call ${SIMPLE_CONTRACT} "s3()" ${GET_ARGS}
cast call ${SIMPLE_CONTRACT} "s4()" ${GET_ARGS}

echo "Get mapping values:"
cast call ${SIMPLE_CONTRACT} "m1(address)(uint256)" \
    0x3bf5733f695b2527acc7bd4c5350e57acfd9fbb5 \
    ${GET_ARGS}
cast call ${SIMPLE_CONTRACT} "m1(address)(uint256)" \
    0x6cac7190535f4908d0524e7d55b3750376ea1ef7 \
    ${GET_ARGS}

echo "Get array values:"
cast call ${SIMPLE_CONTRACT} "arr1(uint256)(uint256)" 0 ${GET_ARGS}
cast call ${SIMPLE_CONTRACT} "arr1(uint256)(uint256)" 1 ${GET_ARGS}
cast call ${SIMPLE_CONTRACT} "arr1(uint256)(uint256)" 2 ${GET_ARGS}
cast call ${SIMPLE_CONTRACT} "arr1(uint256)(uint256)" 3 ${GET_ARGS}
