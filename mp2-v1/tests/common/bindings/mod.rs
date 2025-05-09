pub mod simple {
    use alloy::sol;

    sol!(
        // solc --optimize --abi --bin ./mp2-v1/test-contracts/src/Simple.sol -o mp2-v1/test-contracts/src/
        #[sol(rpc, bytecode = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-contracts/src/Simple.bin")))]
        Simple,
        "./test-contracts/src/Simple.abi"
    );
}
