//! Test contract deployment and call
//! Copied and modified from [snark-verifier](https://github.com/privacy-scaling-explorations/snark-verifier).

use anyhow::{bail, Result};
use revm::{
    primitives::{CreateScheme, ExecutionResult, Output, TransactTo, TxEnv},
    InMemoryDB, EVM,
};

/// Deploy contract and then call with calldata.
/// Return the gas_used and the output bytes of call to deployed contract if
/// both transactions are successful.
pub fn deploy_and_call(deployment_code: Vec<u8>, calldata: Vec<u8>) -> Result<(u64, Vec<u8>)> {
    let mut evm = EVM {
        env: Default::default(),
        db: Some(InMemoryDB::default()),
    };

    evm.env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TransactTo::Create(CreateScheme::Create),
        data: deployment_code.into(),
        ..Default::default()
    };

    let result = evm.transact_commit().unwrap();
    let contract = match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(contract)),
            ..
        } => contract,
        ExecutionResult::Revert { gas_used, output } =>
            bail!(
                "Contract deployment transaction reverts with gas_used {gas_used} and output {:#x}",
                output
            ),
        ExecutionResult::Halt { reason, gas_used } => bail!(
                "Contract deployment transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
                reason
            ),
        _ => unreachable!(),
    };

    evm.env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TransactTo::Call(contract),
        data: calldata.into(),
        ..Default::default()
    };

    let result = evm.transact_commit().unwrap();
    log::info!("EVM result: {result:?}");
    match result {
        ExecutionResult::Success {
            gas_used,
            output: Output::Call(bytes),
            ..
        } => Ok((gas_used, bytes.to_vec())),
        ExecutionResult::Revert { gas_used, output } => bail!(
            "Contract call transaction reverts with gas_used {gas_used} and output {:#x}",
            output
        ),
        ExecutionResult::Halt { reason, gas_used } => bail!(
            "Contract call transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
            reason
        ),
        _ => unreachable!(),
    }
}
