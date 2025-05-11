This crate uses artifacts that are built for `mp2-v1/test-contracts/src/Simple.sol`
contract:

* `mp2-v1/test-contracts/src/Simple.abi`
* `mp2-v1/Simple.bin`.

They were generated with the following version of `solc`:

```
solc --version
solc, the solidity compiler commandline interface
Version: 0.8.30+commit.73712a01.Darwin.appleclang
```

To regenerate these files, run:

```
solc --optimize --abi --bin ./mp2-v1/test-contracts/src/Simple.sol -o ./mp2-v1/test-contracts/src/
```
