# Governance upgrade CLI tool

Tool to analyze the zkSync upgrades.



First, you need to get the gateway_ecosystem_upgrade_output.yaml file.
(you can find it in zksync-era/configs )


## Example use:

To just verify the file (without access to any rpc)

```
cargo run -- --ecosystem-yaml data/gateway_ecosystem_upgrade_output.yaml 
```

If you want to verify the bytecodes:
```
cargo run -- --ecosystem-yaml data/gateway_ecosystem_upgrade_output.yaml  --l1-rpc http://localhost:8545
```


You might also provide own commits - for the tool to fetch the bytecode hashes from
```
cargo run -- --ecosystem-yaml data/gateway_ecosystem_upgrade_output.yaml  --l1-rpc http://localhost:8545 --contracts-commit 1d24f1a92970fd359ddcbf0891eb6c66946a6c82 --era-commit 69ea2c61ae0e84da982493427bf39b6e62632de5 --create2-txs-file data/p2/tx_hashes.txt
```

You might also want to specify the l2 chain id (or l2 RPC URL), and testnet-contracts (if deploying on testnet without proofs), and bridgehub address - for final verification.

```
cargo run -- --ecosystem-yaml data/gateway_ecosystem_upgrade_output.yaml --l1-rpc http://localhost:8545 --contracts-commit 2cc0621acf3ccd0536bfd01999727753d1447931 --era-commit 0efe1db5126bc2d2b0702a1404f7eb0ca0231ef0 --l2-chain-id 270 --testnet-contracts  --bridgehub-address 0xb244E9B485fc872e3242960b786dB5189f6A6d2A
```


## Features
- gets the bytecode hashes (for system contracts) from github - and compares them.
