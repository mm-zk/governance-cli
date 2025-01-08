# Governance upgrade CLI tool

Tool to analyze the zkSync upgrades.



First, you need to get the gateway-upgrade-ecosystem.toml file.
(you can find it in contracts/l1-contracts/script-config/gateway-upgrade-ecosystem.toml )


## Example use:

To just verify the file (without access to any rpc)

```
cargo run -- --ecosystem-toml data/p2/gateway-upgrade-ecosystem.toml
```

If you want to verify the bytecodes:
```
cargo run -- --ecosystem-toml data/p2/gateway-upgrade-ecosystem.toml --l1-rpc http://localhost:8545
```


You might also provide own commits - for the tool to fetch the bytecode hashes from
```
cargo run -- --ecosystem-toml data/p2/gateway-upgrade-ecosystem.toml --l1-rpc http://localhost:8545 --contracts-commit 1d24f1a92970fd359ddcbf0891eb6c66946a6c82 --era-commit 69ea2c61ae0e84da982493427bf39b6e62632de5 --create2-txs-file data/p2/tx_hashes.txt
```

For full verification of the bytecodes, you should also provide the tx_hashes file, that was computed from your broadcast file, that contains all the CREATE2 call transaction hashes.



## Features
- gets the bytecode hashes (for system contracts) from github - and compares them.
