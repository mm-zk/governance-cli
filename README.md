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
cargo run -- --ecosystem-toml data/p2/gateway-upgrade-ecosystem.toml --l1-rpc http://localhost:8545 --era-commit 26cc4e4ba641f1695c52cf249e9278207d403d9d --contracts-commit 69ea2c61ae0e84da982493427bf39b6e62632de5
```




## Features
- gets the bytecode hashes (for system contracts) from github - and compares them.
