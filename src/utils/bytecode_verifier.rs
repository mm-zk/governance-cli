use alloy::hex;
use alloy::primitives::{keccak256, Bytes};
use alloy::primitives::{map::HashMap, FixedBytes};
use serde::{Deserialize, Serialize};

use super::{compute_hash_with_arguments, get_contents_from_github};

#[derive(Default)]
pub struct BytecodeVerifier {
    pub bytecode_hash_to_file: HashMap<FixedBytes<32>, String>,
    pub bytecode_file_to_zkhash: HashMap<String, FixedBytes<32>>,
}

impl BytecodeVerifier {
    // Tries to parse the `maybe_bytecode` as the init code.
    pub fn try_parse_bytecode(&self, maybe_bytecode: &[u8]) -> Option<(String, Vec<u8>)> {
        // We do not know how many params there were, we just brute force from 0 to 10
        for i in 0..10 {
            if let Some(h) = compute_hash_with_arguments(&Bytes::copy_from_slice(maybe_bytecode), i) {
                if let Some(name) = self.bytecode_hash_to_file.get(&h) {
                    return Some((
                        name.clone(),
                        maybe_bytecode[maybe_bytecode.len() - 32 * i..].to_vec()
                    ));
                }
            }
        }

        None
    }

    fn get_create2_and_transfer_bytecode(&self) -> Vec<u8> {
        // We generally try to not rely on bytecodes of the contracts, but in this case
        // it is the most efficient way.
        let create2_and_transfer_bytecode = hex::decode("60a060405234801561000f575f80fd5b506040516102c03803806102c083398101604081905261002e9161012e565b5f828451602086015ff590506001600160a01b0381166100945760405162461bcd60e51b815260206004820152601960248201527f437265617465323a204661696c6564206f6e206465706c6f7900000000000000604482015260640160405180910390fd5b60405163f2fde38b60e01b81526001600160a01b03838116600483015282169063f2fde38b906024015f604051808303815f87803b1580156100d4575f80fd5b505af11580156100e6573d5f803e3d5ffd5b505050506001600160a01b031660805250610209915050565b634e487b7160e01b5f52604160045260245ffd5b80516001600160a01b0381168114610129575f80fd5b919050565b5f805f60608486031215610140575f80fd5b83516001600160401b0380821115610156575f80fd5b818601915086601f830112610169575f80fd5b81518181111561017b5761017b6100ff565b604051601f8201601f19908116603f011681019083821181831017156101a3576101a36100ff565b816040528281526020935089848487010111156101be575f80fd5b5f91505b828210156101df57848201840151818301850152908301906101c2565b5f848483010152809750505050808601519350505061020060408501610113565b90509250925092565b60805160a261021e5f395f602e015260a25ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c80638efc30f914602a575b5f80fd5b60507f000000000000000000000000000000000000000000000000000000000000000081565b6040516001600160a01b03909116815260200160405180910390f3fea2646970667358221220fd100d8cba14d94be3a7e02be2024b2005374d099be5d61a3beb1aa4690ab94064736f6c63430008180033").unwrap();


        // But just in case, we'll cross check the result
        assert!(self.bytecode_hash_to_file(&keccak256(&create2_and_transfer_bytecode)).unwrap() == "l1-contracts/Create2AndTransfer");

        create2_and_transfer_bytecode
    }

    pub fn is_create2_and_transfer_bytecode_prefix<'a>(&self, slice: &'a[u8]) -> Option<&'a[u8]> {
        let bytecode = self.get_create2_and_transfer_bytecode();

        if slice.len() < bytecode.len() {
            return None;
        }

        if bytecode != slice[..bytecode.len()] {
            return None;
        }

        return Some(&slice[bytecode.len()..])
    }

    // // Tries to find the bytecode that is a prefix of the provided slice.
    // // If found, returns the name of the bytecode + the rest of the slice
    // // Note, that this method is very inefficient and only suitable for bytecodes that are known to be short.
    // pub fn try_parse_bytecode_starting_from_pos<'a>(&self, maybe_bytecode: &'a[u8]) -> Option<(String, &'a[u8])> {
    //     let mut pos = 32;
    //     while pos < maybe_bytecode.len() {
    //         let potential_bytecode = keccak256(&maybe_bytecode[..pos]);
    //         if let Some(x) = self.bytecode_hash_to_file(&potential_bytecode) {
    //             return Some((x.clone(), &maybe_bytecode[pos..]));
    //         }
    //         pos += 32;
    //     }
    //     None
    // }

    pub fn bytecode_hash_to_file(&self, bytecode_hash: &FixedBytes<32>) -> Option<&String> {
        self.bytecode_hash_to_file.get(bytecode_hash)
    }

    pub fn add_bytecode_hash(&mut self, bytecode_hash: FixedBytes<32>, file: String) {
        self.bytecode_hash_to_file
            .insert(bytecode_hash, file.clone());
    }

    pub async fn init_from_github(&mut self, commit: &str) {
        let contract_hashes = ContractHashes::init_from_github(commit).await;
        for contract_hash in contract_hashes.hashes {
            for maybe_hash in [
                &contract_hash.evm_bytecode_hash,
                &contract_hash.evm_deployed_bytecode_hash,
                &contract_hash.zk_bytecode_hash,
            ] {
                if let Some(hash) = maybe_hash {
                    let bytecode_hash =
                        FixedBytes::try_from(hex::decode(&hash).unwrap().as_slice()).unwrap();
                    self.add_bytecode_hash(bytecode_hash, contract_hash.contract_name.clone());
                }
            }
            if let Some(hash) = &contract_hash.zk_bytecode_hash {
                let bytecode_hash =
                    FixedBytes::try_from(hex::decode(&hash).unwrap().as_slice()).unwrap();
                self.bytecode_file_to_zkhash
                    .insert(contract_hash.contract_name, bytecode_hash);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractHash {
    #[serde(rename = "contractName")]
    pub contract_name: String,
    #[serde(rename = "evmBytecodeHash")]
    pub evm_bytecode_hash: Option<String>,
    #[serde(rename = "evmDeployedBytecodeHash")]
    pub evm_deployed_bytecode_hash: Option<String>,
    #[serde(rename = "zkBytecodeHash")]
    pub zk_bytecode_hash: Option<String>,
}

#[derive(Debug)]
pub struct ContractHashes {
    pub hashes: Vec<ContractHash>,
}

impl ContractHashes {
    pub async fn init_from_github(commit: &str) -> Self {
        let contents = Self::get_contents(commit).await;
        Self {
            hashes: serde_json::from_str(&contents).expect("Failed to parse JSON"),
        }
    }

    async fn get_contents(commit: &str) -> String {
        get_contents_from_github(
            commit,
            "matter-labs/era-contracts",
            "AllContractsHashes.json",
        )
        .await
    }
}


// cargo run -- --ecosystem-yaml data/gateway_ecosystem_upgrade_output.yaml --l1-rpc $SEPOLIA --contracts-commit 5ece924c7936833b564e305f0609fe1fdfc1677c --era-commit 4a67c91e32a6930865c0f8bd6fcec4c1f1ff60dd --l2-chain-id 270 --testnet-contracts  --bridgehub-address 0x236D1c3Ff32Bd0Ca26b72Af287E895627c0478cE