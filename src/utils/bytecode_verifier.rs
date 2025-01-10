use alloy::hex;
use alloy::primitives::{map::HashMap, FixedBytes};
use serde::{Deserialize, Serialize};

use super::get_contents_from_github;

#[derive(Default)]
pub struct BytecodeVerifier {
    pub bytecode_hash_to_file: HashMap<FixedBytes<32>, String>,
    pub bytecode_file_to_zkhash: HashMap<String, FixedBytes<32>>,
}

impl BytecodeVerifier {
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
