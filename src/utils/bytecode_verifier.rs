use alloy::hex;
use alloy::primitives::{map::HashMap, FixedBytes};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

#[derive(Default)]
pub struct BytecodeVerifier {
    pub bytecode_hash_to_file: HashMap<FixedBytes<32>, String>,
    //pub contract_hashes: Option<SystemContractHashes>,
}

impl BytecodeVerifier {
    pub fn bytecode_hash_to_file(&self, bytecode_hash: &FixedBytes<32>) -> Option<&String> {
        self.bytecode_hash_to_file.get(bytecode_hash)
    }

    pub fn add_bytecode_hash(&mut self, bytecode_hash: FixedBytes<32>, file: String) {
        self.bytecode_hash_to_file.insert(bytecode_hash, file);
    }

    pub async fn init_from_github(&mut self, commit: &str) {
        let contract_hashes = SystemContractHashes::init_from_github(commit).await;

        for hash in contract_hashes.hashes {
            let bytecode_hash =
                FixedBytes::try_from(hex::decode(&hash.bytecode_hash).unwrap().as_slice()).unwrap();
            self.add_bytecode_hash(bytecode_hash, hash.contract_name);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemContractHash {
    #[serde(rename = "contractName")]
    pub contract_name: String,
    #[serde(rename = "bytecodePath")]
    pub bytecode_path: String,
    #[serde(rename = "bytecodeHash")]
    pub bytecode_hash: String,
}

#[derive(Debug)]
pub struct SystemContractHashes {
    pub hashes: Vec<SystemContractHash>,
}

impl SystemContractHashes {
    pub async fn init_from_github(commit: &str) -> Self {
        let contents = Self::get_contents(commit).await;
        Self {
            hashes: serde_json::from_str(&contents).expect("Failed to parse JSON"),
        }
    }

    async fn get_contents(commit: &str) -> String {
        let url = format!(
            "https://raw.githubusercontent.com/matter-labs/era-contracts/{}/system-contracts/SystemContractsHashes.json",
            commit
        );

        let cache_path = Path::new("cache");
        fs::create_dir_all(cache_path).expect("Failed to create cache directory");

        let cache_file_path = cache_path.join(format!("SystemContractHashes-{}.json", commit));

        if !cache_file_path.exists() {
            let response = reqwest::get(url).await.unwrap();

            let mut file =
                File::create(cache_file_path.clone()).expect("Failed to create cache file");
            let data = response.bytes().await.unwrap();
            file.write_all(&data).unwrap();
        }

        let data = fs::read_to_string(&cache_file_path).expect("Failed to read cache file");
        return data;
    }
}
