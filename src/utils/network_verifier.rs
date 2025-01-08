use alloy::consensus::Transaction;
use alloy::primitives::map::{HashMap, HashSet};
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder};

#[derive(Default)]
pub struct NetworkVerifier {
    pub l1_rpc: Option<String>,
    pub l2_rpc: Option<String>,

    pub create2_aliases: HashMap<Address, HashSet<FixedBytes<32>>>,
}

impl NetworkVerifier {
    pub fn add_l1_network_rpc(&mut self, network_rpc: String) {
        self.l1_rpc = Some(network_rpc);
    }
    pub fn add_l2_network_rpc(&mut self, network_rpc: String) {
        self.l2_rpc = Some(network_rpc);
    }

    pub async fn get_era_chain_id(&self) -> Option<u64> {
        if let Some(network) = self.l2_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());
            let chain_id = provider.get_chain_id().await.unwrap();
            Some(chain_id)
        } else {
            None
        }
    }

    pub async fn get_l1_chain_id(&self) -> Option<u64> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());
            let chain_id = provider.get_chain_id().await.unwrap();
            Some(chain_id)
        } else {
            None
        }
    }

    pub async fn get_bytecode_hash_at(&self, address: &Address) -> Option<FixedBytes<32>> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());
            let code = provider.get_code_at(address.clone()).await.unwrap();
            if code.len() == 0 {
                // if connected and address has no bytecode - should return 0s.
                Some(FixedBytes::ZERO)
            } else {
                Some(keccak256(&code))
            }
        } else {
            // should return None if not connected.
            None
        }
    }

    pub async fn get_possible_create2_bytecode_hashes(
        &self,
        address: &Address,
    ) -> HashSet<FixedBytes<32>> {
        self.create2_aliases
            .get(address)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn storage_at(
        &self,
        address: &Address,
        key: &FixedBytes<32>,
    ) -> Option<FixedBytes<32>> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());

            let storage = provider
                .get_storage_at(address.clone(), U256::from_be_bytes(key.0))
                .await
                .unwrap();

            Some(FixedBytes::from_slice(&storage.to_be_bytes_vec()))
        } else {
            None
        }
    }

    fn compute_hash_with_arguments(
        &self,
        input: &Bytes,
        num_arguments: usize,
    ) -> Option<FixedBytes<32>> {
        if input.len() < (num_arguments + 2) * 32 {
            None
        } else {
            let after_32_bytes = &input[32..input.len() - 32 * num_arguments];
            Some(keccak256(after_32_bytes))
        }
    }

    pub async fn check_crate2_deploy(
        &self,
        transaction: &str,
        expected_create2_address: &Address,
        expected_create2_salt: &FixedBytes<32>,
    ) -> Option<(Address, HashSet<FixedBytes<32>>)> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let tx_hash: TxHash = transaction.parse().unwrap();
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());

            let tx = provider
                .get_transaction_by_hash(tx_hash)
                .await
                .unwrap()
                .unwrap();

            if tx.to() != Some(expected_create2_address.clone()) {
                return None;
            }

            //  this is l1 nullifier dev.

            // We don't know how many constructor arguments where there, so we'll try to guess.

            let mut hashes = HashSet::default();
            for num_arguments in 0..10 {
                if let Some(hash) = self.compute_hash_with_arguments(tx.input(), num_arguments) {
                    hashes.insert(hash);
                } else {
                    break;
                }
            }
            // Compute address
            let mut address_payload = vec![0xff as u8];
            let destination = tx.to().unwrap();

            address_payload.extend_from_slice(destination.as_slice());

            let salt = &tx.input()[0..32];
            if salt != expected_create2_salt.as_slice() {
                println!("Salt mismatch: {:?} != {:?}", salt, expected_create2_salt);
                return None;
            }

            // Extract salt
            address_payload.extend_from_slice(&tx.input()[0..32]);
            // And hash the rest.
            address_payload.extend_from_slice(&keccak256(&tx.input()[32..]).0);

            // compute create2 address
            let address = Address::from_slice(&keccak256(address_payload).0[12..]);
            Some((address, hashes))
        } else {
            None
        }
    }
}
