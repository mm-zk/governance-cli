use alloy::primitives::{keccak256, Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};

#[derive(Default)]
pub struct NetworkVerifier {
    pub network_rpc: Option<String>,
}

impl NetworkVerifier {
    pub fn add_network_rpc(&mut self, network_rpc: String) {
        self.network_rpc = Some(network_rpc);
    }

    pub fn get_era_chain_id(&self) -> Option<u32> {
        //return Some(13);
        return None;
    }

    pub async fn get_l1_chain_id(&self) -> Option<u64> {
        if let Some(network) = self.network_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());
            let chain_id = provider.get_chain_id().await.unwrap();
            Some(chain_id)
        } else {
            None
        }
    }

    pub async fn get_bytecode_hash_at(&self, address: &Address) -> Option<FixedBytes<32>> {
        if let Some(network) = self.network_rpc.as_ref() {
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

    pub async fn storage_at(
        &self,
        address: &Address,
        key: &FixedBytes<32>,
    ) -> Option<FixedBytes<32>> {
        if let Some(network) = self.network_rpc.as_ref() {
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
}
