use alloy::primitives::{Address, FixedBytes};
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

    pub fn get_bytecode_hash_at(&self, _address: &Address) -> Option<FixedBytes<32>> {
        // should return None if not connected.
        // if connected and address has no bytecode -shoudl return 0s.
        None
    }
}
