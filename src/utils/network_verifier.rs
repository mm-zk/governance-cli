use alloy::primitives::{Address, FixedBytes};

#[derive(Default)]
pub struct NetworkVerifier {}

impl NetworkVerifier {
    pub fn get_era_chain_id(&self) -> Option<u32> {
        //return Some(13);
        return None;
    }

    pub fn get_bytecode_hash_at(&self, _address: &Address) -> Option<FixedBytes<32>> {
        // should return None if not connected.
        // if connected and address has no bytecode -shoudl return 0s.
        None
    }
}
