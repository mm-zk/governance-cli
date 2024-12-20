use alloy::primitives::{map::HashMap, Address};

enum FixedAddresses {
    Bootloader = 0x8001,
    NonceHolder = 0x8003,
}

#[derive(Default)]
pub struct AddressVerifier {
    pub address_to_name: HashMap<Address, String>,
    pub name_to_address: HashMap<String, Address>,
}

impl AddressVerifier {
    pub fn reverse_lookup(&self, address: &Address) -> Option<&String> {
        self.address_to_name.get(address)
    }

    pub fn add_address(&mut self, address: Address, name: &str) {
        // TODO: accept that this should be empty.
        self.name_to_address.insert(name.to_string(), address);
        self.address_to_name.insert(address, name.to_string());
    }
}
