use crate::utils::address_verifier::AddressVerifier;
use alloy::{
    hex::{self, ToHexExt},
    primitives::Address,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DeployedAddresses {
    native_token_vault_addr: Address,
    validator_timelock_addr: Address,
    bridges: Bridges,
    bridgehub: Bridgehub,
}

#[derive(Debug, Deserialize)]
pub struct Bridges {
    shared_bridge_proxy_addr: Address,
}
#[derive(Debug, Deserialize)]
pub struct Bridgehub {
    ctm_deployment_tracker_proxy_addr: Address,
}

impl DeployedAddresses {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        address_verifier.add_address(self.native_token_vault_addr, "native_token_vault");
        address_verifier.add_address(self.validator_timelock_addr, "validator_timelock");
        address_verifier.add_address(self.bridges.shared_bridge_proxy_addr, "shared_bridge_proxy");
        address_verifier.add_address(
            self.bridgehub.ctm_deployment_tracker_proxy_addr,
            "ctm_deployment_tracker",
        );
    }
}
