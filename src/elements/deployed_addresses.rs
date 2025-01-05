use std::panic::Location;

use crate::{traits::Verify, utils::address_verifier::AddressVerifier};
use alloy::primitives::{Address, FixedBytes};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DeployedAddresses {
    native_token_vault_addr: Address,
    validator_timelock_addr: Address,
    l2_wrapped_base_token_store_addr: Address,
    bridges: Bridges,
    bridgehub: Bridgehub,
    state_transition: StateTransition,
}

#[derive(Debug, Deserialize)]
pub struct Bridges {
    shared_bridge_proxy_addr: Address,
    pub l1_nullifier_implementation_addr: Address,
    pub erc20_bridge_implementation_addr: Address,
}
#[derive(Debug, Deserialize)]
pub struct Bridgehub {
    ctm_deployment_tracker_proxy_addr: Address,
    bridgehub_implementation_addr: Address,
}

#[derive(Debug, Deserialize)]
pub struct StateTransition {
    pub verifier_addr: Address,
    pub state_transition_implementation_addr: Address,

    pub genesis_upgrade_addr: Address,
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
        address_verifier.add_address(
            self.bridgehub.bridgehub_implementation_addr,
            "bridgehub_implementation_addr",
        );
        address_verifier.add_address(self.state_transition.verifier_addr, "verifier");

        address_verifier.add_address(
            self.l2_wrapped_base_token_store_addr,
            "l2_wrapped_base_token_store",
        );

        address_verifier.add_address(
            self.state_transition.state_transition_implementation_addr,
            "state_transition_implementation_addr",
        );
        address_verifier.add_address(
            self.bridges.l1_nullifier_implementation_addr,
            "l1_nullifier_implementation_addr",
        );
        address_verifier.add_address(
            self.bridges.erc20_bridge_implementation_addr,
            "erc20_bridge_implementation_addr",
        );
        address_verifier.add_address(
            self.state_transition.genesis_upgrade_addr,
            "genesis_upgrade_addr",
        );
    }

    //#[track_caller]
    async fn verify_single_address(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        address: &Address,
        expected_file: &str,
    ) -> anyhow::Result<()> {
        let bytecode_hash = verifiers
            .network_verifier
            .get_bytecode_hash_at(address)
            .await;
        match bytecode_hash {
            Some(bytecode_hash) => {
                println!(
                    "Checking bytecode for {} at {} l1 hash: {}",
                    expected_file, address, bytecode_hash
                );
                if bytecode_hash == FixedBytes::ZERO {
                    result.report_warn(&format!(
                        "Bytecode hash at {} is zero - expected code {} at {}",
                        address,
                        expected_file,
                        Location::caller()
                    ));
                    return Ok(());
                } else {
                    let original_file = verifiers
                        .bytecode_verifier
                        .bytecode_hash_to_file(&bytecode_hash);
                    match original_file {
                        Some(file) => {
                            if file == expected_file {
                                result.report_ok(expected_file);
                            } else {
                                result.report_error(&format!(
                                    "{} has bytecode from wrong file: {} at {}",
                                    expected_file,
                                    file,
                                    Location::caller()
                                ));
                            }
                        }
                        None => result.report_warn(&format!(
                            "Unknown bytecode hash at address {} - {} - at {}",
                            address,
                            bytecode_hash,
                            Location::caller()
                        )),
                    }
                }
            }
            None => result.report_warn(&format!(
                "No RPC connection - Cannot check bytecode for {} at {}",
                expected_file, address
            )),
        };
        Ok(())
    }
}

impl Verify for DeployedAddresses {
    async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        self.verify_single_address(
            verifiers,
            result,
            &self.native_token_vault_addr,
            "NativeTokenVault.sol",
        )
        .await?;

        self.verify_single_address(
            verifiers,
            result,
            &self.validator_timelock_addr,
            "ValidatorTimelock",
        )
        .await?;

        self.verify_single_address(
            verifiers,
            result,
            &self.bridges.shared_bridge_proxy_addr,
            "SharedBridgeProxy.sol",
        )
        .await?;
        self.verify_single_address(
            verifiers,
            result,
            &self.bridgehub.ctm_deployment_tracker_proxy_addr,
            "CtmDeploymentTrackerProxy.sol",
        )
        .await?;

        // TODO: verify that each address has actually something deployed.
        result.report_ok("deployed addresses");
        Ok(())
    }
}
