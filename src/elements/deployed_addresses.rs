use crate::{traits::Verify, utils::address_verifier::AddressVerifier};
use alloy::primitives::Address;
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

    fn verify_single_address(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        address: &Address,
        expected_file: &str,
    ) -> anyhow::Result<()> {
        let bytecode_hash = verifiers.network_verifier.get_bytecode_hash_at(address);
        match bytecode_hash {
            Some(bytecode_hash) => {
                let original_file = verifiers
                    .bytecode_verifier
                    .bytecode_hash_to_file(&bytecode_hash);
                match original_file {
                    Some(file) => {
                        if file == expected_file {
                            result.report_ok(expected_file);
                        } else {
                            result.report_error(&format!(
                                "{} has bytecode from wrong file: {}",
                                expected_file, file
                            ));
                        }
                    }
                    None => result.report_warn("Unknown bytecode hash"),
                }
            }
            None => result.report_warn(&format!(
                "Cannot check bytecode for {} at {}",
                expected_file, address
            )),
        };
        Ok(())
    }
}

impl Verify for DeployedAddresses {
    fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        self.verify_single_address(
            verifiers,
            result,
            &self.native_token_vault_addr,
            "NativeTokenVault.sol",
        )?;

        self.verify_single_address(
            verifiers,
            result,
            &self.validator_timelock_addr,
            "ValidatorTimelock.sol",
        )?;

        self.verify_single_address(
            verifiers,
            result,
            &self.bridges.shared_bridge_proxy_addr,
            "SharedBridgeProxy.sol",
        )?;
        self.verify_single_address(
            verifiers,
            result,
            &self.bridgehub.ctm_deployment_tracker_proxy_addr,
            "CtmDeploymentTrackerProxy.sol",
        )?;

        // TODO: verify that each address has actually something deployed.
        result.report_ok("deployed addresses");
        Ok(())
    }
}
