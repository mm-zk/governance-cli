use crate::{traits::Verify, utils::address_verifier::AddressVerifier};
use alloy::primitives::Address;
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
}

impl Verify for DeployedAddresses {
    async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result
            .expect_deployed_proxy_with_bytecode(
                verifiers,
                &self.native_token_vault_addr,
                "NativeTokenVault.sol",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.validator_timelock_addr,
                "ValidatorTimelock",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.l2_wrapped_base_token_store_addr,
                "L2WrappedBaseTokenStore",
            )
            .await;

        result
            .expect_deployed_proxy_with_bytecode(
                verifiers,
                &self.bridgehub.ctm_deployment_tracker_proxy_addr,
                "CtmDeploymentTrackerProxy.sol",
            )
            .await;

        self.bridges.verify(verifiers, result).await?;
        self.bridgehub.verify(verifiers, result).await?;
        self.state_transition.verify(verifiers, result).await?;

        // TODO: verify that each address has actually something deployed.
        result.report_ok("deployed addresses");
        Ok(())
    }
}

impl Verify for Bridges {
    async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result
            .expect_deployed_proxy_with_bytecode(
                verifiers,
                &self.shared_bridge_proxy_addr,
                "SharedBridgeProxy.sol",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.l1_nullifier_implementation_addr,
                "L1Nullifier",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.erc20_bridge_implementation_addr,
                "ERC20Bridge",
            )
            .await;

        Ok(())
    }
}

impl Verify for Bridgehub {
    async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result
            .expect_deployed_proxy_with_bytecode(
                verifiers,
                &self.ctm_deployment_tracker_proxy_addr,
                "CTMDeploymentTracker",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.bridgehub_implementation_addr,
                "BridgehubImplementation",
            )
            .await;

        Ok(())
    }
}

impl Verify for StateTransition {
    async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result
            .expect_deployed_bytecode(verifiers, &self.verifier_addr, "Verifier")
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.state_transition_implementation_addr,
                "StateTransitionImpl",
            )
            .await;
        result
            .expect_deployed_bytecode(verifiers, &self.genesis_upgrade_addr, "L1GenesisUpgrade")
            .await;

        Ok(())
    }
}
