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
    pub admin_facet_addr: Address,
    pub default_upgrade_addr: Address,
    pub diamond_init_addr: Address,
    pub executor_facet_addr: Address,
    pub genesis_upgrade_addr: Address,
    pub getters_facet_addr: Address,
    pub mailbox_facet_addr: Address,
    pub state_transition_implementation_addr: Address,
    pub verifier_addr: Address,
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

        address_verifier.add_address(
            self.l2_wrapped_base_token_store_addr,
            "l2_wrapped_base_token_store",
        );

        address_verifier.add_address(
            self.bridges.l1_nullifier_implementation_addr,
            "l1_nullifier_implementation_addr",
        );
        address_verifier.add_address(
            self.bridges.erc20_bridge_implementation_addr,
            "erc20_bridge_implementation_addr",
        );
        self.state_transition.add_to_verifier(address_verifier);
    }
}

impl StateTransition {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        address_verifier.add_address(self.admin_facet_addr, "admin_facet");
        address_verifier.add_address(self.default_upgrade_addr, "default_upgrade");
        address_verifier.add_address(self.diamond_init_addr, "diamond_init");
        address_verifier.add_address(self.executor_facet_addr, "executor_facet");
        address_verifier.add_address(self.genesis_upgrade_addr, "genesis_upgrade_addr");
        address_verifier.add_address(self.getters_facet_addr, "getters_facet");
        address_verifier.add_address(self.mailbox_facet_addr, "mailbox_facet");
        address_verifier.add_address(
            self.state_transition_implementation_addr,
            "state_transition_implementation_addr",
        );
        address_verifier.add_address(self.verifier_addr, "verifier");
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
                "l1-contracts/L1NativeTokenVault",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.validator_timelock_addr,
                "l1-contracts/ValidatorTimelock",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.l2_wrapped_base_token_store_addr,
                "l1-contracts/L2WrappedBaseTokenStore",
            )
            .await;

        result
            .expect_deployed_proxy_with_bytecode(
                verifiers,
                &self.bridgehub.ctm_deployment_tracker_proxy_addr,
                "l1-contracts/CTMDeploymentTracker",
            )
            .await;

        self.bridges.verify(verifiers, result).await?;
        self.bridgehub.verify(verifiers, result).await?;
        self.state_transition.verify(verifiers, result).await?;

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
                "l1-contracts/L1AssetRouter",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.l1_nullifier_implementation_addr,
                if verifiers.testnet_contracts {
                    "l1-contracts/L1NullifierDev"
                } else {
                    "l1-contracts/L1Nullifier"
                },
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.erc20_bridge_implementation_addr,
                "l1-contracts/L1ERC20Bridge",
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
                "l1-contracts/CTMDeploymentTracker",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.bridgehub_implementation_addr,
                "l1-contracts/Bridgehub",
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
            .expect_deployed_bytecode(
                verifiers,
                &self.verifier_addr,
                if verifiers.testnet_contracts {
                    "l1-contracts/TestnetVerifier"
                } else {
                    "l1-contracts/Verifier"
                },
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.state_transition_implementation_addr,
                "l1-contracts/ChainTypeManager",
            )
            .await;
        result
            .expect_deployed_bytecode(
                verifiers,
                &self.genesis_upgrade_addr,
                "l1-contracts/L1GenesisUpgrade",
            )
            .await;

        result
            .expect_deployed_bytecode(verifiers, &self.admin_facet_addr, "l1-contracts/AdminFacet")
            .await;
        result
            .expect_deployed_bytecode(
                verifiers,
                &self.default_upgrade_addr,
                "l1-contracts/DefaultUpgrade",
            )
            .await;
        result
            .expect_deployed_bytecode(
                verifiers,
                &self.diamond_init_addr,
                "l1-contracts/DiamondInit",
            )
            .await;
        result
            .expect_deployed_bytecode(
                verifiers,
                &self.executor_facet_addr,
                "l1-contracts/ExecutorFacet",
            )
            .await;
        result
            .expect_deployed_bytecode(
                verifiers,
                &self.getters_facet_addr,
                "l1-contracts/GettersFacet",
            )
            .await;
        result
            .expect_deployed_bytecode(
                verifiers,
                &self.mailbox_facet_addr,
                "l1-contracts/MailboxFacet",
            )
            .await;

        Ok(())
    }
}
