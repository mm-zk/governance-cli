use alloy::{dyn_abi::SolType, primitives::Bytes, sol};

use super::force_deployment::ForceDeployment;

sol! {


    #[derive(Debug)]
    struct GatewayUpgradeEncodedInput {
        ForceDeployment[] forceDeployments;
        uint256 l2GatewayUpgradePosition;
        bytes fixedForceDeploymentsData;
        address ctmDeployer;
        address oldValidatorTimelock;
        address newValidatorTimelock;
        address wrappedBaseTokenStore;
    }

    #[derive(Debug)]
    struct FixedForceDeploymentsData {
        uint256 l1ChainId;
        uint256 eraChainId;
        address l1AssetRouter;
        bytes32 l2TokenProxyBytecodeHash;
        address aliasedL1Governance;
        uint256 maxNumberOfZKChains;
        bytes32 bridgehubBytecodeHash;
        bytes32 l2AssetRouterBytecodeHash;
        bytes32 l2NtvBytecodeHash;
        bytes32 messageRootBytecodeHash;
        address l2SharedBridgeLegacyImpl;
        address l2BridgedStandardERC20Impl;
        // The forced beacon address. It is needed only for internal testing.
        // MUST be equal to 0 in production.
        // It will be the job of the governance to ensure that this value is set correctly.
        address dangerousTestOnlyForcedBeacon;
    }
}

pub struct PostUpgradeCalldata {
    pub gateway_upgrade_encoded_input: GatewayUpgradeEncodedInput,
}

impl PostUpgradeCalldata {
    pub fn parse(data: &Bytes) -> Self {
        PostUpgradeCalldata {
            gateway_upgrade_encoded_input: GatewayUpgradeEncodedInput::abi_decode(data, true)
                .unwrap(),
        }
    }

    pub fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        // TODO: verify all force deployments.
        // TODO: verify old timelock
        // TODO: verify gateway deployment position (what is this??)

        let addr = verifiers
            .address_verifier
            .name_or_unknown(&self.gateway_upgrade_encoded_input.ctmDeployer);
        if addr != "ctm_deployment_tracker" {
            result.report_error(&format!(
                "ctm_deployment_tracker is not the expected address. Got: {}",
                addr
            ));
        };

        let addr = verifiers
            .address_verifier
            .name_or_unknown(&self.gateway_upgrade_encoded_input.wrappedBaseTokenStore);
        if addr != "l2_wrapped_base_token_store" {
            result.report_error(&format!(
                "l2_wrapped_base_token_store is not the expected address. Got: {}",
                addr
            ));
        };

        let addr = verifiers
            .address_verifier
            .name_or_unknown(&self.gateway_upgrade_encoded_input.newValidatorTimelock);
        if addr != "validator_timelock" {
            result.report_error(&format!(
                "validator_timelock is not the expected address. Got: {}",
                addr
            ));
        };

        let fixed_force_deployments_data = FixedForceDeploymentsData::abi_decode(
            &self.gateway_upgrade_encoded_input.fixedForceDeploymentsData,
            true,
        )
        .unwrap();

        fixed_force_deployments_data.verify(verifiers, result)?;

        Ok(())
    }
}

impl FixedForceDeploymentsData {
    pub fn verify(
        &self,
        _verifiers: &crate::traits::Verifiers,
        _result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        // TODO: verify everything.
        Ok(())
    }
}
