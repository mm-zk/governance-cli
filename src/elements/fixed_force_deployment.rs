use alloy::{
    primitives::{Address, U256},
    sol,
};

sol! {
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

impl FixedForceDeploymentsData {
    pub fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        match verifiers.network_verifier.get_era_chain_id() {
            Some(era_chain_id) => {
                if U256::from(era_chain_id) != self.eraChainId {
                    result.report_error(&format!(
                        "Era chain id mismatch: expected {}, got {}",
                        self.eraChainId, era_chain_id
                    ));
                }
            }
            None => {
                result.report_warn("Era chain id not verified");
            }
        }

        match verifiers.network_verifier.get_l1_chain_id() {
            Some(l1_chain_id) => {
                if U256::from(l1_chain_id) != self.l1ChainId {
                    result.report_error(&format!(
                        "L1 chain id mismatch: expected {}, got {}",
                        self.l1ChainId, l1_chain_id
                    ));
                }
            }
            None => {
                result.report_warn("L1 chain id not verified");
            }
        }

        result.expect_address(verifiers, &self.l1AssetRouter, "shared_bridge_proxy");
        result.expect_bytecode(
            verifiers,
            &self.l2TokenProxyBytecodeHash,
            "l2TokenProxyBytecode",
        );
        result.expect_address(verifiers, &self.aliasedL1Governance, "aliased_governance");

        if self.maxNumberOfZKChains != U256::from(100) {
            result.report_error("maxNumberOfZKChains must be 100");
        }

        result.expect_bytecode(verifiers, &self.bridgehubBytecodeHash, "Bridgehub.sol");
        result.expect_bytecode(
            verifiers,
            &self.l2AssetRouterBytecodeHash,
            "L2AssetRouter.sol",
        );
        result.expect_bytecode(verifiers, &self.l2NtvBytecodeHash, "L2NTV.sol");

        result.expect_bytecode(verifiers, &self.messageRootBytecodeHash, "MessageRoot.sol");

        result.expect_address(
            verifiers,
            &self.l2SharedBridgeLegacyImpl,
            "shared_bridge_legacy_impl",
        );

        result.expect_address(
            verifiers,
            &self.l2BridgedStandardERC20Impl,
            "erc20_bridged_standard",
        );

        if self.dangerousTestOnlyForcedBeacon != Address::ZERO {
            result.report_error("dangerousTestOnlyForcedBeacon must be 0");
        }

        Ok(())
    }
}
