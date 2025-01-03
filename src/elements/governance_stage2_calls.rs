use crate::traits::Verify;

use super::call_list::CallList;

pub struct GovernanceStage2Calls {
    pub calls: CallList,
}

impl Verify for GovernanceStage2Calls {
    fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 2 calls ===");
        let list_of_calls = [
            (
                "transparent_proxy_admin",
                "upgrade(address,address)",
            ),
            (
                "transparent_proxy_admin",
                "upgradeAndCall(address,address,bytes)",
            ),
            (
                "transparent_proxy_admin",
                "upgrade(address,address)",
            ),
            (
                "transparent_proxy_admin",
                "upgrade(address,address)",
            ),
            (
                "state_transition_manager",
                "setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes),bytes))",
            ),
            (
                "state_transition_manager",
                "setValidatorTimelock(address)",
            ),
            (
                "bridgehub_proxy",
                "setAddresses(address,address,address)",
            ),
            (
                "old_shared_bridge_proxy",
                "setL1NativeTokenVault(address)",
            ),
            (
                "old_shared_bridge_proxy",
                "setL1AssetRouter(address)",
            ),
            (
                "state_transition_manager",
                "setProtocolVersionDeadline(uint256,uint256)",
            ),
            (
                "upgrade_timer",
                "checkDeadline()",
            ),
        ];

        self.calls.verify(list_of_calls.into(), verifiers, result)?;

        Ok(())
    }
}
