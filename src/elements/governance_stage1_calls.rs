use alloy::sol_types::SolCall;

use crate::{
    elements::{
        protocol_version::ProtocolVersion, set_new_version_upgrade::upgradeCall,
        upgrade_deadline::UpgradeDeadline,
    },
    traits::Verify,
};

use super::{
    call_list::CallList, governance_stage2_calls::setValidatorTimelockCall,
    set_new_version_upgrade::setNewVersionUpgradeCall,
};

pub struct GovernanceStage1Calls {
    pub calls: CallList,
}

impl Verify for GovernanceStage1Calls {
    async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 1 calls ===");

        let list_of_calls = [
            ("validator_timelock", "acceptOwnership()"),
            ("shared_bridge_proxy", "acceptOwnership()"),
            ("ctm_deployment_tracker", "acceptOwnership()"),
            ("rollup_da_manager", "acceptOwnership()"),
            ("state_transition_manager",
            "setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256,uint256,uint256)"),
            (
                "state_transition_manager",
                "setValidatorTimelock(address)",
            ),
            ("upgrade_timer", "startTimer()"),

        ];

        self.calls.verify(list_of_calls.into(), verifiers, result)?;

        // The only - non-trivial call is setNewVersionUpgrade.

        let calldata = &self.calls.elems[4].data;
        let data = setNewVersionUpgradeCall::abi_decode(calldata, true).unwrap();

        //println!("Call: {:?} ", data.diamondCut);

        {
            let decoded =
                setValidatorTimelockCall::abi_decode(&self.calls.elems[5].data, true).unwrap();

            result.expect_address(verifiers, &decoded.addr, "validator_timelock");
        }

        let deadline = UpgradeDeadline {
            deadline: data.oldProtocolVersionDeadline,
        };
        let old_protocol_version: ProtocolVersion = data.oldProtocolVersion.into();
        let new_protocol_version: ProtocolVersion = data.newProtocolVersion.into();
        result.print_info(&format!(
            "Protocol versions: from: {} to: {} deadline: {}",
            old_protocol_version, new_protocol_version, deadline
        ));
        if !deadline.deadline_within_day_range(3, 14) {
            result.report_warn(&format!(
                "Expected upgrade deadline to be within 3 - 14 days from now, but it is {}",
                deadline
            ));
        }

        let diamond_cut = data.diamondCut;

        let upgrade = upgradeCall::abi_decode(&diamond_cut.initCalldata, true).unwrap();

        upgrade
            ._proposedUpgrade
            .verify_transaction(verifiers, result)
            .await?;

        Ok(())
    }
}
