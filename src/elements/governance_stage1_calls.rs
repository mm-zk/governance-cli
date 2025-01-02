use crate::traits::Verify;

use super::call_list::CallList;

pub struct GovernanceStage1Calls {
    pub calls: CallList,
}

impl Verify for GovernanceStage1Calls {
    fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 1 calls ===");

        let list_of_calls = [
            ("validator_timelock", "acceptOwnership()"),
            ("shared_bridge_proxy", "acceptOwnership()"),
            ("ctm_deployment_tracker", "acceptOwnership()"),
            ("Unknown: 0x4b321AA7b13Da7A40737333085cC6d0aAC355DaB",
            "acceptOwnership()"),
            ("Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
            "setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256,uint256,uint256)"),
            ("Unknown: 0xa25E32103B151F39352b7e9af1700B7a4743931c", "startTimer()"),

        ];

        self.calls.verify(list_of_calls.into(), verifiers, result)?;

        // Now analyse the setNewVersionUpgrade call
        // TODO

        Ok(())
    }
}
