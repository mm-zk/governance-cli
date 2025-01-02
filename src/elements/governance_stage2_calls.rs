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
                "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
                "upgrade(address,address)",
            ),
            (
                "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
                "upgradeAndCall(address,address,bytes)",
            ),
            (
                "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
                "upgrade(address,address)",
            ),
            (
                "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
                "upgrade(address,address)",
            ),
            (
                "Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
                "setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes),bytes))",
            ),
            (
                "Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
                "setValidatorTimelock(address)",
            ),
            (
                "Unknown: 0xf4c557C9DB802bfabC9A1AD569E284f8edC93cAd",
                "setAddresses(address,address,address)",
            ),
            (
                "Unknown: 0xa5699243143b21E6863018971B2FCABCCC9997A9",
                "setL1NativeTokenVault(address)",
            ),
            (
                "Unknown: 0xa5699243143b21E6863018971B2FCABCCC9997A9",
                "setL1AssetRouter(address)",
            ),
            (
                "Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
                "setProtocolVersionDeadline(uint256,uint256)",
            ),
            (
                "Unknown: 0xa25E32103B151F39352b7e9af1700B7a4743931c",
                "checkDeadline()",
            ),
        ];

        self.calls
            .verify(list_of_calls.into(), verifiers, result)
            .unwrap();

        Ok(())
    }
}
