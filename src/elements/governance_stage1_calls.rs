use alloy::{hex, sol, sol_types::SolValue};

use crate::traits::{Verifiers, Verify};

sol! {

    #[derive(Debug)]
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    #[derive(Debug)]
    struct CallList {
        Call[] elems;
    }

}

impl CallList {
    pub fn parse(hex_data: &String) -> Self {
        CallList::abi_decode_sequence(&hex::decode(hex_data).unwrap(), false).unwrap()
    }
}

pub fn expect_simple_call(
    verifiers: &Verifiers,
    call: Option<Call>,
    target: &str,
    method_name: &str,
) -> Result<String, String> {
    match call {
        Some(call) => {
            let address_from_call = verifiers
                .address_verifier
                .address_to_name
                .get(&call.target)
                .unwrap_or(&format!("Unknown: {}", call.target))
                .clone();

            if target != address_from_call {
                return Err(format!(
                    "Expected call to: {} with data: {} not found - instead the call is to {}",
                    target, method_name, address_from_call
                ));
            }

            let method_selector = verifiers.selector_verifier.compute_selector(method_name);

            if call.data.len() < 4 {
                return Err(format!("Call data is too short"));
            }
            if hex::encode(&call.data[0..4]) != method_selector {
                return Err(format!(
                    "Expected call to: {} not found - instead the call selector was to {} - {}",
                    method_name,
                    hex::encode(&call.data[0..4]),
                    verifiers
                        .selector_verifier
                        .to_method_name(hex::encode(&call.data[0..4]))
                        .unwrap_or_default()
                ));
            }

            Ok(format!("Called {} with {}", target, method_name))
        }
        None => Err(format!(
            "Expected call to: {} with data: {} not found",
            target, method_name
        )),
    }
}

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

        // first, quickly analyze the calls - most of them should be simple without any args.
        let mut elems = std::collections::VecDeque::from(self.calls.elems.clone());

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            "validator_timelock",
            "acceptOwnership()",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            "shared_bridge_proxy",
            "acceptOwnership()",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            "ctm_deployment_tracker",
            "acceptOwnership()",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0x4b321AA7b13Da7A40737333085cC6d0aAC355DaB",
            "acceptOwnership()",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
      elems.pop_front(),
            // FIXME
            "Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
            "setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256,uint256,uint256)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa25E32103B151F39352b7e9af1700B7a4743931c",
            "startTimer()",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        if elems.len() != 0 {
            result.report_error("Too many calls in governance1.");
        }

        // Now analyse the setNewVersionUpgrade call
        // TODO

        Ok(())
    }
}

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

        let mut elems = std::collections::VecDeque::from(self.calls.elems.clone());

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
            "upgrade(address,address)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
            "upgradeAndCall(address,address,bytes)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
            "upgrade(address,address)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }
        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa4606C4c09a1f5DD1e6a763716D3191DDA537b22",
            "upgrade(address,address)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
            "setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes),bytes))",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
            "setValidatorTimelock(address)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xf4c557C9DB802bfabC9A1AD569E284f8edC93cAd",
            "setAddresses(address,address,address)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa5699243143b21E6863018971B2FCABCCC9997A9",
            "setL1NativeTokenVault(address)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }
        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa5699243143b21E6863018971B2FCABCCC9997A9",
            "setL1AssetRouter(address)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }
        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0x40cb63ECd4e207A5ac8B8eE38e20Fa4094a8c0bc",
            "setProtocolVersionDeadline(uint256,uint256)",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }
        match expect_simple_call(
            verifiers,
            elems.pop_front(),
            // FIXME
            "Unknown: 0xa25E32103B151F39352b7e9af1700B7a4743931c",
            "checkDeadline()",
        ) {
            Ok(msg) => result.report_ok(&msg),
            Err(msg) => result.report_error(&msg),
        }

        if elems.len() != 0 {
            result.report_error("Too many calls in governance2.");
        }
        Ok(())
    }
}
