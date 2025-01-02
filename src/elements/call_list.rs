use alloy::{hex, sol, sol_types::SolValue};

use crate::traits::Verifiers;

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

    pub fn verify(
        &self,
        list_of_calls: Vec<(&str, &str)>,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        let mut elems = std::collections::VecDeque::from(self.elems.clone());

        let mut errors = 0;

        for (target, method_name) in &list_of_calls {
            match expect_simple_call(verifiers, elems.pop_front(), target, method_name) {
                Ok(msg) => result.report_ok(&msg),
                Err(msg) => {
                    result.report_error(&msg);
                    errors += 1;
                }
            }
        }
        if elems.len() != 0 {
            errors += 1;
            result.report_error(&format!(
                "Too many calls: expected {} got {}.",
                list_of_calls.len(),
                list_of_calls.len() + elems.len()
            ));
        }

        if errors > 0 {
            anyhow::bail!("{} errors", errors)
        } else {
            Ok(())
        }
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
