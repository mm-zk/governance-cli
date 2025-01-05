use crate::traits::{Verifiers, Verify};
use alloy::{
    hex,
    primitives::U256,
    sol,
    sol_types::{SolCall, SolValue},
};

use super::{
    call_list::{Call, CallList},
    fixed_force_deployment::FixedForceDeploymentsData,
    protocol_version::ProtocolVersion,
};

pub struct GovernanceStage2Calls {
    pub calls: CallList,
}

sol! {
    function upgrade(address proxy, address implementation) {
    }

    function upgradeAndCall(address proxy, address implementation, bytes data) {
    }

    function setValidatorTimelock(address addr) {
    }

    function singleAddressArgument(address addr) {

    }
    function setProtocolVersionDeadline(uint256 protocolVersion, uint256 newDeadline) {
    }

    #[derive(Debug)]
    enum Action {
        Add,
        Replace,
        Remove
    }

    #[derive(Debug)]
    struct FacetCut {
        address facet;
        Action action;
        bool isFreezable;
        bytes4[] selectors;
    }


    #[derive(Debug)]
    struct DiamondCutData {
        FacetCut[] facetCuts;
        address initAddress;
        bytes initCalldata;
    }


    #[derive(Debug)]
    struct ChainCreationParams {
        address genesisUpgrade;
        bytes32 genesisBatchHash;
        uint64 genesisIndexRepeatedStorageChanges;
        bytes32 genesisBatchCommitment;
        DiamondCutData diamondCut;
        bytes forceDeploymentsData;
    }

    function setChainCreationParams(ChainCreationParams calldata _chainCreationParams)  {
    }

}

impl GovernanceStage2Calls {
    pub fn verify_upgrade_call(
        &self,
        verifiers: &Verifiers,
        result: &mut crate::traits::VerificationResult,

        call: &Call,
        proxy_address: &str,
        implementation_address: &str,
        call_payload: Option<String>,
    ) {
        let data = call.data.clone();

        let (proxy, implementation) = match call_payload {
            Some(call_payload) => {
                let decoded = upgradeAndCallCall::abi_decode(&data, true).unwrap();
                if decoded.data != hex::decode(call_payload.clone()).unwrap() {
                    result.report_error(&format!(
                        "Expected upgrade call data to be {}, but got {}",
                        call_payload, decoded.data
                    ));
                }
                (decoded.proxy, decoded.implementation)
            }
            None => {
                let decoded = upgradeCall::abi_decode(&data, true).unwrap();
                (decoded.proxy, decoded.implementation)
            }
        };

        if result.expect_address(verifiers, &proxy, proxy_address) {
            if result.expect_address(verifiers, &implementation, implementation_address) {
                result.report_ok(&format!("Upgrade call for {} to {}", proxy, implementation));
            }
        }
    }
}

impl Verify for GovernanceStage2Calls {
    async fn verify(
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

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[0],
            "state_transition_manager",
            "state_transition_implementation_addr",
            None,
        );

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[1],
            "bridgehub_proxy",
            "bridgehub_implementation_addr",
            Some(
                verifiers
                    .selector_verifier
                    .compute_selector("initializeV2()"),
            ),
        );

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[2],
            "old_shared_bridge_proxy",
            "l1_nullifier_implementation_addr",
            None,
        );

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[3],
            "legacy_erc20_bridge_proxy",
            "erc20_bridge_implementation_addr",
            None,
        );

        let decoded =
            setChainCreationParamsCall::abi_decode(&self.calls.elems[4].data, true).unwrap();

        decoded
            ._chainCreationParams
            .verify(verifiers, result)
            .await?;

        {
            let decoded =
                setValidatorTimelockCall::abi_decode(&self.calls.elems[5].data, true).unwrap();

            result.expect_address(verifiers, &decoded.addr, "validator_timelock");
        }

        {
            let decoded =
                singleAddressArgumentCall::abi_decode_raw(&self.calls.elems[7].data[4..], true)
                    .unwrap();

            result.expect_address(verifiers, &decoded.addr, "native_token_vault");
        }

        {
            let decoded =
                singleAddressArgumentCall::abi_decode_raw(&self.calls.elems[8].data[4..], true)
                    .unwrap();

            result.expect_address(verifiers, &decoded.addr, "shared_bridge_proxy");
        }

        {
            let decoded = setProtocolVersionDeadlineCall::abi_decode_raw(
                &self.calls.elems[9].data[4..],
                true,
            )
            .unwrap();

            let pv = ProtocolVersion::from(decoded.protocolVersion);
            const EXPECTED_OLD_PV: &str = "v0.25.0";
            if pv.to_string() != EXPECTED_OLD_PV {
                result.report_warn(&format!(
                    "Invalid protocol version: {} - expected {}",
                    pv, EXPECTED_OLD_PV
                ));
            }

            if decoded.newDeadline != U256::ZERO {
                result.report_error(&format!(
                    "Expected deadline to be 0, but got {}",
                    decoded.newDeadline
                ));
            }
        }

        Ok(())
    }
}

impl ChainCreationParams {
    pub async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        let genesis_upgrade_address = verifiers
            .address_verifier
            .name_or_unknown(&self.genesisUpgrade);
        if genesis_upgrade_address != "genesis_upgrade_addr" {
            result.report_error(&format!(
                "Expected genesis upgrade address to be genesis_upgrade_addr, but got {}",
                genesis_upgrade_address
            ));
        }

        if self.genesisBatchHash.to_string()
            != verifiers.genesis_config.as_ref().unwrap().genesis_root
        {
            result.report_error(&format!(
                "Expected genesis batch hash to be {}, but got {}",
                verifiers.genesis_config.as_ref().unwrap().genesis_root,
                self.genesisBatchHash
            ));
        }

        if self.genesisIndexRepeatedStorageChanges
            != verifiers
                .genesis_config
                .as_ref()
                .unwrap()
                .genesis_rollup_leaf_index
        {
            result.report_error(&format!(
                "Expected genesis index repeated storage changes to be {}, but got {}",
                verifiers
                    .genesis_config
                    .as_ref()
                    .unwrap()
                    .genesis_rollup_leaf_index,
                self.genesisIndexRepeatedStorageChanges
            ));
        }

        if self.genesisBatchCommitment.to_string()
            != verifiers
                .genesis_config
                .as_ref()
                .unwrap()
                .genesis_batch_commitment
        {
            result.report_error(&format!(
                "Expected genesis batch commitment to be {}, but got {}",
                verifiers
                    .genesis_config
                    .as_ref()
                    .unwrap()
                    .genesis_batch_commitment,
                self.genesisBatchCommitment
            ));
        }

        // TODO: implement diamond cut verification

        let fixed_force_deployments_data =
            FixedForceDeploymentsData::abi_decode(&self.forceDeploymentsData, true)?;
        fixed_force_deployments_data
            .verify(verifiers, result)
            .await?;

        Ok(())
    }
}
