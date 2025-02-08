use std::io::Read;

use crate::{
    elements::initialize_data_new_chain::InitializeDataNewChain, get_expected_old_protocol_version, traits::{Verifiers, Verify}, utils::facet_cut_set::{self, FacetCutSet}
};
use alloy::{
    hex, primitives::U256, providers::Provider, sol, sol_types::{SolCall, SolValue}
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
    function setAddresses(address _assetRouter, address _l1CtmDeployer, address _messageRoot) {}

    function setL1NativeTokenVault(address _l1NativeTokenVault);
    function setL1AssetRouter(address _l1AssetRouter);

    function setValidatorTimelock(address addr) {
    }

    function singleAddressArgument(address addr) {

    }
    function setProtocolVersionDeadline(uint256 protocolVersion, uint256 newDeadline) {
    }

    #[derive(Debug, PartialEq)]
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

    /// @notice Faсet structure compatible with the EIP-2535 diamond loupe
    /// @param addr The address of the facet contract
    /// @param selectors The NON-sorted array with selectors associated with facet
    struct Facet {
        address addr;
        bytes4[] selectors;
    }

    function facets() external view returns (Facet[] memory result);

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
                result.report_ok(&format!(
                    "Upgrade call for {} ({}) to {} ({})",
                    proxy, proxy_address, implementation, implementation_address
                ));
            }
        }
    }
}

impl GovernanceStage2Calls {
    pub async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        expected_chain_creation_facets: FacetCutSet
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
            (
                "protocol_upgrade_handler_transparent_proxy_admin",
                "upgradeAndCall(address,address,bytes)",
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

        // Now verifying setChainCreationParams

        {
            let decoded =
            setChainCreationParamsCall::abi_decode(&self.calls.elems[4].data, true).unwrap();

            decoded
                ._chainCreationParams
                .verify(verifiers, result, expected_chain_creation_facets)
                .await?;
        }
        
        {
            let decoded = 
                setAddressesCall::abi_decode(&self.calls.elems[5].data, true).unwrap();
            
            // FIXME: the name is very confusing
            result.expect_address(&verifiers, &decoded._assetRouter, "shared_bridge_proxy");
            result.expect_address(&verifiers, &decoded._l1CtmDeployer, "ctm_deployment_tracker");
            result.expect_address(&verifiers, &decoded._messageRoot, "l1_message_root");
        }

        {
            let decoded =
                setL1NativeTokenVaultCall::abi_decode(&self.calls.elems[6].data, true)
                    .unwrap();

            result.expect_address(verifiers, &decoded._l1NativeTokenVault, "native_token_vault");
        }

        {
            let decoded =
                setL1AssetRouterCall::abi_decode(&self.calls.elems[7].data, true)
                    .unwrap();

            result.expect_address(verifiers, &decoded._l1AssetRouter, "shared_bridge_proxy");
        }

        {
            let decoded = setProtocolVersionDeadlineCall::abi_decode(
                &self.calls.elems[8].data,
                true,
            )
            .unwrap();

            let pv = ProtocolVersion::from(decoded.protocolVersion);
            let expected_old = get_expected_old_protocol_version();

            if pv != expected_old {
                result.report_warn(&format!(
                    "Invalid protocol version: {} - expected {}",
                    pv, expected_old
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
        expected_chain_creation_facets: FacetCutSet
    ) -> anyhow::Result<()> {
        result.print_info("== Chain creation params ==");
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

        verify_chain_creation_diamond_cut(verifiers, result, &self.diamondCut, expected_chain_creation_facets).await;

        let fixed_force_deployments_data =
            FixedForceDeploymentsData::abi_decode(&self.forceDeploymentsData, true)?;
        fixed_force_deployments_data
            .verify(verifiers, result)
            .await?;

        Ok(())
    }
}

pub async fn verify_chain_creation_diamond_cut(
    verifiers: &crate::traits::Verifiers,
    result: &mut crate::traits::VerificationResult,
    diamond_cut: &DiamondCutData,
    expected_chain_creation_facets: FacetCutSet
) {

    let mut proposed_facet_cut = FacetCutSet::new();
    diamond_cut.facetCuts.iter().for_each(|facet| {
        // FIXME: use a single type for `Action`
        let action = match facet.action {
            Action::Add => facet_cut_set::Action::Add,
            Action::Remove => panic!("Remove unexpected"),
            Action::Replace => panic!("Replace unexpected"),
            Action::__Invalid => panic!("Invalid unexpected")
        };
        proposed_facet_cut.add_facet(facet.facet, facet.isFreezable, action);
    });
    if expected_chain_creation_facets != proposed_facet_cut {
        result.report_error(&format!("Invalid chain creation facet cut. Expected: {:#?}\nReceived: {:#?}", expected_chain_creation_facets, proposed_facet_cut));
    }
    
    result.expect_address(verifiers, &diamond_cut.initAddress, "diamond_init");
    let intialize_data_new_chain =
        InitializeDataNewChain::abi_decode(&diamond_cut.initCalldata, true).unwrap();
    intialize_data_new_chain
        .verify(verifiers, result)
        .await
        .unwrap();
}

pub fn verify_facet(
    verifiers: &crate::traits::Verifiers,
    result: &mut crate::traits::VerificationResult,
    facet: &FacetCut,
    expected_facet: &str,
) {
    let facet_address = verifiers.address_verifier.name_or_unknown(&facet.facet);
    if facet_address != expected_facet {
        result.report_error(&format!(
            "Expected facet address to be {}, but got {}",
            expected_facet, facet_address
        ));
    }
    if facet.action != Action::Add {
        result.report_error(&format!(
            "Expected facet {} action to be Add, but got {:?}",
            expected_facet, facet.action
        ));
    }
}
