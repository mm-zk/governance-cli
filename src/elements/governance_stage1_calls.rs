use std::str::FromStr;

use alloy::{primitives::{Address, U256}, sol, sol_types::SolCall};

use crate::{
    elements::{
        protocol_version::ProtocolVersion, set_new_version_upgrade::upgradeCall,
        upgrade_deadline::UpgradeDeadline,
    },
    traits::Verify, utils::facet_cut_set::{self, FacetCutSet},
};

use super::{
    call_list::CallList, deployed_addresses::DeployedAddresses, governance_stage2_calls::{setValidatorTimelockCall, DiamondCutData}, set_new_version_upgrade::{self, setNewVersionUpgradeCall, FacetCut}
};

sol! {
    contract StateTransitionManagerLegacy {
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
        struct ChainCreationParams {
            address genesisUpgrade;
            bytes32 genesisBatchHash;
            uint64 genesisIndexRepeatedStorageChanges;
            bytes32 genesisBatchCommitment;
            DiamondCutData diamondCut;
        }
    
        function setChainCreationParams(ChainCreationParams calldata _chainCreationParams)  {
        }
    
    }  
}

pub struct GovernanceStage1Calls {
    pub calls: CallList,
}

async fn verity_facet_cuts(
    facet_cuts: &[FacetCut],
    result: &mut crate::traits::VerificationResult,
    expected_upgrade_facets: FacetCutSet
) {
    // We ensure two invariants here:
    // - Firstly we use `Remove` operations only. This is mainly for ensuring that
    // the upgrade will pass.
    // - Secondly, we ensure that the set of operations is identical.
    let mut used_add = false;
    let mut proposed_facet_cuts = FacetCutSet::new();
    facet_cuts.iter().for_each(|facet| {
        let action = match facet.action {
            set_new_version_upgrade::Action::Add => {
                used_add = true;
                facet_cut_set::Action::Add
            },
            set_new_version_upgrade::Action::Remove => {
                assert!(!used_add, "Unexpected `Remove` operation after `Add`");
                facet_cut_set::Action::Remove
            },
            set_new_version_upgrade::Action::Replace => panic!("Replace unexpected"),
            set_new_version_upgrade::Action::__Invalid => panic!("Invalid unexpected")
        };

        proposed_facet_cuts.add_facet(facet.facet, facet.isFreezable, action);
        facet.selectors.iter().for_each(|selector| proposed_facet_cuts.add_selector(facet.facet, selector.0));
    });

    if proposed_facet_cuts != expected_upgrade_facets {
        result.report_error(&format!("Incorrect facet cuts. Expected {:#?}\nReceived: {:#?}", expected_upgrade_facets, proposed_facet_cuts));
    }
}

impl GovernanceStage1Calls {
    pub(crate) async fn verify(
        &self,
        deployed_addresses: &DeployedAddresses,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        expected_upgrade_facets: FacetCutSet
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 1 calls ===");

        let list_of_calls = [
            ("validator_timelock", "acceptOwnership()"),
            ("l1_asset_router_proxy", "acceptOwnership()"),
            ("ctm_deployment_tracker", "acceptOwnership()"),
            ("rollup_da_manager", "acceptOwnership()"),
            ("state_transition_manager",
            "setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256,uint256,uint256)"),
            (
                "state_transition_manager",
                "setValidatorTimelock(address)",
            ),
            ("state_transition_manager","setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes)))"),
            ("upgrade_timer", "startTimer()"),

        ];

        self.calls.verify(&list_of_calls, verifiers, result)?;

        // Checking the new validator timelock
        {
            let decoded =
                setValidatorTimelockCall::abi_decode(&self.calls.elems[5].data, true).unwrap();

            result.expect_address(verifiers, &decoded.addr, "validator_timelock");
        }

        // Checking the dummy chain creation params
        {
            let decoded = StateTransitionManagerLegacy::setChainCreationParamsCall::abi_decode(&self.calls.elems[6].data, true).unwrap();

            // Any sort of data is accepted there as long as the `genesisUpgrade` is a definitely invalid address, which
            // cause new chain creation to revert.
            if decoded._chainCreationParams.genesisUpgrade != Address::from_str("0x0000000000000000000000000000000000000001").unwrap() {
                result.report_error("Invalid dummy chain creation params in stage1");
            } 
        }

        let calldata = &self.calls.elems[4].data;
        let data = setNewVersionUpgradeCall::abi_decode(calldata, true).unwrap();

        if data.oldProtocolVersionDeadline != U256::MAX {
            result.report_error("Wrong old protocol version deadline for stage1 call");
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

        let diamond_cut = data.diamondCut;

        if diamond_cut.initAddress != deployed_addresses.l1_gateway_upgrade {
            result.report_error(&format!("Unexpected init address for the diamond cut: {}, expected {}", diamond_cut.initAddress, deployed_addresses.l1_gateway_upgrade));
        }

        verity_facet_cuts(
            &diamond_cut.facetCuts, 
            result,
            expected_upgrade_facets
        ).await;

        let upgrade = upgradeCall::abi_decode(&diamond_cut.initCalldata, true).unwrap();

        upgrade
            ._proposedUpgrade
            .verify(
                verifiers, 
                result,
                deployed_addresses.l1_bytecodes_supplier_addr
            )
            .await?;

        Ok(())
    }
}
