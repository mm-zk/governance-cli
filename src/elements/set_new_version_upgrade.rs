use alloy::{primitives::U256, sol};

use crate::utils::address_verifier::FixedAddresses;

use super::{
    post_upgrade_calldata::PostUpgradeCalldata, protocol_version::ProtocolVersion,
    upgrade_deadline::UpgradeDeadline,
};

sol! {
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


    function setNewVersionUpgrade(DiamondCutData diamondCut,uint256 oldProtocolVersion, uint256 oldProtocolVersionDeadline,uint256 newProtocolVersion) {
    }



    #[derive(Debug)]
    struct VerifierParams {
        bytes32 recursionNodeLevelVkHash;
        bytes32 recursionLeafLevelVkHash;
        bytes32 recursionCircuitsSetVksHash;
    }

    #[derive(Debug)]
    struct L2CanonicalTransaction {
        uint256 txType;
        uint256 from;
        uint256 to;
        uint256 gasLimit;
        uint256 gasPerPubdataByteLimit;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        uint256 paymaster;
        uint256 nonce;
        uint256 value;
        // In the future, we might want to add some
        // new fields to the struct. The `txData` struct
        // is to be passed to account and any changes to its structure
        // would mean a breaking change to these accounts. To prevent this,
        // we should keep some fields as "reserved"
        // It is also recommended that their length is fixed, since
        // it would allow easier proof integration (in case we will need
        // some special circuit for preprocessing transactions)
        uint256[4] reserved;
        bytes data;
        bytes signature;
        uint256[] factoryDeps;
        bytes paymasterInput;
        // Reserved dynamic type for the future use-case. Using it should be avoided,
        // But it is still here, just in case we want to enable some additional functionality
        bytes reservedDynamic;
    }

    #[derive(Debug)]
    struct ProposedUpgrade {
        L2CanonicalTransaction l2ProtocolUpgradeTx;
        bytes32 bootloaderHash;
        bytes32 defaultAccountHash;
        address verifier;
        VerifierParams verifierParams;
        bytes l1ContractsUpgradeCalldata;
        bytes postUpgradeCalldata;
        uint256 upgradeTimestamp;
        uint256 newProtocolVersion;
    }

    #[derive(Debug)]
    function upgrade(ProposedUpgrade calldata _proposedUpgrade) {

    }

}

impl upgradeCall {}

impl ProposedUpgrade {
    pub fn verify_transaction(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== checking upgrade tx ===");

        let mut errors = 0;

        let tx = &self.l2ProtocolUpgradeTx;
        if tx.txType != U256::from(254) {
            result.report_error("Invalid txType");
            errors += 1;
        }

        if tx.from != U256::from(FixedAddresses::ForceDeployer as u64) {
            result.report_error("Invalid from");
            errors += 1;
        }
        if tx.to != U256::from(FixedAddresses::Deployer as u64) {
            result.report_error("Invalid to");
            errors += 1;
        }
        // TODO: analyze factory deps !!

        let bootloader = verifiers
            .bytecode_verifier
            .bytecode_hash_to_file(&self.bootloaderHash);
        match bootloader {
            Some(file) => {
                if file != "Bootloader" {
                    result.report_error("Invalid bootloader hash");
                    errors += 1;
                }
            }
            None => {
                result.report_warn(&format!(
                    "Cannot verify bootloader hash: {}",
                    self.bootloaderHash
                ));
            }
        }

        let default_account = verifiers
            .bytecode_verifier
            .bytecode_hash_to_file(&self.defaultAccountHash);
        match default_account {
            Some(file) => {
                if file != "Default Account" {
                    result.report_error("Invalid default AA hash");
                    errors += 1;
                }
            }
            None => {
                result.report_warn(&format!(
                    "Cannot verify default AA hash: {}",
                    self.defaultAccountHash
                ));
            }
        }

        /*

        VerifierParams verifierParams;
        bytes l1ContractsUpgradeCalldata;
        bytes postUpgradeCalldata;
         */

        let verifier = verifiers
            .address_verifier
            .address_to_name
            .get(&self.verifier)
            .unwrap_or(&format!("Unknown: {}", self.verifier))
            .clone();

        if verifier != "verifier" {
            result.report_error(&format!("Invalid verifier: {}", verifier));
            errors += 1;
        }

        // FIXME: protocol version should be v0.26.0
        let pv = ProtocolVersion::from(self.newProtocolVersion).to_string();
        if pv != "v0.27.0" {
            result.report_error(&format!(
                "Invalid protocol version: {} - expected v0.27.0",
                pv
            ));
            errors += 1;
        }

        let timestamp = UpgradeDeadline::from(self.upgradeTimestamp).to_string();
        // TODO: should we check something here?
        result.print_info(&format!("Upgrade timestamp: {}", timestamp));

        if errors > 0 {
            anyhow::bail!("{} errors", errors)
        }

        // TOOD: check verifier params.

        if self.l1ContractsUpgradeCalldata.len() > 0 {
            result.report_error("l1ContractsUpgradeCalldata is not empty");
            errors += 1;
        }

        let post_upgrade_calldata = PostUpgradeCalldata::parse(&self.postUpgradeCalldata);

        post_upgrade_calldata.verify(verifiers, result)?;

        Ok(())
    }
}
