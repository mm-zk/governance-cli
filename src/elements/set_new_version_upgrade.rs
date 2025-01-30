use std::collections::HashSet;

use alloy::{
    primitives::{FixedBytes, U256},
    sol,
};

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

const EXPECTED_BYTECODES: [&str; 41] = [
    "CodeOracle.yul",
    "EcAdd.yul",
    "EcMul.yul",
    "EcPairing.yul",
    "Ecrecover.yul",
    "EventWriter.yul",
    "Keccak256.yul",
    "P256Verify.yul",
    "SHA256.yul",
    "proved_batch.yul",
    "l1-contracts/BeaconProxy",
    "l1-contracts/BridgedStandardERC20",
    "l1-contracts/Bridgehub",
    "l1-contracts/L2AssetRouter",
    "l1-contracts/L2NativeTokenVault",
    "l1-contracts/L2SharedBridgeLegacy",
    "l1-contracts/L2WrappedBaseToken",
    "l1-contracts/MessageRoot",
    "l1-contracts/UpgradeableBeacon",
    "l2-contracts/RollupL2DAValidator",
    "l2-contracts/ValidiumL2DAValidator",
    "system-contracts/AccountCodeStorage",
    "system-contracts/BootloaderUtilities",
    "system-contracts/ComplexUpgrader",
    "system-contracts/Compressor",
    "system-contracts/ContractDeployer",
    "system-contracts/Create2Factory",
    "system-contracts/DefaultAccount",
    "system-contracts/EmptyContract",
    "system-contracts/ImmutableSimulator",
    "system-contracts/KnownCodesStorage",
    "system-contracts/L1Messenger",
    "system-contracts/L2BaseToken",
    "system-contracts/L2GatewayUpgrade",
    "system-contracts/L2GenesisUpgrade",
    "system-contracts/MsgValueSimulator",
    "system-contracts/NonceHolder",
    "system-contracts/PubdataChunkPublisher",
    "system-contracts/SloadContract",
    "system-contracts/SystemContext",
    "system-contracts/TransparentUpgradeableProxy",
];

impl ProposedUpgrade {
    pub async fn verify_transaction(
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
        if tx.to != U256::from(FixedAddresses::DeployerSystemContract as u64) {
            result.report_error("Invalid to");
            errors += 1;
        }
        if tx.gasLimit != U256::from(72_000_000) {
            result.report_error("Invalid gasLimit");
            errors += 1;
        }
        if tx.gasPerPubdataByteLimit != U256::from(800) {
            result.report_error("Invalid gasPerPubdataByteLimit");
            errors += 1;
        }
        if tx.maxFeePerGas != U256::from(0) {
            result.report_error("Invalid maxFeePerGas");
            errors += 1;
        }
        if tx.maxPriorityFeePerGas != U256::from(0) {
            result.report_error("Invalid maxPriorityFeePerGas");
            errors += 1;
        }
        if tx.paymaster != U256::from(0) {
            result.report_error("Invalid paymaster");
            errors += 1;
        }
        if tx.value != U256::from(0) {
            result.report_error("Invalid value");
            errors += 1;
        }
        if tx.reserved != [U256::from(0); 4] {
            result.report_error("Invalid reserved");
            errors += 1;
        }
        if tx.data.len() != 0 {
            result.report_error("Invalid data");
            errors += 1;
        }
        if tx.paymasterInput.len() != 0 {
            result.report_error("Invalid paymasterInput");
            errors += 1;
        }
        if tx.reservedDynamic.len() != 0 {
            result.report_error("Invalid reservedDynamic");
            errors += 1;
        }

        // FIXME: it is not checked that the bytecodes were actually published
        let deps = tx
            .factoryDeps
            .iter()
            .map(|dep| FixedBytes::<32>::from_slice(&dep.to_be_bytes::<32>()))
            .collect::<Vec<_>>();

        let mut expected_bytecodes: HashSet<&str> = EXPECTED_BYTECODES.into();

        for dep in deps {
            let file_name = verifiers.bytecode_verifier.bytecode_hash_to_file(&dep);
            match file_name {
                Some(file_name) => {
                    if !expected_bytecodes.contains(&file_name.as_str()) {
                        result.report_error(&format!(
                            "Unexpected dependency in factory deps: {}",
                            file_name
                        ));
                        errors += 1;
                    } else {
                        expected_bytecodes.remove(&file_name.as_str());
                    }
                }
                None => {
                    result.report_error(&format!(
                        "Invalid dependency in factory deps - cannot find file for hash: {:?}",
                        dep
                    ));
                    errors += 1;
                }
            }
        }
        if expected_bytecodes.len() > 0 {
            result.report_error(&format!(
                "Missing dependencies in factory deps: {:?}",
                expected_bytecodes
            ));
            errors += 1;
        }
        if errors == 0 {
            result.report_ok("Upgrade transaction & factory deps are correct");
        }

        result.expect_bytecode(verifiers, &self.bootloaderHash, "proved_batch.yul");
        result.expect_bytecode(
            verifiers,
            &self.defaultAccountHash,
            "system-contracts/DefaultAccount",
        );

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

        // Verifier params should be zero - as everything is hardcoded within the verifier contract itself.
        if self.verifierParams.recursionNodeLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionLeafLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionCircuitsSetVksHash != [0u8; 32]
        {
            result.report_error("Verifier params must be empty.");
            errors += 1;
        }

        if self.l1ContractsUpgradeCalldata.len() > 0 {
            result.report_error("l1ContractsUpgradeCalldata is not empty");
            errors += 1;
        }

        let post_upgrade_calldata = PostUpgradeCalldata::parse(&self.postUpgradeCalldata);
        post_upgrade_calldata.verify(verifiers, result).await?;

        let upgrade_timestamp = self.upgradeTimestamp;
        result.print_info(&format!("Upgrade timestamp: {}", upgrade_timestamp));
        if upgrade_timestamp != U256::default() {
            result.report_warn("Upgrade timestamp must be zero");
        }

        let pv = ProtocolVersion::from(self.newProtocolVersion).to_string();
        pub const EXPECTED_PROTOCOL_VERSION: &str = "v0.26.0";
        if pv != EXPECTED_PROTOCOL_VERSION {
            result.report_warn(&format!(
                "Invalid protocol version: {} - expected {}",
                pv, EXPECTED_PROTOCOL_VERSION
            ));
        }

        if errors > 0 {
            anyhow::bail!("{} errors", errors)
        }

        Ok(())
    }
}
