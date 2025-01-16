use std::fmt::Display;

use alloy::{primitives::U256, sol};

sol! {
    #[derive(Debug, Default, PartialEq)]
    enum PubdataPricingMode {
        #[default]
        Rollup,
        Validium
    }

    #[derive(Debug, Default)]
    struct FeeParams {
        PubdataPricingMode pubdataPricingMode;
        uint32 batchOverheadL1Gas;
        uint32 maxPubdataPerBatch;
        uint32 maxL2GasPerBatch;
        uint32 priorityTxMaxPubdata;
        uint64 minimalL2GasPrice;
    }
    struct VerifierParams {
        bytes32 recursionNodeLevelVkHash;
        bytes32 recursionLeafLevelVkHash;
        bytes32 recursionCircuitsSetVksHash;
    }

    struct InitializeDataNewChain {
        address verifier;
        VerifierParams verifierParams;
        bytes32 l2BootloaderBytecodeHash;
        bytes32 l2DefaultAccountBytecodeHash;
        uint256 priorityTxMaxGasLimit;
        FeeParams feeParams;
        address blobVersionedHashRetriever;
    }
}

impl InitializeDataNewChain {
    pub async fn verify(
        &self,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== checking initialize data ===");

        result.expect_address(verifiers, &self.verifier, "verifier");
        if self.verifierParams.recursionNodeLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionLeafLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionCircuitsSetVksHash != [0u8; 32]
        {
            result.report_error("Verifier params must be empty.");
        }

        result.expect_bytecode(
            verifiers,
            &self.l2BootloaderBytecodeHash,
            "proved_batch.yul",
        );
        result.expect_bytecode(
            verifiers,
            &self.l2DefaultAccountBytecodeHash,
            "system-contracts/DefaultAccount",
        );

        if self.priorityTxMaxGasLimit != U256::from(72_000_000) {
            result.report_warn(&format!(
                "priorityTxMaxGasLimit must be 72_000_000 got {}",
                self.priorityTxMaxGasLimit
            ));
        }

        // verify FeeParams sanity.

        // First check file based FeeParams
        let file_based_fee_params = &verifiers.fee_param_verifier.file_based_fee_params;

        if self.feeParams.pubdataPricingMode != file_based_fee_params.pubdataPricingMode {
            result.report_error(&format!(
                "File Based FeeParams - {} - Expected {}, got {}",
                "pubdataPricingMode",
                file_based_fee_params.pubdataPricingMode,
                self.feeParams.pubdataPricingMode
            ));
        } else {
            result.report_ok(&format!(
                "File Based FeeParams - {}: {}",
                "pubdataPricingMode", self.feeParams.pubdataPricingMode
            ));
        }

        if self.feeParams.batchOverheadL1Gas != file_based_fee_params.batchOverheadL1Gas {
            result.report_error(&format!(
                "File Based FeeParams - {} - Expected {}, got {}",
                "batchOverheadL1Gas",
                file_based_fee_params.batchOverheadL1Gas,
                self.feeParams.batchOverheadL1Gas
            ));
        } else {
            result.report_ok(&format!(
                "File Based FeeParams - {}: {}",
                "batchOverheadL1Gas", self.feeParams.batchOverheadL1Gas
            ));
        }

        if self.feeParams.maxPubdataPerBatch != file_based_fee_params.maxPubdataPerBatch {
            result.report_error(&format!(
                "File Based FeeParams - {} - Expected {}, got {}",
                "maxPubdataPerBatch",
                file_based_fee_params.maxPubdataPerBatch,
                self.feeParams.maxPubdataPerBatch
            ));
        } else {
            result.report_ok(&format!(
                "File Based FeeParams - {}: {}",
                "maxPubdataPerBatch", self.feeParams.maxPubdataPerBatch
            ));
        }

        if self.feeParams.maxL2GasPerBatch != file_based_fee_params.maxL2GasPerBatch {
            result.report_error(&format!(
                "File Based FeeParams - {} - Expected {}, got {}",
                "maxL2GasPerBatch",
                file_based_fee_params.maxL2GasPerBatch,
                self.feeParams.maxL2GasPerBatch
            ));
        } else {
            result.report_ok(&format!(
                "File Based FeeParams - {}: {}",
                "maxL2GasPerBatch", self.feeParams.maxL2GasPerBatch
            ));
        }

        if self.feeParams.priorityTxMaxPubdata != file_based_fee_params.priorityTxMaxPubdata {
            result.report_error(&format!(
                "File Based FeeParams - {} - Expected {}, got {}",
                "priorityTxMaxPubdata",
                file_based_fee_params.priorityTxMaxPubdata,
                self.feeParams.priorityTxMaxPubdata
            ));
        } else {
            result.report_ok(&format!(
                "File Based FeeParams - {}: {}",
                "priorityTxMaxPubdata", self.feeParams.priorityTxMaxPubdata
            ));
        }

        if self.feeParams.minimalL2GasPrice != file_based_fee_params.minimalL2GasPrice {
            result.report_error(&format!(
                "File Based FeeParams - {} - Expected {}, got {}",
                "minimalL2GasPrice",
                file_based_fee_params.minimalL2GasPrice,
                self.feeParams.minimalL2GasPrice
            ));
        } else {
            result.report_ok(&format!(
                "File Based FeeParams - {}: {}",
                "minimalL2GasPrice", self.feeParams.minimalL2GasPrice
            ));
        }

        // First check on chain based FeeParams
        let on_chain_based_fee_params = &verifiers.fee_param_verifier.on_chain_fee_params;
        if self.feeParams.pubdataPricingMode != on_chain_based_fee_params.pubdataPricingMode {
            result.report_error(&format!(
                "On Chain Based FeeParams - {} - Expected {}, got {}",
                "pubdataPricingMode",
                on_chain_based_fee_params.pubdataPricingMode,
                self.feeParams.pubdataPricingMode
            ));
        } else {
            result.report_ok(&format!(
                "On Chain Based FeeParams - {}: {}",
                "pubdataPricingMode", self.feeParams.pubdataPricingMode
            ));
        }

        if self.feeParams.batchOverheadL1Gas != on_chain_based_fee_params.batchOverheadL1Gas {
            result.report_error(&format!(
                "On Chain Based FeeParams - {} - Expected {}, got {}",
                "batchOverheadL1Gas",
                on_chain_based_fee_params.batchOverheadL1Gas,
                self.feeParams.batchOverheadL1Gas
            ));
        } else {
            result.report_ok(&format!(
                "On Chain Based FeeParams - {}: {}",
                "batchOverheadL1Gas", self.feeParams.batchOverheadL1Gas
            ));
        }

        if self.feeParams.maxPubdataPerBatch != on_chain_based_fee_params.maxPubdataPerBatch {
            result.report_error(&format!(
                "On Chain Based FeeParams - {} - Expected {}, got {}",
                "maxPubdataPerBatch",
                on_chain_based_fee_params.maxPubdataPerBatch,
                self.feeParams.maxPubdataPerBatch
            ));
        } else {
            result.report_ok(&format!(
                "On Chain Based FeeParams - {}: {}",
                "maxPubdataPerBatch", self.feeParams.maxPubdataPerBatch
            ));
        }

        if self.feeParams.maxL2GasPerBatch != on_chain_based_fee_params.maxL2GasPerBatch {
            result.report_error(&format!(
                "On Chain Based FeeParams - {} - Expected {}, got {}",
                "maxL2GasPerBatch",
                on_chain_based_fee_params.maxL2GasPerBatch,
                self.feeParams.maxL2GasPerBatch
            ));
        } else {
            result.report_ok(&format!(
                "On Chain Based FeeParams - {}: {}",
                "maxL2GasPerBatch", self.feeParams.maxL2GasPerBatch
            ));
        }

        if self.feeParams.priorityTxMaxPubdata != on_chain_based_fee_params.priorityTxMaxPubdata {
            result.report_error(&format!(
                "On Chain Based FeeParams - {} - Expected {}, got {}",
                "priorityTxMaxPubdata",
                on_chain_based_fee_params.priorityTxMaxPubdata,
                self.feeParams.priorityTxMaxPubdata
            ));
        } else {
            result.report_ok(&format!(
                "On Chain Based FeeParams - {}: {}",
                "priorityTxMaxPubdata", self.feeParams.priorityTxMaxPubdata
            ));
        }

        if self.feeParams.minimalL2GasPrice != on_chain_based_fee_params.minimalL2GasPrice {
            result.report_error(&format!(
                "On Chain Based FeeParams - {} - Expected {}, got {}",
                "minimalL2GasPrice",
                on_chain_based_fee_params.minimalL2GasPrice,
                self.feeParams.minimalL2GasPrice
            ));
        } else {
            result.report_ok(&format!(
                "On Chain Based FeeParams - {}: {}",
                "minimalL2GasPrice", self.feeParams.minimalL2GasPrice
            ));
        }

        Ok(())
    }
}

impl Display for PubdataPricingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubdataPricingMode::Rollup => write!(f, "{}", "Rollup"),
            PubdataPricingMode::Validium => write!(f, "{}", "Validium"),
            PubdataPricingMode::__Invalid => write!(f, "{}", "Invalid"),
        }
    }
}
