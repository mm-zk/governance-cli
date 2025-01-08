use alloy::{primitives::U256, sol};

sol! {
    #[derive(Debug)]
    enum PubdataPricingMode {
        Rollup,
        Validium
    }

    #[derive(Debug)]
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
            "DefaultAccount",
        );

        if self.priorityTxMaxGasLimit != U256::from(72_000_000) {
            result.report_warn(&format!(
                "priorityTxMaxGasLimit must be 72_000_000 got {}",
                self.priorityTxMaxGasLimit
            ));
        }

        // TODO: verify fee params sanity.

        /*
        result.expect_address(
            verifiers,
            &self.blobVersionedHashRetriever,
            "blob_versioned_hash_retriever",
        );*/

        Ok(())
    }
}
