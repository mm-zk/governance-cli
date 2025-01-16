use alloy::primitives::{Address, Uint};
use serde::{Deserialize, Serialize};

use crate::elements::initialize_data_new_chain::{FeeParams, PubdataPricingMode};

use super::{get_contents_from_github, network_verifier::NetworkVerifier};

const FEE_PARAM_STORAGE_SLOT: u8 = 38u8;

#[derive(Default)]
pub struct FeeParamVerifier {
    pub on_chain_fee_params: FeeParams,
    pub file_based_fee_params: FeeParams,
}

impl FeeParamVerifier {
    pub async fn init_from_github(&mut self, commit: &str) {
        let system_config = SystemConfig::init_from_github(commit).await;
        self.file_based_fee_params = FeeParams {
            pubdataPricingMode: PubdataPricingMode::Rollup,
            batchOverheadL1Gas: system_config.batch_overhead_l1_gas,
            maxPubdataPerBatch: system_config.priority_tx_pubdata_per_batch,
            maxL2GasPerBatch: system_config.priority_tx_max_gas_per_batch,
            priorityTxMaxPubdata: system_config.priority_tx_max_pubdata,
            minimalL2GasPrice: u64::from(system_config.priority_tx_minimal_gas_price),
        }
    }

    pub async fn init_from_on_chain(
        &mut self,
        diamond_proxy_address: &Address,
        network_verifier: &NetworkVerifier,
    ) {
        let value = network_verifier
            .get_storage_at(diamond_proxy_address, FEE_PARAM_STORAGE_SLOT)
            .await;

        match value {
            None => self.on_chain_fee_params = FeeParams::default(),
            Some(value) => {
                // Remove first 11 bytes as its padding from storage slot
                let bytes = &value.0[7..];

                // Parse the remaining bytes into their fields
                let minimal_l2_gas_price_bytes = &bytes[0..8];
                let priority_tx_max_pubdata_bytes = &bytes[8..12];
                let max_l2_gas_per_batch_bytes = &bytes[12..16];
                let max_pubdata_per_batch_bytes = &bytes[16..20];
                let batch_overhead_l1_gas_bytes = &bytes[20..24];
                let pubdata_pricing_mode_byte = bytes[24];

                let minimal_l2_gas_price = u64::from_be_bytes(
                    Uint::<64, 1>::from_be_slice(minimal_l2_gas_price_bytes).to_be_bytes(),
                );
                let priority_tx_max_pubdata = u32::from_be_bytes(
                    Uint::<32, 1>::from_be_slice(priority_tx_max_pubdata_bytes).to_be_bytes(),
                );
                let max_l2_gas_per_batch = u32::from_be_bytes(
                    Uint::<32, 1>::from_be_slice(max_l2_gas_per_batch_bytes).to_be_bytes(),
                );
                let max_pubdata_per_batch = u32::from_be_bytes(
                    Uint::<32, 1>::from_be_slice(max_pubdata_per_batch_bytes).to_be_bytes(),
                );
                let batch_overhead_l1_gas = u32::from_be_bytes(
                    Uint::<32, 1>::from_be_slice(batch_overhead_l1_gas_bytes).to_be_bytes(),
                );
                let pubdata_pricing_mode = if pubdata_pricing_mode_byte == 0 {
                    PubdataPricingMode::Rollup
                } else if pubdata_pricing_mode_byte == 1 {
                    PubdataPricingMode::Validium
                } else {
                    PubdataPricingMode::__Invalid
                };

                self.on_chain_fee_params = FeeParams {
                    pubdataPricingMode: pubdata_pricing_mode,
                    batchOverheadL1Gas: batch_overhead_l1_gas,
                    maxPubdataPerBatch: max_pubdata_per_batch,
                    maxL2GasPerBatch: max_l2_gas_per_batch,
                    priorityTxMaxPubdata: priority_tx_max_pubdata,
                    minimalL2GasPrice: minimal_l2_gas_price,
                }
            }
        };
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    #[serde(rename = "GUARANTEED_PUBDATA_BYTES")]
    pub guaranteed_pubdata_bytes: u32,
    #[serde(rename = "MAX_TRANSACTIONS_IN_BATCH")]
    pub max_transactions_in_batch: u32,
    #[serde(rename = "REQUIRED_L2_GAS_PRICE_PER_PUBDATA")]
    pub required_l2_gas_price_per_pubdata: u32,
    #[serde(rename = "L1_GAS_PER_PUBDATA_BYTE")]
    pub l1_gas_per_pubdata_byte: u32,
    #[serde(rename = "PRIORITY_TX_MAX_PUBDATA")]
    pub priority_tx_max_pubdata: u32,
    #[serde(rename = "BATCH_OVERHEAD_L1_GAS")]
    pub batch_overhead_l1_gas: u32,
    #[serde(rename = "L1_TX_INTRINSIC_L2_GAS")]
    pub l1_tx_intrinsic_l2_gas: u32,
    #[serde(rename = "L1_TX_INTRINSIC_PUBDATA")]
    pub l1_tx_intrinsic_pubdata: u32,
    #[serde(rename = "L1_TX_MIN_L2_GAS_BASE")]
    pub l1_tx_min_l2_gas_base: u32,
    #[serde(rename = "L1_TX_DELTA_544_ENCODING_BYTES")]
    pub l1_tx_delta_544_encoding_bytes: u32,
    #[serde(rename = "L1_TX_DELTA_FACTORY_DEPS_L2_GAS")]
    pub l1_tx_delta_factory_deps_l2_gas: u32,
    #[serde(rename = "L1_TX_DELTA_FACTORY_DEPS_PUBDATA")]
    pub l1_tx_delta_factory_deps_pubdata: u32,
    #[serde(rename = "L2_TX_INTRINSIC_GAS")]
    pub l2_tx_intrinsic_gas: u32,
    #[serde(rename = "L2_TX_INTRINSIC_PUBDATA")]
    pub l2_tx_intrinsic_pubdata: u32,
    #[serde(rename = "MAX_NEW_FACTORY_DEPS")]
    pub max_new_factory_deps: u32,
    #[serde(rename = "MAX_GAS_PER_TRANSACTION")]
    pub max_gas_per_transaction: u32,
    #[serde(rename = "KECCAK_ROUND_COST_GAS")]
    pub keccak_round_cost_gas: u32,
    #[serde(rename = "SHA256_ROUND_COST_GAS")]
    pub sha256_round_cost_gas: u32,
    #[serde(rename = "ECRECOVER_COST_GAS")]
    pub ecrecover_cost_gas: u32,
    #[serde(rename = "PRIORITY_TX_MINIMAL_GAS_PRICE")]
    pub priority_tx_minimal_gas_price: u32,
    #[serde(rename = "PRIORITY_TX_MAX_GAS_PER_BATCH")]
    pub priority_tx_max_gas_per_batch: u32,
    #[serde(rename = "PRIORITY_TX_PUBDATA_PER_BATCH")]
    pub priority_tx_pubdata_per_batch: u32,
    #[serde(rename = "PRIORITY_TX_BATCH_OVERHEAD_L1_GAS")]
    pub priority_tx_batch_overhead_l1_gas: u32,
}

impl SystemConfig {
    pub async fn init_from_github(commit: &str) -> Self {
        let contents: String = Self::get_contents(commit).await;
        serde_json::from_str(&contents).expect("Failed to parse JSON")
    }

    async fn get_contents(commit: &str) -> String {
        get_contents_from_github(commit, "matter-labs/era-contracts", "SystemConfig.json").await
    }
}
