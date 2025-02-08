use alloy::{
    hex::{self, FromHex, ToHexExt},
    primitives::{Address, FixedBytes},
};
use serde::Deserialize;
use std::{fmt::Debug, fs, str::FromStr};
use traits::{GenesisConfig, VerificationResult, Verifiers, Verify};
use utils::{address_verifier::AddressVerifier, apply_l2_to_l1_alias};

mod elements;
mod traits;
mod utils;
use clap::Parser;
use elements::{
    call_list::CallList, deployed_addresses::DeployedAddresses, governance_stage1_calls::GovernanceStage1Calls, governance_stage2_calls::GovernanceStage2Calls, post_upgrade_calldata::compute_expected_address_for_file, protocol_version::ProtocolVersion
};

const CONTRACTS_COMMIT: &str = "16dedf6d77695ce00f81fce35a3066381b97fca1";
const ERA_COMMIT: &str = "ee14cb4826dbec00e9e7d909ed9af3994379df46";

pub(crate) const EXPECTED_NEW_PROTOCOL_VERSION_STR: &'static str = "0.26.0";
pub(crate) const EXPECTED_OLD_PROTOCOL_VERSION_STR: &'static str = "0.25.0";
pub(crate) const MAX_NUMBER_OF_ZK_CHAINS: u32 = 100;

pub(crate) fn get_expected_new_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_NEW_PROTOCOL_VERSION_STR).unwrap()
}

pub(crate) fn get_expected_old_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_OLD_PROTOCOL_VERSION_STR).unwrap()
}

#[derive(Debug, Deserialize)]
struct Config {
    #[allow(dead_code)]
    chain_upgrade_diamond_cut: String,
    pub(crate) era_chain_id: u64,
    pub(crate) l1_chain_id: u64,
    governance_stage1_calls: String,
    governance_stage2_calls: String,

    deployed_addresses: DeployedAddresses,
    contracts_config: ContractsConfig,

    create2_factory_addr: Address,
    #[allow(dead_code)]
    create2_factory_salt: String,
    #[allow(dead_code)]
    deployer_addr: String,

    protocol_upgrade_handler_proxy_address: String,

    transactions: Vec<String>,
}

impl Config {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        self.deployed_addresses.add_to_verifier(address_verifier);
    }
}

impl Verify for Config {
    async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Config verification ==");

        let provider_chain_id = verifiers.network_verifier.get_l2_chain_id().await;
        if provider_chain_id == self.era_chain_id {
            result.report_ok("Chain id");
        } else {
            result.report_error(&format!(
                "chain id mismatch: {} vs {} ",
                self.era_chain_id, provider_chain_id
            ));
        }

        // Check that addresses actually contain correct bytecodes.
        self.deployed_addresses.verify(&self, verifiers, result).await?;
        let (facets_to_remove, facets_to_add) = self.deployed_addresses.get_expected_facet_cuts(&self, verifiers).await?;

        result
            .expect_deployed_bytecode(verifiers, &self.create2_factory_addr, "Create2Factory")
            .await;

        let stage1 = GovernanceStage1Calls {
            calls: CallList::parse(&self.governance_stage1_calls),
        };

        stage1.verify(&self.deployed_addresses, verifiers, result, facets_to_remove.merge(facets_to_add.clone())).await?;

        let stage2 = GovernanceStage2Calls {
            calls: CallList::parse(&self.governance_stage2_calls),
        };
        stage2.verify(verifiers, result, facets_to_add).await?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ContractsConfig {
    #[allow(dead_code)]
    expected_rollup_l2_da_validator: String,
    #[allow(dead_code)]
    priority_tx_max_gas_limit: u32,
}

pub fn address_eq(address: &Address, addr_string: &str) -> bool {
    address.encode_hex()
        == addr_string
            .strip_prefix("0x")
            .unwrap_or(&addr_string)
            .to_ascii_lowercase()
}

#[derive(Debug, Parser)]
struct Args {
    // ecosystem_yaml file (gateway_ecosystem_upgrade_output.yaml - from zksync_era/configs)
    #[clap(short, long)]
    ecosystem_yaml: String,

    // Commit from zksync-era repository (used for genesis verification)
    #[clap(long, default_value = ERA_COMMIT)]
    era_commit: String,

    // Commit from era-contracts - used for bytecode verification
    #[clap(long, default_value = CONTRACTS_COMMIT)]
    contracts_commit: String,

    // L1 address
    #[clap(long)]
    l1_rpc: Option<String>,

    // L2 address
    #[clap(long)]
    l2_rpc: Option<String>,

    // If L2 RPC is not available, you can provide l2 chain id instead.
    #[clap(long)]
    l2_chain_id: Option<u64>,

    // If set - then will expect testnet contracts to be deployed (like TestnetVerifier).
    #[clap(long)]
    testnet_contracts: bool,

    #[clap(long)]
    bridgehub_address: String,

}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    env_logger::init();

    // Read the YAML file
    let yaml_content = fs::read_to_string(args.ecosystem_yaml)?;

    // Parse the YAML content
    let config: Config = serde_yaml::from_str(&yaml_content)?;

    let mut verifiers = Verifiers::new(args.testnet_contracts, args.bridgehub_address.clone());

    verifiers
        .bytecode_verifier
        .init_from_github(
            &args
                .contracts_commit
                .clone()
        )
        .await;

    verifiers.genesis_config = Some(
        GenesisConfig::init_from_github(
            &args
                .era_commit
        )
        .await,
    );

    verifiers
        .fee_param_verifier
        .init_from_github(
            &args
                .contracts_commit
        )
        .await;

    if let Some(l2_rpc) = &args.l2_rpc {
        verifiers
            .network_verifier
            .add_l2_network_rpc(l2_rpc.clone());
    } else {
        if let Some(l2_chain_id) = args.l2_chain_id {
            verifiers.network_verifier.add_l2_chain_id(l2_chain_id);
        }
    }

    if let Some(l1_rpc) = &args.l1_rpc {
        verifiers
            .network_verifier
            .add_l1_network_rpc(l1_rpc.clone());
        if verifiers.testnet_contracts {
            let chain_id = verifiers.network_verifier.get_l1_chain_id().await;
            if chain_id == 1 {
                panic!("Testnet contracts are not expected to be deployed on L1 mainnet - you passed --testnet-contracts flag.");
            }
        }
        verifiers
            .fee_param_verifier
            .init_from_on_chain(
                &Address::from_hex(&args.bridgehub_address.clone()).unwrap(),
                &verifiers.network_verifier,
            )
            .await;
    }

    println!(
        "Adding {} transactions from create2",
        config.transactions.len()
    );

    for transaction in &config.transactions {
        if let Some((address, contract, constructor_param)) = verifiers
            .network_verifier
            .check_create2_deploy(
                &transaction,
                &config.create2_factory_addr,
                &FixedBytes::<32>::from_hex(&config.create2_factory_salt).unwrap(),
                &verifiers
                .bytecode_verifier
            )
            .await
        {
            verifiers
                .network_verifier
                .create2_constructor_params
                .insert(address, constructor_param)
                .map(|_| {
                    panic!("Duplicate deployment for {:#?}", address);
                });

            verifiers
                .network_verifier.create2_known_bytecodes.insert(address, contract.clone())
                .map(|_| {
                    panic!("Duplicate deployment for {:#?}", address);
                });
        }
    }

    // some constants -- TODO: verify
    verifiers.bytecode_verifier.insert_evm_deployed_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989",
        )
        .unwrap(),
        "Create2Factory".to_string(),
    );

    verifiers.bytecode_verifier.insert_evm_deployed_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "0x1d8a3e7186b2285da5ef3ccf4c63a672e91873f2ffdec522a241f72bfcab11c5",
        )
        .unwrap(),
        "TransparentProxyAdmin".to_string(),
    );

    // Hash of the proxy admin used for stage proofs
    // https://sepolia.etherscan.io/address/0x93AEeE8d98fB0873F8fF595fDd534A1f288786D2
    verifiers.bytecode_verifier.insert_evm_deployed_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "1e651120773914ac75c42598ceac4da0dc3e21709d438937f742ecf916ac30ae",
        )
        .unwrap(),
        "TransparentProxyAdmin".to_string(),
    );

    let protocol_upgrade_handler_proxy_address = Address::from_str(&config.protocol_upgrade_handler_proxy_address).unwrap();

    let mut result = VerificationResult::default();

    verifiers.address_verifier.add_address(protocol_upgrade_handler_proxy_address, "protocol_upgrade_handler_proxy");
    verifiers.address_verifier.add_address(apply_l2_to_l1_alias(protocol_upgrade_handler_proxy_address), "aliased_protocol_upgrade_handler_proxy");
    verifiers.address_verifier.add_address(compute_expected_address_for_file(
        &verifiers,
        "l1-contracts/L2SharedBridgeLegacy",
    ),"l2_shared_bridge_legacy_impl");
    verifiers.address_verifier.add_address(compute_expected_address_for_file(
        &verifiers,
        "l1-contracts/L2SharedBrBridgedStandardERC20idgeLegacy",
    ),"erc20_bridged_standard");

    config.add_to_verifier(&mut verifiers.address_verifier);
    verifiers.address_verifier.add_address(verifiers.network_verifier.get_proxy_admin(protocol_upgrade_handler_proxy_address).await, "protocol_upgrade_handler_transparent_proxy_admin");
    verifiers
        .append_addresses()
        .await
        .unwrap();

    let r = config.verify(&verifiers, &mut result).await;

    println!("{}", result);
    r.unwrap();

    Ok(())
}
