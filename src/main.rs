use alloy::{
    hex::{self, FromHex, ToHexExt},
    primitives::{Address, FixedBytes},
};
use serde::Deserialize;
use std::{fmt::Debug, fs};
use traits::{GenesisConfig, VerificationResult, Verifiers, Verify};
use utils::address_verifier::AddressVerifier;

mod elements;
mod traits;
mod utils;
use clap::Parser;
use elements::{
    call_list::CallList, deployed_addresses::DeployedAddresses,
    governance_stage1_calls::GovernanceStage1Calls, governance_stage2_calls::GovernanceStage2Calls,
};

#[derive(Debug, Deserialize)]
struct Config {
    #[allow(dead_code)]
    chain_upgrade_diamond_cut: String,
    era_chain_id: u64,
    #[allow(dead_code)]
    l1_chain_id: u64,
    governance_stage1_calls: String,
    governance_stage2_calls: String,

    deployed_addresses: DeployedAddresses,
    #[allow(dead_code)]
    contracts_config: ContractsConfig,

    create2_factory_addr: Address,
    #[allow(dead_code)]
    create2_factory_salt: String,
    #[allow(dead_code)]
    deployer_addr: String,

    #[allow(dead_code)]
    owner_address: String,

    transactions: Vec<String>,

    other_config: Option<OtherConfig>,
}

impl Config {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        self.deployed_addresses.add_to_verifier(address_verifier);
        if let Some(other_config) = &self.other_config {
            other_config.add_to_verifier(address_verifier);
        }
    }
}

// Temporary struct to hold the other config data that is missing from the original one
#[derive(Debug, Deserialize)]
struct OtherConfig {
    rollup_da_manager: Address,
    state_transition_manager: Address,
    upgrade_timer: Address,
    transparent_proxy_admin: Address,
    bridgehub_proxy: Address,
    // verified by call to bridgehub.
    old_shared_bridge_proxy: Address,
    // verified by call to shared bridge.
    legacy_erc20_bridge: Address,
    //aliased_governance: Address,
    //shared_bridge_legacy_impl: Address,
    //erc20_bridged_standard: Address,
    //blob_versioned_hash_retriever: Address,
}

impl OtherConfig {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        address_verifier.add_address(self.rollup_da_manager, "rollup_da_manager");
        address_verifier.add_address(self.state_transition_manager, "state_transition_manager");
        address_verifier.add_address(self.upgrade_timer, "upgrade_timer");
        address_verifier.add_address(self.transparent_proxy_admin, "transparent_proxy_admin");
        address_verifier.add_address(self.bridgehub_proxy, "bridgehub_proxy");
        address_verifier.add_address(self.old_shared_bridge_proxy, "old_shared_bridge_proxy");
        address_verifier.add_address(self.legacy_erc20_bridge, "legacy_erc20_bridge_proxy");
        /*
        address_verifier.add_address(self.aliased_governance, "aliased_governance");
        address_verifier.add_address(self.shared_bridge_legacy_impl, "shared_bridge_legacy_impl");
        address_verifier.add_address(self.erc20_bridged_standard, "erc20_bridged_standard");
        address_verifier.add_address(
            self.blob_versioned_hash_retriever,
            "blob_versioned_hash_retriever",
        );*/
    }

    // This method loads the 'missing' information from the config itself.
    // This is a temporary thing - these addresses should be explictily put inside the high level
    // config file instead.
    pub fn init_from_config(config: &Config) -> Self {
        let rollup_da_manager = CallList::parse(&config.governance_stage1_calls).elems[3].target;
        let state_transition_manager =
            CallList::parse(&config.governance_stage1_calls).elems[4].target;
        let upgrade_timer = CallList::parse(&config.governance_stage1_calls).elems[6].target;

        let transparent_proxy_admin =
            CallList::parse(&config.governance_stage2_calls).elems[0].target;

        let bridgehub_proxy = CallList::parse(&config.governance_stage2_calls).elems[5].target;
        let old_shared_bridge_proxy =
            CallList::parse(&config.governance_stage2_calls).elems[6].target;

        let legacy_erc20_bridge = Address::from_slice(
            &CallList::parse(&config.governance_stage2_calls).elems[3].data[16..36],
        );

        Self {
            rollup_da_manager,
            state_transition_manager,
            upgrade_timer,
            transparent_proxy_admin,
            bridgehub_proxy,
            old_shared_bridge_proxy,
            legacy_erc20_bridge,
            //aliased_governance: config.deployed_addresses.aliased_governance,
            //shared_bridge_legacy_impl: config.deployed_addresses.l2SharedBridgeLegacyImpl,
            //erc20_bridged_standard: config.deployed_addresses.l2BridgedStandardERC20Impl,
            //blob_versioned_hash_retriever: config.deployed_addresses.blob_versioned_hash_retriever,
        }
    }
}

impl Verify for OtherConfig {
    async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Other config verification ==");

        // result
        //     .expect_create2_params(
        //         verifiers,
        //         &self.rollup_da_manager,
        //         "l1-contracts/RollupDAManager",
        //     )
        //     .await;

        // result
        //     .expect_create2_params(
        //         verifiers,
        //         &self.upgrade_timer,
        //         "l1-contracts/GovernanceUpgradeTimer",
        //     )
        //     .await;

        match verifiers.bridgehub_address {
            Some(bridgehub_address) => {
                if bridgehub_address != self.bridgehub_proxy {
                    result.report_error(&format!(
                        "Bridgehub address mismatch: expected {}, got {}",
                        self.bridgehub_proxy, bridgehub_address
                    ));
                }
            }
            None => {
                result.report_warn(&format!(
                    "Cannot verify Bridgehub address {} - as it wasn't provided in the flags.",
                    self.bridgehub_proxy
                ));
            }
        }

        let bridgehub_info = verifiers
            .network_verifier
            .get_bridgehub_info(self.bridgehub_proxy.clone())
            .await
            .unwrap();

        match bridgehub_info.stm_address {
            Some(stm_address) => {
                if stm_address != self.state_transition_manager {
                    result.report_error(&format!(
                        "Bridgehub STM mismatch: expected {}, got {}",
                        self.state_transition_manager, stm_address
                    ));
                }
            }
            None => {
                result.report_warn(&format!(
                    "Cannot verify STM address {} - as L2 RPC is not provided.",
                    self.state_transition_manager
                ));
            }
        }

        if bridgehub_info.shared_bridge != self.old_shared_bridge_proxy {
            result.report_error(&format!(
                "Bridgehub shared bridge mismatch: expected {}, got {}",
                self.old_shared_bridge_proxy, bridgehub_info.shared_bridge
            ));
        }

        if bridgehub_info.legacy_bridge != self.legacy_erc20_bridge {
            result.report_error(&format!(
                "Bridgehub legacy bridge mismatch: expected {}, got {}",
                self.legacy_erc20_bridge, bridgehub_info.legacy_bridge
            ));
        }

        /*

        result
            .expect_deployed_bytecode(verifiers, &self.aliased_governance, "AliasedGovernance")
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.shared_bridge_legacy_impl,
                "SharedBridgeLegacyImpl",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.erc20_bridged_standard,
                "ERC20BridgedStandard",
            )
            .await;

        result
            .expect_deployed_bytecode(
                verifiers,
                &self.blob_versioned_hash_retriever,
                "BlobVersionedHashRetriever",
            )
            .await;*/

        Ok(())
    }
}

impl Verify for Config {
    async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Config verification ==");

        match verifiers.network_verifier.get_l2_chain_id().await {
            Some(chain_id) => {
                if self.era_chain_id == chain_id {
                    result.report_ok("Chain id");
                } else {
                    result.report_error(&format!(
                        "chain id mismatch: {} vs {} ",
                        self.era_chain_id, chain_id
                    ));
                }
            }
            None => {
                result.report_warn(&format!("Cannot check chain id - probably not connected",));
            }
        }
        // Check that addresses actually contain correct bytecodes.
        self.deployed_addresses.verify(&self, verifiers, result).await?;

        result
            .expect_deployed_bytecode(verifiers, &self.create2_factory_addr, "Create2Factory")
            .await;

        self.other_config
            .as_ref()
            .unwrap()
            .verify(verifiers, result)
            .await?;

        let stage1 = GovernanceStage1Calls {
            calls: CallList::parse(&self.governance_stage1_calls),
        };

        stage1.verify(verifiers, result).await?;

        let stage2 = GovernanceStage2Calls {
            calls: CallList::parse(&self.governance_stage2_calls),
        };
        stage2.verify(verifiers, result).await?;

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

pub fn address_eq(address: &Address, addr_string: &String) -> bool {
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
    #[clap(long)]
    era_commit: Option<String>,

    // Commit from era-contracts - used for bytecode verification
    #[clap(long)]
    contracts_commit: Option<String>,

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
    bridgehub_address: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    env_logger::init();

    // Read the YAML file
    let yaml_content = fs::read_to_string(args.ecosystem_yaml)?;

    // Parse the YAML content
    let mut config: Config = serde_yaml::from_str(&yaml_content)?;

    let mut verifiers = Verifiers::new(args.testnet_contracts, args.bridgehub_address);

    verifiers
        .bytecode_verifier
        .init_from_github(
            &args
                .contracts_commit
                .unwrap_or("3d73e064c2371ef32edfdbcf9c199e4c85b0fd7e".to_string()),
        )
        .await;

    verifiers.genesis_config = Some(
        GenesisConfig::init_from_github(
            &args
                .era_commit
                .unwrap_or("0efe1db5126bc2d2b0702a1404f7eb0ca0231ef0".to_string()),
        )
        .await,
    );

    if let Some(l1_rpc) = &args.l1_rpc {
        verifiers
            .network_verifier
            .add_l1_network_rpc(l1_rpc.clone());
        if verifiers.testnet_contracts {
            let chain_id = verifiers.network_verifier.get_l1_chain_id().await.unwrap();
            if chain_id == 1 {
                panic!("Testnet contracts are not expected to be deployed on L1 mainnet - you passed --testnet-contracts flag.");
            }
        }
    }

    if let Some(l2_rpc) = &args.l2_rpc {
        verifiers
            .network_verifier
            .add_l2_network_rpc(l2_rpc.clone());
    } else {
        if let Some(l2_chain_id) = args.l2_chain_id {
            verifiers.network_verifier.add_l2_chain_id(l2_chain_id);
        }
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
    verifiers.bytecode_verifier.add_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989",
        )
        .unwrap(),
        "Create2Factory".to_string(),
    );

    verifiers.bytecode_verifier.add_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "0x1d8a3e7186b2285da5ef3ccf4c63a672e91873f2ffdec522a241f72bfcab11c5",
        )
        .unwrap(),
        "TransparentProxyAdmin".to_string(),
    );

    let other_config = OtherConfig::init_from_config(&config);
    config.other_config = Some(other_config);

    let mut result = VerificationResult::default();

    config.add_to_verifier(&mut verifiers.address_verifier);

    let r = config.verify(&verifiers, &mut result).await;

    println!("{}", result);
    r.unwrap();

    Ok(())
}
