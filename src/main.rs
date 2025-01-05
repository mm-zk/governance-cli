use alloy::{hex::ToHexExt, primitives::Address};
use serde::Deserialize;
use std::{fmt::Debug, fs};
use traits::{GenesisConfig, VerificationResult, Verifiers, Verify};
use utils::address_verifier::AddressVerifier;

mod elements;
mod traits;
mod utils;
use elements::{
    call_list::CallList, deployed_addresses::DeployedAddresses,
    governance_stage1_calls::GovernanceStage1Calls, governance_stage2_calls::GovernanceStage2Calls,
};

#[derive(Debug, Deserialize)]
struct Config {
    #[allow(dead_code)]
    chain_upgrade_diamond_cut: String,
    era_chain_id: u32,
    #[allow(dead_code)]
    l1_chain_id: u32,
    governance_stage1_calls: String,
    governance_stage2_calls: String,

    deployed_addresses: DeployedAddresses,
    #[allow(dead_code)]
    contracts_config: ContractsConfig,
    #[allow(dead_code)]
    create2_factory_addr: String,
    #[allow(dead_code)]
    create2_factory_salt: String,
    #[allow(dead_code)]
    deployer_addr: String,

    #[allow(dead_code)]
    owner_address: String,
}

impl Config {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        self.deployed_addresses.add_to_verifier(address_verifier);
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
    old_shared_bridge_proxy: Address,
    legacy_erc20_bridge: Address,
    aliased_governance: Address,
    shared_bridge_legacy_impl: Address,
    erc20_bridged_standard: Address,
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
        address_verifier.add_address(self.aliased_governance, "aliased_governance");
        address_verifier.add_address(self.shared_bridge_legacy_impl, "shared_bridge_legacy_impl");
        address_verifier.add_address(self.erc20_bridged_standard, "erc20_bridged_standard");
    }
}

impl Verify for Config {
    fn verify(&self, verifiers: &Verifiers, result: &mut VerificationResult) -> anyhow::Result<()> {
        result.print_info("== Config verification ==");

        match verifiers.network_verifier.get_era_chain_id() {
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
        self.deployed_addresses.verify(verifiers, result)?;

        let stage1 = GovernanceStage1Calls {
            calls: CallList::parse(&self.governance_stage1_calls),
        };

        stage1.verify(verifiers, result)?;

        let stage2 = GovernanceStage2Calls {
            calls: CallList::parse(&self.governance_stage2_calls),
        };
        stage2.verify(verifiers, result)?;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Read the YAML file
    let yaml_content = fs::read_to_string("data/349ba7cb/gateway-upgrade-ecosystem.toml")?;

    // Parse the YAML content
    let config: Config = toml::from_str(&yaml_content)?;

    let mut verifiers = Verifiers::default();

    /*verifiers
    .bytecode_verifier
    .init_from_github("3e2dad0d96ff8ca21e3fb609d2123b5ace37f573")
    .await;*/

    /*verifiers
    .bytecode_verifier
    .init_from_github("7aab7a47857c0bac8eac5abb8ae695a63be1c3df")
    .await;*/

    verifiers
        .bytecode_verifier
        .init_from_github("c632483a56c2f65956abb1539cfde32ba057a003")
        .await;

    verifiers.genesis_config =
        Some(GenesisConfig::init_from_github("69ea2c61ae0e84da982493427bf39b6e62632de5").await);

    let mut result = VerificationResult::default();

    config.add_to_verifier(&mut verifiers.address_verifier);

    let other_yaml_content = fs::read_to_string("data/349ba7cb/other.toml")?;
    let other_config: OtherConfig = toml::from_str(&other_yaml_content)?;
    other_config.add_to_verifier(&mut verifiers.address_verifier);

    let r = config.verify(&verifiers, &mut result);

    println!("{}", result);
    r.unwrap();

    Ok(())
}
