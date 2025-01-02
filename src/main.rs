use alloy::{hex::ToHexExt, primitives::Address};
use serde::Deserialize;
use std::{fmt::Debug, fs};
use traits::{VerificationResult, Verifiers, Verify};
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Read the YAML file
    let yaml_content = fs::read_to_string("data/gateway-upgrade-ecosystem.toml")?;

    // Parse the YAML content
    let config: Config = toml::from_str(&yaml_content)?;

    let mut verifiers = Verifiers::default();

    let mut result = VerificationResult::default();

    config.add_to_verifier(&mut verifiers.address_verifier);

    let r = config.verify(&verifiers, &mut result);

    println!("{}", result);
    r.unwrap();

    Ok(())
}
