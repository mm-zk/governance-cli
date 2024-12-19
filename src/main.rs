use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct Config {
    chain_upgrade_diamond_cut: String,
    era_chain_id: u32,
    governance_stage1_calls: String,
    deployed_addresses: DeployedAddresses,
    contracts_config: ContractsConfig,
}

#[derive(Debug, Deserialize)]
struct DeployedAddresses {
    native_token_vault_addr: String,
}

#[derive(Debug, Deserialize)]
struct ContractsConfig {
    expected_rollup_l2_da_validator: String,
    priority_tx_max_gas_limit: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the YAML file
    let yaml_content = fs::read_to_string("data/gateway-upgrade-ecosystem.toml")?;

    // Parse the YAML content
    let config: Config = toml::from_str(&yaml_content)?;

    // Print the parsed configuration
    println!("{:#?}", config);

    Ok(())
}
