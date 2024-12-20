use alloy::{
    dyn_abi::SolType,
    hex::{self, ToHexExt},
    primitives::{ruint::aliases::U256, Address},
    sol,
    sol_types::SolCall,
};
use chrono::DateTime;
use serde::Deserialize;
use std::{fmt::Display, fs};

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
    validator_timelock_addr: String,
    bridges: Bridges,
    bridgehub: Bridgehub,
}

#[derive(Debug, Deserialize)]
struct Bridges {
    shared_bridge_proxy_addr: String,
}
#[derive(Debug, Deserialize)]
struct Bridgehub {
    ctm_deployment_tracker_proxy_addr: String,
}

#[derive(Debug, Deserialize)]
struct ContractsConfig {
    expected_rollup_l2_da_validator: String,
    priority_tx_max_gas_limit: u32,
}

struct UpgradeDeadline {
    pub deadline: U256,
}

impl Display for UpgradeDeadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.deadline == U256::MAX {
            write!(f, "INFINITY")
        } else {
            let seconds_since_epoch = self.deadline.try_into();

            match seconds_since_epoch {
                Ok(seconds) => {
                    let datetime = DateTime::from_timestamp(seconds, 0).unwrap();
                    write!(f, "UTC Time: {}", datetime.format("%Y-%m-%d %H:%M:%S"))
                }
                Err(_) => write!(f, "Huge, but not infinity.. strange"),
            }
        }
    }
}

struct ProtocolVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl From<U256> for ProtocolVersion {
    fn from(value: U256) -> Self {
        let rem: U256 = (1u64 << 32).try_into().unwrap();
        Self {
            major: (value.checked_shr(64.try_into().unwrap()).unwrap())
                .wrapping_rem(rem)
                .try_into()
                .unwrap(),
            minor: (value.checked_shr(32.try_into().unwrap()).unwrap())
                .wrapping_rem(rem)
                .try_into()
                .unwrap(),
            patch: value.wrapping_rem(rem).try_into().unwrap(),
        }
    }
}

impl Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

sol! {
    #[allow(missing_docs)]
    // solc v0.8.26; solc Counter.sol --via-ir --optimize --bin
    #[sol(rpc, bytecode="6080806040523460135760df908160198239f35b600080fdfe6080806040526004361015601257600080fd5b60003560e01c9081633fb5c1cb1460925781638381f58a146079575063d09de08a14603c57600080fd5b3460745760003660031901126074576000546000198114605e57600101600055005b634e487b7160e01b600052601160045260246000fd5b600080fd5b3460745760003660031901126074576020906000548152f35b34607457602036600319011260745760043560005500fea2646970667358221220e978270883b7baed10810c4079c941512e93a7ba1cd1108c781d4bc738d9090564736f6c634300081a0033")]
    contract Counter {
        uint256 public number;

        function setNumber(uint256 newNumber) public {
            number = newNumber;
        }

        function increment() public {
            number++;
        }

        function dummy(Call[] calls) {}
    }
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    struct CallList {
        Call[] elems;
    }

    function setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256 oldProtocolVersion, uint256 oldProtocolVersionDeadline,uint256 newProtocolVersion) {

    }


}

pub fn address_eq(address: &Address, addr_string: &String) -> bool {
    address.encode_hex()
        == addr_string
            .strip_prefix("0x")
            .unwrap_or(&addr_string)
            .to_ascii_lowercase()
}

impl DeployedAddresses {
    pub fn reverse_lookup(&self, address: Address) -> Option<String> {
        dbg!(address.encode_hex());
        if address_eq(&address, &self.native_token_vault_addr) {
            return Some("native_token_vault".to_string());
        }
        if address_eq(&address, &self.validator_timelock_addr) {
            return Some("validator_timelock_addr".to_string());
        }

        if address_eq(&address, &self.bridges.shared_bridge_proxy_addr) {
            return Some("shared_bridge_proxy".to_string());
        }
        if address_eq(&address, &self.bridgehub.ctm_deployment_tracker_proxy_addr) {
            return Some("ctm_deployment_tracker".to_string());
        }
        None
    }
}

pub fn selector_to_method_name(selector: String) -> Option<String> {
    if selector == hex::encode(setNewVersionUpgradeCall::SELECTOR) {
        return Some("setNewVersion".to_string());
    }

    if selector == "79ba5097" {
        return Some("acceptOwnership()".to_string());
    }

    if selector == "a39f7449" {
        return Some("startTimer()".to_string());
    }

    None
}

pub fn display_new_version_upgrade_call(data: &setNewVersionUpgradeCall) {
    let deadline = UpgradeDeadline {
        deadline: data.oldProtocolVersionDeadline,
    };
    let old_protocol_version: ProtocolVersion = data.oldProtocolVersion.into();
    let new_protocol_version: ProtocolVersion = data.newProtocolVersion.into();
    println!(
        "Protocol versions: {} {} {}",
        old_protocol_version, deadline, new_protocol_version,
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the YAML file
    let yaml_content = fs::read_to_string("data/gateway-upgrade-ecosystem.toml")?;

    // Parse the YAML content
    let config: Config = toml::from_str(&yaml_content)?;

    // Print the parsed configuration
    println!("{:#?}", config);

    //Counter::setNumberCall::abi_decode(data, validate);

    let aa =
        CallList::abi_decode_sequence(&hex::decode(config.governance_stage1_calls).unwrap(), false)
            .unwrap();

    println!("{:?}", aa.elems.len());

    for (i, x) in aa.elems.iter().enumerate() {
        println!("=== {} ==== ", i);
        println!(
            "{} {:?}",
            x.target,
            config.deployed_addresses.reverse_lookup(x.target)
        );
        println!("{} ", x.value);
        println!(
            "{} {:?}",
            x.data,
            selector_to_method_name(x.data.0.slice(0..4).encode_hex())
        );
    }

    let calldata = &aa.elems[4].data;
    let aa = setNewVersionUpgradeCall::abi_decode(calldata, true).unwrap();

    println!("Call: {:?} ", aa._0);

    display_new_version_upgrade_call(&aa);

    Ok(())
}
