use alloy::{
    dyn_abi::SolType,
    hex::{self, ToHexExt},
    primitives::{ruint::aliases::U256, Address, Selector},
    sol,
    sol_types::SolCall,
};
use chrono::DateTime;
use serde::Deserialize;
use std::{
    fmt::{Debug, Display, Formatter},
    fs,
};
use traits::{VerificationResult, Verifiers, Verify};
use utils::{
    address_verifier::AddressVerifier,
    bytecode_verifier::{self, BytecodeVerifier},
    selector_verifier::{self, SelectorVerifier},
};

mod elements;
mod traits;
mod utils;
use elements::{deployed_addresses::DeployedAddresses, force_deployment::ForceDeployment};

#[derive(Debug, Deserialize)]
struct Config {
    chain_upgrade_diamond_cut: String,
    era_chain_id: u32,
    governance_stage1_calls: String,
    deployed_addresses: DeployedAddresses,
    contracts_config: ContractsConfig,
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
        self.deployed_addresses.verify(verifiers, result)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ContractsConfig {
    expected_rollup_l2_da_validator: String,
    priority_tx_max_gas_limit: u32,
}

struct UpgradeDeadline {
    pub deadline: U256,
}

impl From<U256> for UpgradeDeadline {
    fn from(value: U256) -> Self {
        Self { deadline: value }
    }
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

    enum Action {
        Add,
        Replace,
        Remove
    }

    struct FacetCut {
        address facet;
        Action action;
        bool isFreezable;
        bytes4[] selectors;
    }


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

    #[derive(Debug)]
    struct GatewayUpgradeEncodedInput {
        ForceDeployment[] forceDeployments;
        uint256 l2GatewayUpgradePosition;
        bytes fixedForceDeploymentsData;
        address ctmDeployer;
        address oldValidatorTimelock;
        address newValidatorTimelock;
        address wrappedBaseTokenStore;
    }



}

pub fn address_eq(address: &Address, addr_string: &String) -> bool {
    address.encode_hex()
        == addr_string
            .strip_prefix("0x")
            .unwrap_or(&addr_string)
            .to_ascii_lowercase()
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

impl Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Add => write!(f, "Add"),
            Self::Replace => write!(f, "Replace"),
            Self::Remove => write!(f, "Remove"),
            Self::__Invalid => write!(f, "__Invalid"),
        }
    }
}

impl Debug for FacetCut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FacetCut")
            .field("facet", &self.facet)
            .field("action", &self.action)
            .field("isFreezable", &self.isFreezable)
            .field("selectors", &self.selectors)
            .finish()
    }
}

impl Debug for DiamondCutData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiamondCutData")
            .field("facetCuts", &self.facetCuts)
            .field("initAddress", &self.initAddress)
            .field("initCalldata", &self.initCalldata)
            .finish()
    }
}

pub fn display_facets(diamond_cut: &DiamondCutData) {
    for facet in diamond_cut.facetCuts.iter() {
        println!("{:?}", facet);
    }
}

pub fn display_init_calldata(diamond_cut: &DiamondCutData) {
    // TODO: check - this should be 'gateway upgrade'.
    println!("Init address: {:?}", diamond_cut.initAddress);

    let upgrade = upgradeCall::abi_decode(&diamond_cut.initCalldata, true).unwrap();
    println!("{:?}", upgrade._proposedUpgrade);

    let proposed_upgrade = &upgrade._proposedUpgrade;

    println!(
        "Hashes: bootloader: {:?}  default account: {:?}",
        proposed_upgrade.bootloaderHash, proposed_upgrade.defaultAccountHash
    );
    println!("Verifier adress: {:?}", proposed_upgrade.verifier);

    // empty?? suspicious.
    println!("Verifier params: {:?}", proposed_upgrade.verifierParams);

    println!(
        "New protocol version: {}",
        ProtocolVersion::from(proposed_upgrade.newProtocolVersion)
    );
    // TODO: this should be 'sane'
    println!(
        "New timestamp: {}",
        UpgradeDeadline::from(proposed_upgrade.newProtocolVersion)
    );

    println!("Upgrade tx: {:?}", proposed_upgrade.l2ProtocolUpgradeTx);
    display_l2_protocol_upgrade_tx(&proposed_upgrade.l2ProtocolUpgradeTx);

    let post_upgrade =
        GatewayUpgradeEncodedInput::abi_decode(&proposed_upgrade.postUpgradeCalldata, true)
            .unwrap();

    println!("post upgrade: {:?}", post_upgrade);
}

pub fn display_l2_protocol_upgrade_tx(tx: &L2CanonicalTransaction) {
    println!("L2 protocol upgrade to: {:?}", tx.to);
    // TODO: analyze factory deps...
    // Data is empty??
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Read the YAML file
    let yaml_content = fs::read_to_string("data/gateway-upgrade-ecosystem.toml")?;

    // Parse the YAML content
    let config: Config = toml::from_str(&yaml_content)?;

    // Print the parsed configuration
    //println!("{:#?}", config);

    let mut verifiers = Verifiers::default();

    let mut result = VerificationResult::default();

    config.add_to_verifier(&mut verifiers.address_verifier);

    let _ = config.verify(&verifiers, &mut result).unwrap();

    println!("{}", result);
    /*
    let aa =
        CallList::abi_decode_sequence(&hex::decode(config.governance_stage1_calls).unwrap(), false)
            .unwrap();

    println!("{:?}", aa.elems.len());

    for (i, x) in aa.elems.iter().enumerate() {
        println!("=== {} ==== ", i);
        println!(
            "{} {:?}",
            x.target,
            verifiers.address_verifier.reverse_lookup(&x.target)
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

    println!("Call: {:?} ", aa.diamondCut);
    display_new_version_upgrade_call(&aa);

    display_facets(&aa.diamondCut);

    display_init_calldata(&aa.diamondCut);*/

    Ok(())
}
