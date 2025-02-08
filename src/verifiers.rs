use alloy::{
    hex::{self, FromHex},
    primitives::{Address, Bytes, FixedBytes}, sol, sol_types::SolCall,
};
use colored::Colorize;
use serde::Deserialize;
use std::fmt::Display;
use std::panic::Location;

use crate::utils::{
    address_verifier::AddressVerifier, bytecode_verifier::BytecodeVerifier, fee_param_verifier::FeeParamVerifier, get_contents_from_github, network_verifier::NetworkVerifier, selector_verifier::SelectorVerifier
};

sol! {
  function transparentProxyConstructor(address impl, address initialAdmin, bytes memory initCalldata);
}

#[derive(Default)]
pub struct Verifiers {
    pub testnet_contracts: bool,
    pub bridgehub_address: Address,
    pub selector_verifier: SelectorVerifier,
    pub address_verifier: AddressVerifier,
    pub bytecode_verifier: BytecodeVerifier,
    pub network_verifier: NetworkVerifier,
    pub genesis_config: Option<GenesisConfig>,
    pub fee_param_verifier: FeeParamVerifier,
}

impl Verifiers {
    pub fn new(testnet_contracts: bool, bridgehub_address: String) -> Self {
        Self {
            testnet_contracts,
            bridgehub_address: Address::from_hex(bridgehub_address).unwrap(),
            ..Default::default()
        }
    }

    pub async fn append_addresses(&mut self) -> anyhow::Result<()> {
        let info = self.network_verifier.get_bridgehub_info(self.bridgehub_address).await;

        self.address_verifier.add_address(self.bridgehub_address, "bridgehub_proxy");
        self.address_verifier.add_address(info.stm_address, "state_transition_manager");
        self.address_verifier.add_address(info.transparent_proxy_admin, "transparent_proxy_admin");
        self.address_verifier.add_address(info.shared_bridge, "old_shared_bridge_proxy");
        self.address_verifier.add_address( info.legacy_bridge, "legacy_erc20_bridge_proxy");
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct GenesisConfig {
    pub genesis_root: String,
    pub genesis_rollup_leaf_index: u64,
    pub genesis_batch_commitment: String,
}

impl GenesisConfig {
    pub async fn init_from_github(commit: &str) -> Self {
        println!("init from github {}", commit);
        let data = get_contents_from_github(
            commit,
            "matter-labs/zksync-era",
            "etc/env/file_based/genesis.yaml",
        )
        .await;

        serde_yaml::from_str(&data).unwrap()
    }
}

#[derive(Default)]
pub struct VerificationResult {
    pub result: String,
    pub warnings: u64,
    pub errors: u64,
}

impl VerificationResult {
    pub fn print_info(&self, info: &str) {
        println!("{}", info);
    }
    pub fn report_ok(&self, info: &str) {
        println!("{} {}", "[OK]: ".green(), info);
    }

    pub fn report_warn(&mut self, warn: &str) {
        self.warnings += 1;
        println!("{} {}", "[WARN]:".yellow(), warn);
    }
    pub fn report_error(&mut self, error: &str) {
        self.errors += 1;
        println!("{} {}", "[ERROR]:".red(), error);
    }

    #[track_caller]
    pub fn expect_address(
        &mut self,
        verifiers: &Verifiers,
        address: &Address,
        expected: &str,
    ) -> bool {
        let address = verifiers.address_verifier.name_or_unknown(address);
        if address != expected {
            self.report_error(&format!(
                "Expected address {}, got {} at {}",
                expected,
                address,
                Location::caller()
            ));
            false
        } else {
            true
        }
    }

    #[track_caller]
    pub fn expect_zk_bytecode(
        &mut self,
        verifiers: &Verifiers,
        bytecode_hash: &FixedBytes<32>,
        expected: &str,
    ) {
        match verifiers
            .bytecode_verifier
            .zk_bytecode_hash_to_file(bytecode_hash)
        {
            Some(file_name) => {
                if file_name != expected {
                    self.report_error(&format!(
                        "Expected bytecode {}, got {} at {}",
                        expected,
                        file_name,
                        Location::caller()
                    ));
                }
            }
            None => {
                self.report_warn(&format!(
                    "Cannot verify bytecode hash: {} - expected {} at {}",
                    bytecode_hash,
                    expected,
                    Location::caller()
                ));
            }
        }
    }

    // Verifies *deployed* bytecode of a contract.
    // This function should be generally avoided in favor of the `expect_create2_params` function
    // as the latter would also ensure that the constructor logic is correct.
    pub async fn expect_deployed_bytecode(
        &mut self,
        verifiers: &Verifiers,
        address: &Address,
        expected_file: &str,
    ) {
        let deployed_bytecode = verifiers.network_verifier.get_bytecode_hash_at(address).await;

        let deployed_file = verifiers.bytecode_verifier.evm_deployed_bytecode_hash_to_file(&deployed_bytecode);
        
        let Some(deployed_file) = deployed_file else {
            self.report_error(&format!(
                "Bytecode at address {} empty: Expected {} at {}",
                address,
                expected_file,
                Location::caller()
            ));
            return;
        };

        if deployed_file != expected_file {
            self.report_error(&format!(
                "Bytecode from wrong file: Expected {} got {} at {}",
                expected_file,
                deployed_file,
                Location::caller()
            ));

            return;
        }

        self.report_ok(&format!(
            "{} at {}",
            expected_file, address
        ));
    }

    pub fn expect_create2_params(
        &mut self,
        verifiers: &Verifiers,
        address: &Address,
        expected_constructor_params: Vec<u8>,
        expected_file: &str,
    ) {
        self.expect_create2_params_internal(verifiers, address, expected_constructor_params, expected_file, true);
    }

    pub fn expect_create2_params_internal(
        &mut self,
        verifiers: &Verifiers,
        address: &Address,
        expected_constructor_params: Vec<u8>,
        expected_file: &str,
        report_ok: bool,
    ) -> bool {
        let Some(deployed_file)= verifiers.network_verifier.create2_known_bytecodes.get(address) else {
            self.report_error(&format!("Address {:#?} {} is not present in the create2 deployments", address, expected_file));
            return false; 
        };

        if deployed_file != expected_file {
            self.report_error(&format!(
                "Bytecode from wrong file: Expected {} got {} at {}",
                expected_file,
                deployed_file,
                Location::caller()
            ));

            return false;
        }

        // Unwrap is safe since depployed file/constructor params are added at the same time
        // todo: merge the structs.
        let constructor_params = verifiers.network_verifier.create2_constructor_params.get(address).unwrap();

        if *constructor_params != expected_constructor_params {
            self.report_error(&format!(
                "Invalid constructor params for address {} ({}): Expected {} got {} at {}",
                address,
                expected_file,
                hex::encode(&expected_constructor_params),
                hex::encode(constructor_params),
                Location::caller()
            ));

            return false;
        }   

        if report_ok {
            self.report_ok(&format!(
                "{} at {}",
                expected_file, address
            ));
        }
        true 
    }

    pub async fn expect_create2_params_proxy_with_bytecode(
        &mut self,
        verifiers: &crate::verifiers::Verifiers,
        address: &Address,
        expected_init_params: Vec<u8>,
        expected_initial_admin: Address,
        expected_impl_constructor_params: Vec<u8>,
        expected_file: &str,
    ) {
        let transparent_proxy_key = FixedBytes::from_hex(
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        )
        .unwrap();
        let implementation_address = verifiers
            .network_verifier
            .storage_at(address, &transparent_proxy_key)
            .await;

        let implementation_address = Address::from_slice(&implementation_address.as_slice()[12..]);

        
        let call = transparentProxyConstructorCall::new((implementation_address, expected_initial_admin,  Bytes::copy_from_slice(&expected_init_params)));
        let mut constructor_params = vec![];
        call.abi_encode_raw(&mut constructor_params);

        println!("EXPECTED PARAMS = {}", hex::encode(&constructor_params));

        let is_proxy = self.expect_create2_params_internal(
            verifiers,
            address,
            constructor_params,
            "l1-contracts/TransparentUpgradeableProxy",
            false,
        );

        if !is_proxy {
            // The error handling has been already done in `expect_deployed_bytecode_internal`, we
            // don't have anything else to do here.
            return;
        }

        self.expect_create2_params(
            verifiers,
            &implementation_address,
            expected_impl_constructor_params,
            expected_file,
        );
    }
}

impl Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors > 0 {
            let res = "ERROR".red();
            write!(
                f,
                "{} errors: {}, warnings: {} - result: {}",
                res, self.errors, self.warnings, self.result
            )
        } else {
            if self.warnings == 0 {
                let res = "OK".green();
                write!(f, "{} - result: {}", res, self.result)
            } else {
                let res = "WARN".yellow();
                write!(
                    f,
                    "{} warnings: {} - result: {}",
                    res, self.warnings, self.result
                )
            }
        }
    }
}
