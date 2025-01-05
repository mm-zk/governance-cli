use alloy::primitives::{Address, FixedBytes};
use colored::Colorize;
use serde::Deserialize;
use std::fmt::Display;
use std::panic::Location;

use crate::utils::{
    address_verifier::AddressVerifier, bytecode_verifier::BytecodeVerifier,
    get_contents_from_github, network_verifier::NetworkVerifier,
    selector_verifier::SelectorVerifier,
};

#[derive(Default)]
pub struct Verifiers {
    pub selector_verifier: SelectorVerifier,
    pub address_verifier: AddressVerifier,
    pub bytecode_verifier: BytecodeVerifier,
    pub network_verifier: NetworkVerifier,
    pub genesis_config: Option<GenesisConfig>,
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
    pub fn expect_bytecode(
        &mut self,
        verifiers: &Verifiers,
        bytecode_hash: &FixedBytes<32>,
        expected: &str,
    ) {
        match verifiers
            .bytecode_verifier
            .bytecode_hash_to_file(bytecode_hash)
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
                    "Cannot verify bytecode hash: {} - expected {}",
                    bytecode_hash, expected
                ));
            }
        }
    }
}

impl Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors > 0 {
            let res = "ERROR".red();
            write!(
                f,
                "{} errors: {} - result: {}",
                res, self.errors, self.result
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

pub trait Verify {
    async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()>;
}
