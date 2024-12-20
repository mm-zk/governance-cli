use colored::Colorize;
use std::fmt::Display;

use crate::utils::{
    address_verifier::AddressVerifier, bytecode_verifier::BytecodeVerifier,
    network_verifier::NetworkVerifier, selector_verifier::SelectorVerifier,
};

#[derive(Default)]
pub struct Verifiers {
    pub selector_verifier: SelectorVerifier,
    pub address_verifier: AddressVerifier,
    pub bytecode_verifier: BytecodeVerifier,
    pub network_verifier: NetworkVerifier,
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
    fn verify(&self, verifiers: &Verifiers, result: &mut VerificationResult) -> anyhow::Result<()>;
}
