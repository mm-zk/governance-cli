use std::fmt::Display;

use alloy::sol;

use super::IssueLevel;

sol! {
    #[derive(Debug)]
    struct ForceDeployment {
        bytes32 bytecodeHash;
        address newAddress;
        bool callConstructor;
        uint256 value;
        bytes input;
    }
}

impl ForceDeployment {
    pub fn quick_verify(&self) -> anyhow::Result<IssueLevel> {
        Ok(IssueLevel::None("ok".to_string()))
    }
}

impl Display for ForceDeployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Force deploy: {} to {}",
            self.bytecodeHash, self.newAddress
        )
    }
}
