pub mod deployed_addresses;
pub mod force_deployment;
pub mod governance_stage1_calls;

enum IssueLevel {
    // All is good.
    None(String),

    // Ok for local development.
    // Not acceptable for any public network (stage, testnet, mainnet)
    Warn(String),

    // Not acceptable.
    Error(String),
}
