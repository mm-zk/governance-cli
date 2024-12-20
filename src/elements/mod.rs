pub mod deployed_addresses;
pub mod force_deployment;

enum IssueLevel {
    // All is good.
    None(String),

    // Ok for local development.
    // Not acceptable for any public network (stage, testnet, mainnet)
    Warn(String),

    // Not acceptable.
    Error(String),
}
