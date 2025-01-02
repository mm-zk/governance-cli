pub mod call_list;
pub mod deployed_addresses;
pub mod force_deployment;
pub mod governance_stage1_calls;
pub mod governance_stage2_calls;
pub mod post_upgrade_calldata;
pub mod protocol_version;
pub mod set_new_version_upgrade;
pub mod upgrade_deadline;

enum IssueLevel {
    // All is good.
    None(String),

    // Ok for local development.
    // Not acceptable for any public network (stage, testnet, mainnet)
    Warn(String),

    // Not acceptable.
    Error(String),
}
