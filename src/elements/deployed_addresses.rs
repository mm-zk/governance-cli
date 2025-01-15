use std::str::FromStr;

use crate::{traits::Verify, utils::{address_verifier::AddressVerifier, network_verifier::BridgehubInfo}, Config};
use alloy::{primitives::{Address, U256}, sol, sol_types::{SolCall, SolConstructor, SolValue}};
use serde::Deserialize;
use L2WrappedBaseTokenStore::L2WrappedBaseTokenStoreCalls;


sol! {

    contract L1NativeTokenVault {
        constructor(
            address _l1WethAddress,
            address _l1AssetRouter,
            address _l1Nullifier
        ) {

        }

        function initialize(address _owner, address _bridgedTokenBeacon) {

        }
    }

    #[sol(rpc)]
    contract ValidatorTimelock {
        // FIXME: `uint256 eraChainId` is here because of a mishap in the creation script,
        // it is not present in the contract itself
        constructor(address _initialOwner, uint32 _executionDelay, uint256 eraChainId) {}
        address public chainTypeManager;
        address public owner;
        uint32 public executionDelay;
    }

    #[sol(rpc)]
    contract L2WrappedBaseTokenStore {
        constructor(address _initialOwner, address _admin) {}
        address public admin;
    }

    #[sol(rpc)]
    contract CTMDeploymentTracker {
        constructor(address _bridgehub, address _l1AssetRouter) {

        }
        address public owner;

        function initialize(address _owner){}
    }

    #[sol(rpc)]
    contract L1AssetRouter {
        constructor(
            address _l1WethAddress,
            address _bridgehub,
            address _l1Nullifier,
            uint256 _eraChainId,
            address _eraDiamondProxy
        ) {}
        function initialize(address _owner) external;

        /// @dev Address of native token vault.
        address public nativeTokenVault;

        /// @dev Address of legacy bridge.
        address public legacyBridge;

        address public owner;
    }


    contract L1Nullifier {
        constructor(address _bridgehub, uint256 _eraChainId, address _eraDiamondProxy);
    }

    contract L1ERC20Bridge {
        constructor(
            address _nullifier,
            address _assetRouter,
            address _nativeTokenVault,
            uint256 _eraChainId
        );
    }

    contract ChainTypeManager {
        constructor(address _bridgehub);
    }

    contract AdminFacet {
        constructor(uint256 _l1ChainId, address _rollupDAManager);
    }

    contract ExecutorFacet {
        constructor(uint256 _l1ChainId);
    }

    contract MailboxFacet {
        constructor(uint256 _eraChainId, uint256 _l1ChainId);
    }

    contract BridgehubImpl {
        constructor(uint256 _l1ChainId, address _owner, uint256 _maxNumberOfZKChains) {}
    }
}

#[derive(Debug, Deserialize)]
pub struct DeployedAddresses {
    native_token_vault_addr: Address,
    validator_timelock_addr: Address,
    l2_wrapped_base_token_store_addr: Address,
    // FIXME: verify that the contract is correct
    l1_bytecodes_supplier_addr: Address,
    // FIXME: verify that the following contract is correct.
    rollup_l1_da_validator_addr: Address,
    // FIXME: verify that the following contract is correct.
    validium_l1_da_validator_addr: Address,
    // FIXME: verify that the following contract is correct.
    l1_transitionary_owner: Address,
    // FIXME: verify that the following contract is correct.
    l1_rollup_da_manager: Address,
    bridges: Bridges,
    bridgehub: Bridgehub,
    state_transition: StateTransition,
}

#[derive(Debug, Deserialize)]
pub struct Bridges {
    shared_bridge_proxy_addr: Address,
    pub l1_nullifier_implementation_addr: Address,
    pub erc20_bridge_implementation_addr: Address,
    // FIXME: verify the contents of this contract.
    pub bridged_standard_erc20_impl: Address,
    // FIXME: verify the contents of this contract.
    pub bridged_token_beacon: Address
}
#[derive(Debug, Deserialize)]
pub struct Bridgehub {
    ctm_deployment_tracker_proxy_addr: Address,
    bridgehub_implementation_addr: Address,
    // FIXME: verify that the contents of this contract are correct.
    message_root_proxy_addr: Address,
}

#[derive(Debug, Deserialize)]
pub struct StateTransition {
    pub admin_facet_addr: Address,
    pub default_upgrade_addr: Address,
    pub diamond_init_addr: Address,
    pub executor_facet_addr: Address,
    pub genesis_upgrade_addr: Address,
    pub getters_facet_addr: Address,
    pub mailbox_facet_addr: Address,
    pub state_transition_implementation_addr: Address,
    pub verifier_addr: Address,
}

impl DeployedAddresses {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        address_verifier.add_address(self.native_token_vault_addr, "native_token_vault");
        address_verifier.add_address(self.validator_timelock_addr, "validator_timelock");
        address_verifier.add_address(self.bridges.shared_bridge_proxy_addr, "shared_bridge_proxy");
        address_verifier.add_address(
            self.bridgehub.ctm_deployment_tracker_proxy_addr,
            "ctm_deployment_tracker",
        );
        address_verifier.add_address(
            self.bridgehub.bridgehub_implementation_addr,
            "bridgehub_implementation_addr",
        );

        address_verifier.add_address(
            self.l2_wrapped_base_token_store_addr,
            "l2_wrapped_base_token_store",
        );

        address_verifier.add_address(
            self.bridges.l1_nullifier_implementation_addr,
            "l1_nullifier_implementation_addr",
        );
        address_verifier.add_address(
            self.bridges.erc20_bridge_implementation_addr,
            "erc20_bridge_implementation_addr",
        );
        self.state_transition.add_to_verifier(address_verifier);
    }
}

impl StateTransition {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        address_verifier.add_address(self.admin_facet_addr, "admin_facet");
        address_verifier.add_address(self.default_upgrade_addr, "default_upgrade");
        address_verifier.add_address(self.diamond_init_addr, "diamond_init");
        address_verifier.add_address(self.executor_facet_addr, "executor_facet");
        address_verifier.add_address(self.genesis_upgrade_addr, "genesis_upgrade_addr");
        address_verifier.add_address(self.getters_facet_addr, "getters_facet");
        address_verifier.add_address(self.mailbox_facet_addr, "mailbox_facet");
        address_verifier.add_address(
            self.state_transition_implementation_addr,
            "state_transition_implementation_addr",
        );
        address_verifier.add_address(self.verifier_addr, "verifier");
    }
}

impl DeployedAddresses {
    async fn verify_ntv(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        let l1_ntv_impl_constructor = L1NativeTokenVault::constructorCall::new((bridgehub_info.l1_weth_token_address, config.deployed_addresses.bridges.shared_bridge_proxy_addr, bridgehub_info.shared_bridge)).abi_encode();
        let l1_ntv_init_calldata = L1NativeTokenVault::initializeCall::new((bridgehub_info.owner, self.bridges.bridged_token_beacon)).abi_encode();

        result
            .expect_create2_params_proxy_with_bytecode(
                verifiers,
                &self.native_token_vault_addr,
                l1_ntv_init_calldata,
                bridgehub_info.transparent_proxy_admin,
                l1_ntv_impl_constructor,
                "l1-contracts/L1NativeTokenVault",
            )
            .await;
    }

    async fn verify_validator_timelock(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        let deployer_addr = Address::from_str(&config.deployer_addr).unwrap();
        // FIXME: 0 is correct only on stage/testnet, but not on mainnet.
        const EXECUTION_DELAY:u32 =0;
        result.expect_create2_params(verifiers, &self.validator_timelock_addr, ValidatorTimelock::constructorCall::new((deployer_addr, EXECUTION_DELAY, U256::from(config.era_chain_id))).abi_encode(), "l1-contracts/ValidatorTimelock");

        // Now, we know that the deployment params were correct, but we also need to be sure that the ownership has been transferred successfully.

        let validator_timelock = ValidatorTimelock::new(
            self.validator_timelock_addr,
            // todo: better error handling
            verifiers.network_verifier.get_l1_provider().unwrap()
        );

        let current_owner = validator_timelock.owner().call().await.unwrap().owner;

        // todo: replace asserts with error reporting.

        assert!(current_owner == self.l1_transitionary_owner);
        
        let current_execution_delay = validator_timelock.executionDelay().call().await.unwrap().executionDelay;
        assert!(current_execution_delay == EXECUTION_DELAY);
        
        let chain_type_manager = validator_timelock.chainTypeManager().call().await.unwrap().chainTypeManager;
        assert!(chain_type_manager == bridgehub_info.stm_address.unwrap());
    }

    async fn verify_wrapped_base_token_store(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        // FIXME: ensure to verify the contents of it, i.e. 
        // ensure that for each chain a wrapped base token is stored.
        // A lack of a token is just a warning. This should probably be done
        // in a separate section together with ensuring the presence of the l2 shared bridge

        let deployer_addr = Address::from_str(&config.deployer_addr).unwrap();

        // FIXME: the hack below works on stage only, it should be removed before submitting the PR.
        let deployer_addr = Address::from_str("a6ed12b87d2e6ea039d27e1ffbdc24915ffd3042").unwrap();

        result.expect_create2_params(verifiers, &self.l2_wrapped_base_token_store_addr, L2WrappedBaseTokenStore::constructorCall::new((bridgehub_info.owner, deployer_addr)).abi_encode(), "l1-contracts/L2WrappedBaseTokenStore");

        let l2_wrapped_base_token_store = L2WrappedBaseTokenStore::new(
            self.l2_wrapped_base_token_store_addr,
            // todo: better error handling
            verifiers.network_verifier.get_l1_provider().unwrap()
        );

        let current_admin = l2_wrapped_base_token_store.admin().call().await.unwrap().admin;

        assert!(current_admin == bridgehub_info.ecosystem_admin);
    }

    async fn verify_ctm_deployment_track(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        let ctm_deployer_impl_constructor = CTMDeploymentTracker::constructorCall::new((bridgehub_info.bridgehub_addr, config.deployed_addresses.bridges.shared_bridge_proxy_addr)).abi_encode();

        let deployer_addr = Address::from_str(&config.deployer_addr).unwrap();
        let ctm_deployer_init_calldata = CTMDeploymentTracker::initializeCall::new((deployer_addr,)).abi_encode();


        result
            .expect_create2_params_proxy_with_bytecode(
                verifiers,
                // FIXME: maybe this thing belongs to the bridgehub struct?
                &self.bridgehub.ctm_deployment_tracker_proxy_addr,
                ctm_deployer_init_calldata,
                bridgehub_info.transparent_proxy_admin,
                ctm_deployer_impl_constructor,
                "l1-contracts/CTMDeploymentTracker",
            )
            .await;

        let ctm_dt=  CTMDeploymentTracker::new(
            self.bridgehub.ctm_deployment_tracker_proxy_addr,
            verifiers.network_verifier.get_l1_provider().unwrap()
        );
        let owner =ctm_dt.owner().call().await.unwrap().owner;

        assert!(owner == self.l1_transitionary_owner);
    }

    async fn verify_l1_asset_router(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        // fixme: error handling
        let era_diamond_proxy = verifiers.network_verifier.get_chain_diamond_proxy(bridgehub_info.stm_address.unwrap(), config.era_chain_id).await.unwrap();
        let l1_asset_router_impl_constructor = L1AssetRouter::constructorCall::new((bridgehub_info.l1_weth_token_address,bridgehub_info.bridgehub_addr, bridgehub_info.shared_bridge, U256::from(config.era_chain_id), era_diamond_proxy)).abi_encode();
        let deployer_addr = Address::from_str(&config.deployer_addr).unwrap();
        let l1_asset_router_init_calldata = L1AssetRouter::initializeCall::new((deployer_addr,)).abi_encode();

        result
            .expect_create2_params_proxy_with_bytecode(
                verifiers,
                &self.bridges.shared_bridge_proxy_addr,
                l1_asset_router_init_calldata,
                bridgehub_info.transparent_proxy_admin,
                l1_asset_router_impl_constructor,
                "l1-contracts/L1AssetRouter",
            )
            .await;

        let l1_asset_router = L1AssetRouter::new(
            self.bridges.shared_bridge_proxy_addr,
            verifiers.network_verifier.get_l1_provider().unwrap()
        );

        let current_owner = l1_asset_router.owner().call().await.unwrap().owner;
        assert!(current_owner == self.l1_transitionary_owner);

        let legacy_bridge = l1_asset_router.legacyBridge().call().await.unwrap().legacyBridge;
        assert!(legacy_bridge == bridgehub_info.legacy_bridge);

        let l1_ntv = l1_asset_router.nativeTokenVault().call().await.unwrap().nativeTokenVault;
        assert!(l1_ntv == self.native_token_vault_addr);
    }

    async fn verify_l1_nullifier(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        let era_diamond_proxy = verifiers.network_verifier.get_chain_diamond_proxy(bridgehub_info.stm_address.unwrap(), config.era_chain_id).await.unwrap();
        let l1nullifier_constructor_data = L1Nullifier::constructorCall::new(
            (bridgehub_info.bridgehub_addr, U256::from(config.era_chain_id), era_diamond_proxy)
        ).abi_encode();

        result.expect_create2_params(verifiers, &self.bridges.l1_nullifier_implementation_addr, l1nullifier_constructor_data, "l1-contracts/L1Nullifier");
    }

    async fn verify_l1_erc20_bridge(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        result.expect_create2_params(
            verifiers, 
            &self.bridges.erc20_bridge_implementation_addr, 
            L1ERC20Bridge::constructorCall::new((bridgehub_info.shared_bridge, self.bridges.shared_bridge_proxy_addr, self.native_token_vault_addr, U256::from(config.era_chain_id))).abi_encode(), 
            "l1-contracts/L1ERC20Bridge"
        );
    }

    async fn verify_bridgehub_impl(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        // FIXME: this should be pulled from config somewhere, though the number is
        // correct for all envs.
        const MAX_NUMBER_OF_CHAINS: usize = 100;
        result.expect_create2_params(
            verifiers, 
            &self.bridgehub.bridgehub_implementation_addr, 
            BridgehubImpl::constructorCall::new((U256::from(config.l1_chain_id), bridgehub_info.owner, U256::from(MAX_NUMBER_OF_CHAINS))).abi_encode(), 
            "l1-contracts/Bridgehub"
        );
    }

    async fn verify_chain_type_manager(
        &self,
        _config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) {
        result.expect_create2_params(
            verifiers, 
            &self.state_transition.state_transition_implementation_addr, 
            ChainTypeManager::constructorCall::new((bridgehub_info.bridgehub_addr,)).abi_encode(), 
            "l1-contracts/ChainTypeManager"
        );
    }

    async fn verify_admin_facet(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        _bridgehub_info: &BridgehubInfo
    ) {
        result.expect_create2_params(
            verifiers, 
            &self.state_transition.admin_facet_addr, 
            AdminFacet::constructorCall::new((U256::from(config.l1_chain_id), self.l1_rollup_da_manager)).abi_encode(), 
            "l1-contracts/AdminFacet"
        );
    }

    async fn verify_executor_facet(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        _bridgehub_info: &BridgehubInfo
    ) {
        result.expect_create2_params(
            verifiers, 
            &self.state_transition.executor_facet_addr, 
            ExecutorFacet::constructorCall::new((U256::from(config.l1_chain_id),)).abi_encode(), 
            "l1-contracts/ExecutorFacet"
        );
    }

    async fn verify_getters_facet(
        &self,
        _config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        _bridgehub_info: &BridgehubInfo
    ) {
        result.expect_create2_params(
            verifiers, 
            &self.state_transition.getters_facet_addr, 
            vec![], 
            "l1-contracts/GettersFacet"
        );
    }

    async fn verify_mailbox_facet(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
        _bridgehub_info: &BridgehubInfo
    ) {
        result.expect_create2_params(
            verifiers, 
            &self.state_transition.mailbox_facet_addr, 
            MailboxFacet::constructorCall::new((U256::from(config.era_chain_id), U256::from(config.l1_chain_id))).abi_encode(), 
            "l1-contracts/MailboxFacet"
        );
    }

    pub async fn verify(
        &self,
        config: &Config,
        verifiers: &crate::traits::Verifiers,
        result: &mut crate::traits::VerificationResult,
    ) -> anyhow::Result<()> {
        // fixme: remove unwrap
        let bridgehub_addr = config.other_config.as_ref().unwrap().bridgehub_proxy;

        let Some(bridgehub_info) = verifiers.network_verifier.get_bridgehub_info(bridgehub_addr).await else {
            anyhow::bail!("Can not verify deployed addresses without bridgehub");
        };

        self.verify_ntv(config, verifiers, result, &bridgehub_info).await;
        self.verify_validator_timelock(config, verifiers, result, &bridgehub_info).await;
        self.verify_wrapped_base_token_store(config, verifiers, result, &bridgehub_info).await;
        self.verify_ctm_deployment_track(config, verifiers, result, &bridgehub_info).await;

        self.verify_l1_asset_router(config, verifiers, result, &bridgehub_info).await;
        self.verify_l1_nullifier(config, verifiers, result, &bridgehub_info).await;
        self.verify_l1_erc20_bridge(config, verifiers, result, &bridgehub_info).await;
        self.verify_bridgehub_impl(config, verifiers, result, &bridgehub_info).await;
        


        self.verify_chain_type_manager(config, verifiers, result, &bridgehub_info).await;


        self.verify_admin_facet(config, verifiers, result, &bridgehub_info).await;
        self.verify_executor_facet(config, verifiers, result, &bridgehub_info).await;
        self.verify_getters_facet(config, verifiers, result, &bridgehub_info).await;
        self.verify_mailbox_facet(config, verifiers, result, &bridgehub_info).await;

          
        result
            .expect_create2_params(
                verifiers,
                &self.state_transition.verifier_addr,
                vec![],
                if verifiers.testnet_contracts {
                    "l1-contracts/TestnetVerifier"
                } else {
                    "l1-contracts/Verifier"
                },
            );
        result
            .expect_create2_params(
                verifiers,
                &self.state_transition.genesis_upgrade_addr,
                vec![],
                    "l1-contracts/L1GenesisUpgrade"
            );
        result
            .expect_create2_params(
                verifiers,
                &self.state_transition.default_upgrade_addr,
                vec![],
                    "l1-contracts/DefaultUpgrade"
            );
        result
            .expect_create2_params(
                verifiers,
                &self.state_transition.diamond_init_addr,
                vec![],
                    "l1-contracts/DiamondInit"
            );

        result.report_ok("deployed addresses");
        Ok(())
    }
}
