use alloy::consensus::Transaction;
use alloy::hex::FromHex;
use alloy::primitives::map::{HashMap, HashSet};
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::transports::http::Http;
use alloy::{contract, sol};
use alloy::sol_types::SolCall;
use chrono::format::Fixed;
use reqwest::Client;

use super::bytecode_verifier::BytecodeVerifier;
use super::{compute_create2_address_evm, compute_hash_with_arguments};

sol! {
    #[sol(rpc)]
    contract Bridgehub {
        address public sharedBridge;
        address public admin;
        mapping(uint256 _chainId => address) public stateTransitionManager;
        function owner() external view returns (address) {

        }
    }

    #[sol(rpc)]
    contract L1SharedBridge {
        function legacyBridge() public returns (address);
        function L1_WETH_TOKEN() public returns (address);
    }
    
    #[sol(rpc)]
    contract ChainTypeManager {
        function getHyperchain(uint256 _chainId) public view returns (address);
    }

    function create2AndTransferParams(bytes memory bytecode, bytes32 salt, address owner) {

    }
}

const EIP1967_PROXY_ADMIN_SLOT: &str = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

#[derive(Debug)]
pub struct BridgehubInfo {
    pub shared_bridge: Address,
    pub legacy_bridge: Address,
    pub stm_address: Option<Address>,
    pub owner: Address,
    pub transparent_proxy_admin: Address,
    pub l1_weth_token_address: Address,
    pub ecosystem_admin: Address,
    pub bridgehub_addr: Address
}

#[derive(Default)]
pub struct NetworkVerifier {
    pub l1_rpc: Option<String>,
    pub l2_rpc: Option<String>,
    pub l2_chain_id: Option<u64>,

    // todo: maybe merge into one struct.
    pub create2_known_bytecodes: HashMap<Address, String>,
    pub create2_constructor_params: HashMap<Address, Vec<u8>>,
}

impl NetworkVerifier {
    pub fn add_l1_network_rpc(&mut self, network_rpc: String) {
        self.l1_rpc = Some(network_rpc);
    }
    pub fn add_l2_network_rpc(&mut self, network_rpc: String) {
        self.l2_rpc = Some(network_rpc);
    }

    pub fn add_l2_chain_id(&mut self, l2_chain_id: u64) {
        self.l2_chain_id = Some(l2_chain_id)
    }

    pub async fn get_l2_chain_id(&self) -> Option<u64> {
        if let Some(network) = self.l2_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());
            let chain_id = provider.get_chain_id().await.unwrap();
            Some(chain_id)
        } else {
            self.l2_chain_id
        }
    }

    pub async fn get_l1_chain_id(&self) -> Option<u64> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());
            let chain_id = provider.get_chain_id().await.unwrap();
            Some(chain_id)
        } else {
            None
        }
    }

    pub async fn get_bytecode_hash_at(&self, address: &Address) -> Option<FixedBytes<32>> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());
            let code = provider.get_code_at(address.clone()).await.unwrap();
            if code.len() == 0 {
                // if connected and address has no bytecode - should return 0s.
                Some(FixedBytes::ZERO)
            } else {
                Some(keccak256(&code))
            }
        } else {
            // should return None if not connected.
            None
        }
    }

    pub async fn get_chain_diamond_proxy(&self, stm_addr: Address, era_chain_id: u64) -> Option<Address> {
        let provider = self.get_l1_provider()?;

        let ctm = ChainTypeManager::new(
            stm_addr,
            provider
        );
        let address = ctm.getHyperchain(U256::from(era_chain_id)).call().await.unwrap()._0;

        Some(address)
    }   

    pub async fn storage_at(
        &self,
        address: &Address,
        key: &FixedBytes<32>,
    ) -> Option<FixedBytes<32>> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());

            let storage = provider
                .get_storage_at(address.clone(), U256::from_be_bytes(key.0))
                .await
                .unwrap();

            Some(FixedBytes::from_slice(&storage.to_be_bytes_vec()))
        } else {
            None
        }
    }

    pub async fn get_storage_at(&self, address: &Address, key: u8) -> Option<FixedBytes<32>> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());

            let storage = provider
                .get_storage_at(address.clone(), U256::from(key))
                .await
                .unwrap();

            Some(FixedBytes::from_slice(&storage.to_be_bytes_vec()))
        } else {
            None
        }
    }

    fn compute_hash_with_arguments(
        &self,
        input: &Bytes,
        num_arguments: usize,
    ) -> Option<FixedBytes<32>> {
        if input.len() < (num_arguments + 2) * 32 {
            None
        } else {
            let after_32_bytes = &input[32..input.len() - 32 * num_arguments];
            Some(keccak256(after_32_bytes))
        }
    }
    pub fn get_l1_provider(&self) -> Option<RootProvider<Http<Client>>> {
        let network = self.l1_rpc.as_ref()?;

        Some(ProviderBuilder::new().on_http(network.parse().unwrap()))
    } 

    pub async fn get_bridgehub_info(&self, bridgehub_addr: Address) -> Option<BridgehubInfo> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());

            let bridgehub = Bridgehub::new(bridgehub_addr, provider.clone());

            let shared_bridge_address = bridgehub.sharedBridge().call().await.unwrap().sharedBridge;

            let shared_bridge = L1SharedBridge::new(shared_bridge_address, provider.clone());

            let l2_chain_id = self.get_l2_chain_id().await;

            let stm_address = if let Some(l2_chain_id) = l2_chain_id {
                Some(
                    bridgehub
                        .stateTransitionManager(l2_chain_id.try_into().unwrap())
                        .call()
                        .await
                        .unwrap()
                        ._0,
                )
            } else {
                None
            };

            let owner = bridgehub.owner().call().await.unwrap()._0;
            let ecosystem_admin = bridgehub.admin().call().await.unwrap().admin;

            let transparent_proxy_admin = self.storage_at(&bridgehub_addr, &FixedBytes::<32>::from_hex(EIP1967_PROXY_ADMIN_SLOT).unwrap()).await?;

            let legacy_bridge = shared_bridge.legacyBridge().call().await.unwrap()._0;
            let l1_weth_token_address = shared_bridge.L1_WETH_TOKEN().call().await.unwrap()._0;

            Some(BridgehubInfo {
                shared_bridge: shared_bridge_address,
                legacy_bridge,
                stm_address,
                owner,
                transparent_proxy_admin: Address::from_slice(&transparent_proxy_admin[12..]),
                l1_weth_token_address,
                ecosystem_admin,
                bridgehub_addr
            })
        } else {
            None
        }
    }

    /// Fetches the `transaction` and tries to parse it as a CREATE2 deployment 
    /// transaction.
    /// If successful, it returns a tuple of three items: the address of the deployed contract,
    /// the path to the contract and its constructor params.
    pub async fn check_create2_deploy(
        &self,
        transaction: &str,
        expected_create2_address: &Address,
        expected_create2_salt: &FixedBytes<32>,
        bytecode_verifier: &BytecodeVerifier
    ) -> Option<(Address, String, Vec<u8>)> {
        if let Some(network) = self.l1_rpc.as_ref() {
            let tx_hash: TxHash = transaction.parse().unwrap();
            let provider = ProviderBuilder::new().on_http(network.parse().unwrap());

            let tx = provider
                .get_transaction_by_hash(tx_hash)
                .await
                .unwrap()
                .unwrap();

            if tx.to() != Some(expected_create2_address.clone()) {
                return None;
            }

            // There are two types of CREATE2 deployments that were used:
            // - Usual, using CREATE2Factory directly.
            // - By using the `Create2AndTransfer` contract.
            // We will try both here.

            let salt = &tx.input()[0..32];
            if salt != expected_create2_salt.as_slice() {
                println!("Salt mismatch: {:?} != {:?}", salt, expected_create2_salt);
                return None;
            }

            
            if let Some((name, params)) = bytecode_verifier.try_parse_bytecode(&tx.input()[32..]) {
                let addr= compute_create2_address_evm(tx.to().unwrap(), FixedBytes::<32>::from_slice(salt), keccak256(&tx.input()[32..]));
                return Some((addr, name, params));
            };

            let bytecode_input = &tx.input()[32..];

            // Okay, this may be the `Create2AndTransfer` method.
            if let Some(create2_and_transfer_input) = bytecode_verifier.is_create2_and_transfer_bytecode_prefix(bytecode_input) {
                let x = create2AndTransferParamsCall::abi_decode_raw(create2_and_transfer_input, false).unwrap();
                if salt != x.salt.as_slice() {
                    println!("Salt mismatch: {:?} != {:?}", salt, x.salt);
                    return None;
                }
                // We do not need to cross check `owner` here, it will be cross checked against whatever owner is currently set 
                // to the final contracts.
                // We do still need to check the input to find out potential constructor param
                let (name, params) = bytecode_verifier.try_parse_bytecode(&x.bytecode)?;
                let salt = FixedBytes::<32>::from_slice(salt);
                let create2_and_transfer_addr = compute_create2_address_evm(tx.to().unwrap(), salt, keccak256(&tx.input()[32..]));
                
                let contract_addr = compute_create2_address_evm(create2_and_transfer_addr, salt, keccak256(&x.bytecode));

                return Some((contract_addr, name, params));
            }   

            None
        } else {
            None
        }
    }
}
