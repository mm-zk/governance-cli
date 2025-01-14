use alloy::consensus::Transaction;
use alloy::primitives::map::{HashMap, HashSet};
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use alloy::sol_types::SolCall;

use super::bytecode_verifier::BytecodeVerifier;
use super::{compute_create2_address_evm, compute_hash_with_arguments};

sol! {
    #[sol(rpc)]
    contract Bridgehub {
        address public sharedBridge;
        mapping(uint256 _chainId => address) public stateTransitionManager;
    }

    #[sol(rpc)]
    contract L1SharedBridge {
        function legacyBridge() public returns (address);
    }

    function create2AndTransferParams(bytes memory bytecode, bytes32 salt, address owner) {

    }
}

#[derive(Debug)]
pub struct BridgehubInfo {
    pub shared_bridge: Address,
    pub legacy_bridge: Address,
    pub stm_address: Option<Address>,
}

#[derive(Default)]
pub struct NetworkVerifier {
    pub l1_rpc: Option<String>,
    pub l2_rpc: Option<String>,
    pub l2_chain_id: Option<u64>,
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

            Some(BridgehubInfo {
                shared_bridge: shared_bridge_address,
                legacy_bridge: shared_bridge.legacyBridge().call().await.unwrap()._0,
                stm_address,
            })
        } else {
            None
        }
    }

    /// Fetches the `transaction` and tries to parse it as a CREATE2 deployment 
    /// transaction.
    /// If successful, it returns a tuple of two items: the path to the contract and
    /// its constructor params.
    pub async fn check_create2_deploy(
        &self,
        transaction: &str,
        expected_create2_address: &Address,
        expected_create2_salt: &FixedBytes<32>,
        bytecode_verifier: &BytecodeVerifier
    ) -> Option<(String, Vec<u8>)> {
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

            if let Some(x) = bytecode_verifier.try_parse_bytecode(&tx.input()[32..]) {
                return Some(x);
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
                return bytecode_verifier.try_parse_bytecode(&x.bytecode);
            }   

            None
        } else {
            None
        }
    }
}
