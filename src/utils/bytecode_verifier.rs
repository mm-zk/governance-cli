use alloy::primitives::{map::HashMap, FixedBytes};

#[derive(Default)]
pub struct BytecodeVerifier {
    pub bytecode_hash_to_file: HashMap<FixedBytes<32>, String>,
}

impl BytecodeVerifier {
    pub fn bytecode_hash_to_file(&self, bytecode_hash: &FixedBytes<32>) -> Option<&String> {
        self.bytecode_hash_to_file.get(bytecode_hash)
    }

    pub fn add_bytecode_hash(&mut self, bytecode_hash: FixedBytes<32>, file: String) {
        self.bytecode_hash_to_file.insert(bytecode_hash, file);
    }
}
