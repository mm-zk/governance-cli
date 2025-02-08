use alloy::{hex, primitives::Keccak256};

#[derive(Default)]
pub struct SelectorVerifier {}

impl SelectorVerifier {
    pub fn compute_selector(&self, method_name: &str) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(method_name.as_bytes());
        let result = hasher.finalize();

        hex::encode(&result[..4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_selector() {
        let verifier = SelectorVerifier::default();
        assert_eq!(verifier.compute_selector("acceptOwnership()"), "79ba5097");
    }
}
