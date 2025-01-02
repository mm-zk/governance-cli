use alloy::{hex, primitives::Keccak256};

#[derive(Default)]
pub struct SelectorVerifier {}

impl SelectorVerifier {
    pub fn to_method_name(&self, selector: String) -> Option<String> {
        if selector == "79ba5097" {
            return Some("acceptOwnership()".to_string());
        }

        if selector == "a39f7449" {
            return Some("startTimer()".to_string());
        }

        None
    }

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
    fn test_to_method_name() {
        let verifier = SelectorVerifier::default();
        assert_eq!(
            verifier.to_method_name("79ba5097".to_string()),
            Some("acceptOwnership()".to_string())
        );
        assert_eq!(
            verifier.to_method_name("a39f7449".to_string()),
            Some("startTimer()".to_string())
        );
        assert_eq!(verifier.to_method_name("unknown".to_string()), None);
    }

    #[test]
    fn test_compute_selector() {
        let verifier = SelectorVerifier::default();
        assert_eq!(verifier.compute_selector("acceptOwnership()"), "79ba5097");
    }
}
