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
}
