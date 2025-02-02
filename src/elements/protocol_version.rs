use std::fmt::Display;

use alloy::primitives::U256;

pub struct ProtocolVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl From<U256> for ProtocolVersion {
    fn from(value: U256) -> Self {
        let rem: U256 = (1u64 << 32).try_into().unwrap();
        Self {
            major: (value.checked_shr(64.try_into().unwrap()).unwrap())
                .wrapping_rem(rem)
                .try_into()
                .unwrap(),
            minor: (value.overflowing_shr(32.try_into().unwrap()).0)
                .wrapping_rem(rem)
                .try_into()
                .unwrap(),
            patch: value.wrapping_rem(rem).try_into().unwrap(),
        }
    }
}

impl Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}
