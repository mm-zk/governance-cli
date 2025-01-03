use std::fmt::Display;

use alloy::primitives::U256;
use chrono::DateTime;

pub struct UpgradeDeadline {
    pub deadline: U256,
}

impl UpgradeDeadline {
    // Whether the deadline is within (now + day_from, now + day_to)
    pub fn deadline_within_day_range(&self, day_from: i64, day_to: i64) -> bool {
        let seconds_since_epoch: Result<i64, _> = self.deadline.try_into();

        match seconds_since_epoch {
            Ok(seconds) => {
                let now = chrono::Utc::now().timestamp();
                let day_from_seconds = day_from * 24 * 60 * 60;
                let day_to_seconds = day_to * 24 * 60 * 60;
                let day_from = now + day_from_seconds;
                let day_to = now + day_to_seconds;
                seconds >= day_from && seconds <= day_to
            }
            Err(_) => false,
        }
    }
}

impl From<U256> for UpgradeDeadline {
    fn from(value: U256) -> Self {
        Self { deadline: value }
    }
}

impl Display for UpgradeDeadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.deadline == U256::MAX {
            write!(f, "INFINITY")
        } else {
            let seconds_since_epoch = self.deadline.try_into();

            match seconds_since_epoch {
                Ok(seconds) => {
                    let datetime = DateTime::from_timestamp(seconds, 0).unwrap();
                    write!(f, "UTC Time: {}", datetime.format("%Y-%m-%d %H:%M:%S"))
                }
                Err(_) => write!(f, "Huge, but not infinity.. strange"),
            }
        }
    }
}
