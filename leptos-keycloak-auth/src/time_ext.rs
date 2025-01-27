use std::time::Duration as StdDuration;

pub(crate) trait TimeDurationExt {
    /// Assertion: Duration is NOT negative.
    fn to_std_duration(self) -> StdDuration;
}

impl TimeDurationExt for time::Duration {
    fn to_std_duration(self) -> StdDuration {
        match self.is_negative() {
            true => StdDuration::ZERO,
            false => StdDuration::from_nanos(self.whole_nanoseconds().try_into().expect("::time::Duration nanoseconds to not overflow a u64. Should not happen in hundreds of years.")),
        }
    }
}
