use std::time::Duration as StdDuration;

pub(crate) trait TimeDurationExt {
    /// Converts to a `std::time::Duration`, returning `Duration::ZERO` if this duration is negative.
    fn to_std_duration(self) -> StdDuration;
}

impl TimeDurationExt for time::Duration {
    fn to_std_duration(self) -> StdDuration {
        match self.is_negative() {
            true => StdDuration::ZERO,
            false => match self.whole_nanoseconds().try_into() {
                Ok(nanos) => StdDuration::from_nanos(nanos),
                Err(_err) => {
                    unreachable!("We already handled the negative case. Conversion of i128 to u64 must succeed now.");
                }
            },
        }
    }
}
