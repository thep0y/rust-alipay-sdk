use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::AlipayResult;

pub fn now() -> AlipayResult<Duration> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?)
}

pub fn to_time_string(duration: Duration) -> String {
    let utc_offset = 8 * 3600; // UTC+8时区的偏移量，以秒为单位

    let adjusted_timestamp = duration.as_secs() + utc_offset;

    let seconds_in_minute = 60;
    let seconds_in_hour = seconds_in_minute * 60;
    let seconds_in_day = seconds_in_hour * 24;

    let days = adjusted_timestamp / seconds_in_day;
    let hours = (adjusted_timestamp % seconds_in_day) / seconds_in_hour;
    let minutes = (adjusted_timestamp % seconds_in_hour) / seconds_in_minute;
    let seconds = adjusted_timestamp % seconds_in_minute;

    // 计算年月
    let (mut year, mut month) = (1970, 1);
    let mut days_remaining = days;
    while days_remaining >= days_in_month(year, month) {
        days_remaining -= days_in_month(year, month);
        month += 1;
        if month > 12 {
            month = 1;
            year += 1;
        }
    }

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year,
        month,
        days_remaining + 1,
        hours,
        minutes,
        seconds
    )
}

fn days_in_month(year: u32, month: u32) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => panic!("Invalid month"),
    }
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use crate::time::to_time_string;

    #[test]
    fn time_string() {
        let duration = Duration::new(1693580767542 / 1000, 0);
        let time_str = to_time_string(duration);

        assert_eq!(time_str, "2023-09-01 23:06:07");
    }
}
