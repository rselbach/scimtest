pub(crate) fn parse(mut value: &str) -> Option<i64> {
    let negative = value.starts_with('-');
    if value.starts_with(['-', '+']) {
        value = &value[1..];
    }
    if value == "0" {
        return Some(0);
    }
    if value.is_empty() {
        return None;
    }
    let limit = 1u64 << 63;
    let mut total = 0u64;
    while !value.is_empty() {
        let digits = value.bytes().take_while(u8::is_ascii_digit).count();
        let mut amount = 0u64;
        for digit in value[..digits].bytes() {
            amount = amount
                .checked_mul(10)?
                .checked_add(u64::from(digit - b'0'))?;
            if amount > limit {
                return None;
            }
        }
        value = &value[digits..];
        let mut fraction = 0u64;
        let mut scale = 1f64;
        let mut decimals = 0;
        if let Some(rest) = value.strip_prefix('.') {
            decimals = rest.bytes().take_while(u8::is_ascii_digit).count();
            let mut overflow = false;
            for digit in rest[..decimals].bytes() {
                if overflow {
                    continue;
                }
                if fraction > (limit - 1) / 10 {
                    overflow = true;
                    continue;
                }
                let next = fraction * 10 + u64::from(digit - b'0');
                if next > limit {
                    overflow = true;
                    continue;
                }
                fraction = next;
                scale *= 10.;
            }
            value = &rest[decimals..];
        }
        if digits == 0 && decimals == 0 {
            return None;
        }
        let length = value
            .bytes()
            .take_while(|byte| !byte.is_ascii_digit() && *byte != b'.')
            .count();
        let unit = match &value[..length] {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return None,
        };
        value = &value[length..];
        amount = amount
            .checked_mul(unit)?
            .checked_add((fraction as f64 * (unit as f64 / scale)) as u64)?;
        total = total.checked_add(amount)?;
        if total > limit {
            return None;
        }
    }
    if negative {
        return i64::try_from(-(i128::from(total))).ok();
    }
    i64::try_from(total).ok()
}

pub(crate) fn format(nanos: i64) -> String {
    if nanos == 0 {
        return "0s".into();
    }
    let mut value = nanos.unsigned_abs();
    let sign = if nanos < 0 { "-" } else { "" };
    if value < 1_000_000_000 {
        let (scale, unit) = match value {
            1..1_000 => (1, "ns"),
            1_000..1_000_000 => (1_000, "µs"),
            _ => (1_000_000, "ms"),
        };
        return format!("{sign}{}{unit}", decimal(value, scale));
    }
    let hours = value / 3_600_000_000_000;
    value %= 3_600_000_000_000;
    let minutes = value / 60_000_000_000;
    value %= 60_000_000_000;
    let seconds = decimal(value, 1_000_000_000);
    if hours > 0 {
        return format!("{sign}{hours}h{minutes}m{seconds}s");
    }
    if minutes > 0 {
        return format!("{sign}{minutes}m{seconds}s");
    }
    format!("{sign}{seconds}s")
}

fn decimal(value: u64, scale: u64) -> String {
    let whole = value / scale;
    let remainder = value % scale;
    if remainder == 0 {
        return whole.to_string();
    }
    let width = scale.ilog10() as usize;
    let fraction = format!("{remainder:0width$}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}
