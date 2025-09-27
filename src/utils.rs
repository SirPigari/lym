use std::cmp::Ordering;

fn version_to_tuple(v: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].parse().ok()?;
    Some((major, minor, patch))
}

pub fn parse_bytes(input: &str) -> Option<u128> {
    let input = input.trim().to_lowercase();

    let (num_str, unit_str) = input
        .trim()
        .chars()
        .partition::<String, _>(|c| c.is_ascii_digit() || *c == '.');

    let number: f64 = num_str.parse().ok()?;

    let multiplier: u128 = match unit_str.trim() {
        "" | "b"       => 1,
        "kb"           => 1000,
        "mb"           => 1000u128.pow(2),
        "gb"           => 1000u128.pow(3),
        "tb"           => 1000u128.pow(4),
        "pb" | "pt"    => 1000u128.pow(5),
        "eb"           => 1000u128.pow(6),

        "kib"          => 1024,
        "mib"          => 1024u128.pow(2),
        "gib"          => 1024u128.pow(3),
        "tib"          => 1024u128.pow(4),
        "pib"          => 1024u128.pow(5),
        "eib"          => 1024u128.pow(6),

        _ => return None,
    };

    Some((number * multiplier as f64) as u128)
}

pub fn json_type(val: &serde_json::Value) -> &'static str {
    match val {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

pub fn cmp_version(a: &str, b: &str) -> Option<Ordering> {
    let a_v = version_to_tuple(a)?;
    let b_v = version_to_tuple(b)?;

    Some(
        if a_v.0 != b_v.0 {
            a_v.0.cmp(&b_v.0)
        } else if a_v.1 != b_v.1 {
            a_v.1.cmp(&b_v.1)
        } else {
            a_v.2.cmp(&b_v.2)
        }
    )
}

pub fn cmp_version_tuples(a: (u64, u64, u64), b: (u64, u64, u64)) -> Ordering {
    if a.0 != b.0 {
        a.0.cmp(&b.0)
    } else if a.1 != b.1 {
        a.1.cmp(&b.1)
    } else {
        a.2.cmp(&b.2)
    }
}

pub fn check_version(current: &str, required: &str) -> bool {
    if required.is_empty() {
        return true;
    }

    if required == "*" {
        return true;
    }

    let cur = match version_to_tuple(current) {
        Some(v) => v,
        None => return false,
    };

    let ge = |a, b| cmp_version_tuples(a, b) != std::cmp::Ordering::Less;
    let gt = |a, b| cmp_version_tuples(a, b) == std::cmp::Ordering::Greater;
    let le = |a, b| cmp_version_tuples(a, b) != std::cmp::Ordering::Greater;
    let lt = |a, b| cmp_version_tuples(a, b) == std::cmp::Ordering::Less;
    let eq = |a, b| cmp_version_tuples(a, b) == std::cmp::Ordering::Equal;

    if required.starts_with('^') {
        let req_str = &required[1..];
        let req = match version_to_tuple(req_str) {
            Some(v) => v,
            None => return false,
        };
        let upper = (req.0 + 1, 0, 0);
        return ge(cur, req) && lt(cur, upper);
    } else if required.starts_with(">=") {
        let req_str = &required[2..];
        let req = match version_to_tuple(req_str) {
            Some(v) => v,
            None => return false,
        };
        return ge(cur, req);
    } else if required.starts_with("<=") {
        let req_str = &required[2..];
        let req = match version_to_tuple(req_str) {
            Some(v) => v,
            None => return false,
        };
        return le(cur, req);
    } else if required.starts_with('<') {
        let req_str = &required[1..];
        let req = match version_to_tuple(req_str) {
            Some(v) => v,
            None => return false,
        };
        return lt(cur, req);
    } else if required.starts_with('>') {
        let req_str = &required[1..];
        let req = match version_to_tuple(req_str) {
            Some(v) => v,
            None => return false,
        };
        return gt(cur, req);
    } else if required.starts_with('~') {
        let req_str = &required[1..];
        let req = match version_to_tuple(req_str) {
            Some(v) => v,
            None => return false,
        };
        let upper = (req.0, req.1 + 1, 0);
        return ge(cur, req) && lt(cur, upper);
    } else {
        let req = match version_to_tuple(required) {
            Some(v) => v,
            None => return false,
        };
        return eq(cur, req);
    }
}

pub fn is_next_version(new: &str, last: &str) -> bool {
    let new_v = match version_to_tuple(new) {
        Some(v) => v,
        None => return false,
    };
    let last_v = match version_to_tuple(last) {
        Some(v) => v,
        None => return false,
    };

    if new_v.0 == last_v.0 + 1 && new_v.1 == 0 && new_v.2 == 0 {
        return true; // Major bump
    }
    if new_v.0 == last_v.0 && new_v.1 == last_v.1 + 1 && new_v.2 == 0 {
        return true; // Minor bump
    }
    if new_v.0 == last_v.0 && new_v.1 == last_v.1 && new_v.2 == last_v.2 + 1 {
        return true; // Patch bump
    }

    false
}

pub fn find_closest_match<'a>(target: &str, options: &'a [String]) -> Option<&'a str> {
    let mut closest: Option<(&str, usize)> = None;

    for opt in options {
        if opt == "_" {
            continue;
        }
        let dist = levenshtein_distance(target, opt);
        if closest.is_none() || dist < closest.unwrap().1 {
            closest = Some((opt.as_str(), dist));
        }
    }

    match closest {
        Some((s, dist)) if dist <= 2 => Some(s),
        _ => None,
    }
}

pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let mut costs = vec![0; b.len() + 1];
    for j in 0..=b.len() {
        costs[j] = j;
    }

    for (i, ca) in a.chars().enumerate() {
        let mut last = i;
        costs[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let old = costs[j + 1];
            let cost = if ca == cb {
                0
            } else if ca.eq_ignore_ascii_case(&cb) {
                1
            } else {
                2
            };
            costs[j + 1] = std::cmp::min(
                std::cmp::min(costs[j] + 1, costs[j + 1] + 1),
                last + cost,
            );
            last = old;
        }
    }
    costs[b.len()]
}