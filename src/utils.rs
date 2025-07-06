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

fn cmp_version(a: (u64,u64,u64), b: (u64,u64,u64)) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if a.0 != b.0 {
        return a.0.cmp(&b.0);
    }
    if a.1 != b.1 {
        return a.1.cmp(&b.1);
    }
    a.2.cmp(&b.2)
}

pub fn check_version(current: &str, required: &str) -> bool {
    if required.is_empty() {
        return true;
    }

    let cur = match version_to_tuple(current) {
        Some(v) => v,
        None => return false,
    };

    let ge = |a, b| cmp_version(a, b) != std::cmp::Ordering::Less;
    let gt = |a, b| cmp_version(a, b) == std::cmp::Ordering::Greater;
    let le = |a, b| cmp_version(a, b) != std::cmp::Ordering::Greater;
    let lt = |a, b| cmp_version(a, b) == std::cmp::Ordering::Less;
    let eq = |a, b| cmp_version(a, b) == std::cmp::Ordering::Equal;

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