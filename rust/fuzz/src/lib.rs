//! LibAFL fuzzers for longfellow-zk. See README.md.

pub mod alloc_limit;
pub mod circasm;
pub mod edn;
pub mod fixtures;
pub mod grammar;
pub mod mdoc_props;
pub mod proof_edits;
pub mod runner;

/// Maximum CBOR nesting depth in an assembled or raw input. Used by the CBOR
/// and mdoc harnesses when `LF_FUZZ_MAX_DEPTH` is set, to keep known
/// recursion crashes from dominating a comparison run. The scan is done in
/// uninstrumented harness code.
pub fn cbor_depth_exceeds(data: &[u8], limit: usize) -> bool {
    // Conservative: count container/tag heads seen before enough items close
    // them. Over-approximates depth, which is fine for a filter.
    let mut depth = 0usize;
    let mut pending: Vec<u64> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        let major = b >> 5;
        let info = b & 0x1f;
        i += 1;
        let (arg, skip) = match info {
            0..=23 => (u64::from(info), 0),
            24 => (data.get(i).copied().map_or(0, u64::from), 1),
            25 => (0, 2),
            26 => (0, 4),
            27 => (0, 8),
            _ => (0, 0),
        };
        i += skip;
        match major {
            2 | 3 => i = i.saturating_add(arg as usize),
            4 | 5 | 6 => {
                depth += 1;
                if depth > limit {
                    return true;
                }
                pending.push(if major == 6 { 1 } else { arg.max(1) });
                continue;
            }
            _ => {}
        }
        // A scalar finished; pop completed containers.
        while let Some(top) = pending.last_mut() {
            *top -= 1;
            if *top > 0 {
                break;
            }
            pending.pop();
            depth = depth.saturating_sub(1);
        }
    }
    false
}

pub fn max_depth_from_env() -> Option<usize> {
    std::env::var("LF_FUZZ_MAX_DEPTH").ok().and_then(|v| v.parse().ok())
}
