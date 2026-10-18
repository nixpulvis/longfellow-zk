//! Invariants on successful `parse_mdoc` results. The prover builds the
//! circuit witness from these offsets and lengths, so an out-of-range value
//! is a bug even when nothing panics. Kept in the (uninstrumented) library so
//! the checks themselves add no coverage.

use mdoc_zk_circuits::cbor::mdoc::ParsedMdoc;

pub fn check<N>(parsed: &ParsedMdoc<N>) {
    // MSO offsets index into the MSO map, which sits inside cbor_mso.
    for (name, off) in [
        ("doc_type", parsed.doc_type_offset_in_mso),
        ("valid_from", parsed.valid_from_offset_in_mso),
        ("valid_until", parsed.valid_until_offset_in_mso),
        ("device_key_info", parsed.device_key_info_offset_in_mso),
        ("value_digests", parsed.value_digests_offset_in_mso),
    ] {
        assert!(
            off < parsed.cbor_mso.len(),
            "{name} offset {off} outside MSO of {} bytes",
            parsed.cbor_mso.len()
        );
    }

    for attr in &parsed.attrs {
        let item = &attr.cbor_issuer_signed_item;
        let loc = &attr.field_locator;
        for i in 0..4 {
            let end = loc.slot_position[i].checked_add(loc.length[i]);
            assert!(
                end.is_some_and(|e| e <= item.len()),
                "attr {:?} slot {i}: {}+{} exceeds item of {} bytes",
                String::from_utf8_lossy(&attr.name),
                loc.slot_position[i],
                loc.length[i],
                item.len()
            );
        }
        // The four slots are a permutation of 0..4.
        let mut seen = [false; 4];
        for k in 0..4 {
            let slot = (loc.permutation >> (2 * k)) & 3;
            assert!(!seen[slot], "permutation {:#x} repeats slot {slot}", loc.permutation);
            seen[slot] = true;
        }
        // elementValue bytes must appear inside the signed item.
        assert!(
            item.windows(attr.cbor_value.len().max(1))
                .any(|w| w == attr.cbor_value.as_slice()),
            "elementValue not found inside its IssuerSignedItem"
        );
    }
}
