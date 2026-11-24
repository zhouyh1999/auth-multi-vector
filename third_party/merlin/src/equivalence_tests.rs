//! Check execution changes against the pristine Merlin 3.0.0 STROBE source.
use crate::{strobe::Strobe128, strobe_reference};

fn assert_same_state(actual: &Strobe128, expected: &strobe_reference::Strobe128) {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    let mut left = [0; 512];
    let mut right = [0; 512];
    actual.prf(&mut left, false);
    expected.prf(&mut right, false);
    assert_eq!(left, right);
}

#[test]
fn every_rate_offset_and_operation_matches_upstream() {
    let data: [u8; 1024] = core::array::from_fn(|i| (i * 37 + i / 7) as u8);
    // Prefix lengths cover every initial position in the 166-byte rate block.
    for prefix in 0..166 {
        for len in [
            0, 1, 2, 3, 4, 8, 15, 16, 31, 32, 33, 64, 165, 166, 167, 331, 332, 1024,
        ] {
            let mut actual = Strobe128::new(b"gem-strobe-equivalence-v1");
            let mut expected = strobe_reference::Strobe128::new(b"gem-strobe-equivalence-v1");
            actual.ad(&data[..prefix], false);
            expected.ad(&data[..prefix], false);
            assert_same_state(&actual, &expected);

            actual.meta_ad(b"b_i", false);
            expected.meta_ad(b"b_i", false);
            actual.meta_ad(&(len as u32).to_le_bytes(), true);
            expected.meta_ad(&(len as u32).to_le_bytes(), true);
            assert_same_state(&actual, &expected);

            let middle = len / 2;
            actual.ad(&data[..middle], false);
            expected.ad(&data[..middle], false);
            actual.ad(&data[middle..len], true);
            expected.ad(&data[middle..len], true);
            assert_same_state(&actual, &expected);

            actual.key(&data[..middle], false);
            expected.key(&data[..middle], false);
            actual.key(&data[middle..len], true);
            expected.key(&data[middle..len], true);
            assert_same_state(&actual, &expected);

            let mut left = [0; 1024];
            let mut right = [0; 1024];
            actual.prf(&mut left[..middle], false);
            expected.prf(&mut right[..middle], false);
            actual.prf(&mut left[middle..len], true);
            expected.prf(&mut right[middle..len], true);
            assert_eq!(left, right, "prefix={}, length={}", prefix, len);
            assert_same_state(&actual, &expected);
        }
    }
}
