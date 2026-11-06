pub(crate) fn equal(left: &str, right: &str) -> bool {
    if left.is_ascii() && right.is_ascii() {
        return left.eq_ignore_ascii_case(right);
    }
    left.chars().map(fold).eq(right.chars().map(fold))
}
pub(crate) fn lowercase(value: &str) -> String {
    value.chars().map(lower).collect()
}
fn lower(value: char) -> char {
    value.to_lowercase().next().unwrap_or(value)
}
fn fold(value: char) -> char {
    if let Ok(index) = EXCEPTIONS.binary_search_by_key(&value, |(value, _)| *value) {
        return EXCEPTIONS[index].1;
    }
    let mut lower = value.to_lowercase();
    match (lower.next(), lower.next()) {
        (Some(value), None) => value,
        _ => value,
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/support/mod.rs"]
mod support;

#[test]
fn every_unicode_scalar_matches_go_simple_fold_equivalence_classes() {
    let input = (0..=char::MAX as u32)
        .filter_map(char::from_u32)
        .map(fold)
        .collect::<String>();
    let lowered = (0..=char::MAX as u32)
        .filter_map(char::from_u32)
        .map(lower)
        .collect::<String>();
    let result = support::bridge_input(
        "check-casefold",
        std::path::Path::new("unused"),
        &serde_json::to_vec(&serde_json::json!({"folded":input,"lowered":lowered})).unwrap(),
    );
    let result: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["checked"], 1_112_064);
    assert_eq!(result["mismatches"], serde_json::json!([]), "{result}");
    assert_eq!(
        result["lower_mismatches"],
        serde_json::json!([]),
        "{result}"
    );
    for (left, right, want) in [
        ("Σ", "ς", true),
        ("K", "k", true),
        ("ſ", "s", true),
        ("İ", "i", false),
        ("ı", "i", false),
        ("ß", "ss", false),
    ] {
        assert_eq!(equal(left, right), want);
    }
}

// Simple-fold exceptions to Unicode 17.0.0 lowercase, checked against Go.
const EXCEPTIONS: &[(char, char)] = &[
    ('\u{130}', '\u{130}'),
    ('\u{17f}', '\u{73}'),
    ('\u{399}', '\u{345}'),
    ('\u{39c}', '\u{b5}'),
    ('\u{3a3}', '\u{3c2}'),
    ('\u{3b9}', '\u{345}'),
    ('\u{3bc}', '\u{b5}'),
    ('\u{3c3}', '\u{3c2}'),
    ('\u{3d0}', '\u{3b2}'),
    ('\u{3d1}', '\u{3b8}'),
    ('\u{3d5}', '\u{3c6}'),
    ('\u{3d6}', '\u{3c0}'),
    ('\u{3f0}', '\u{3ba}'),
    ('\u{3f1}', '\u{3c1}'),
    ('\u{3f5}', '\u{3b5}'),
    ('\u{1c80}', '\u{432}'),
    ('\u{1c81}', '\u{434}'),
    ('\u{1c82}', '\u{43e}'),
    ('\u{1c83}', '\u{441}'),
    ('\u{1c84}', '\u{442}'),
    ('\u{1c85}', '\u{442}'),
    ('\u{1c86}', '\u{44a}'),
    ('\u{1c87}', '\u{463}'),
    ('\u{1e9b}', '\u{1e61}'),
    ('\u{1fbe}', '\u{345}'),
    ('\u{1fd3}', '\u{390}'),
    ('\u{1fe3}', '\u{3b0}'),
    ('\u{a64a}', '\u{1c88}'),
    ('\u{a64b}', '\u{1c88}'),
    ('\u{fb06}', '\u{fb05}'),
];
