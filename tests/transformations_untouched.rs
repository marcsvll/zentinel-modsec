//! A transformation that has nothing to do says so without allocating: most
//! values are plain text that no decoding or normalization changes.

mod common;

use std::borrow::Cow;

use common::allocations;
use zentinel_modsec::transformations::create_transformation;

#[test]
fn a_value_with_nothing_to_transform_costs_no_allocation() {
    for name in [
        "urlDecode",
        "urlDecodeUni",
        "htmlEntityDecode",
        "jsDecode",
        "cssDecode",
        "escapeSeqDecode",
        "utf8toUnicode",
        "lowercase",
        "removeNulls",
        "compressWhitespace",
        "removeWhitespace",
        "normalizePath",
        "normalizePathWin",
        "removeComments",
        "replaceComments",
        "removeCommentsChar",
        "cmdLine",
    ] {
        let t = create_transformation(name).expect("known transformation");
        let before = allocations();
        let unchanged = matches!(t.transform("ordinaryvalue123"), Cow::Borrowed(_));
        assert_eq!(allocations() - before, 0, "{name} allocated");
        assert!(unchanged, "{name} copied a value it did not change");
    }
}

#[test]
fn a_value_with_something_to_transform_is_still_transformed() {
    let cases = [
        ("urlDecodeUni", "a%20b+c%u0041", "a b cA"),
        ("jsDecode", "a\\x41", "aA"),
        ("cssDecode", "a\\41 b", "aAb"),
        ("escapeSeqDecode", "a\\x41", "aA"),
        ("lowercase", "Select", "select"),
        ("compressWhitespace", "a \t b", "a b"),
        ("removeWhitespace", "a \t b", "ab"),
        ("normalizePath", "/a/./b//c/../d", "/a/b/d"),
        ("normalizePathWin", "\\a\\.\\b", "/a/b"),
        ("removeComments", "a/* x */b", "ab"),
        ("replaceComments", "a/* x */b", "a b"),
        ("removeCommentsChar", "a/*b--c#d", "abcd"),
        ("cmdLine", "C^at  /Etc/Passwd", "cat/etc/passwd"),
    ];
    for (name, input, expected) in cases {
        let t = create_transformation(name).expect("known transformation");
        assert_eq!(t.transform(input), expected, "{name} on {input:?}");
    }
}
