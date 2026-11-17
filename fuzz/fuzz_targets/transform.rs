//! Every transformation over arbitrary bytes, alone and in chains of up to four picked by
//! the input's first bytes, as rules chain them. Nothing may panic, and a transformation
//! that reports nothing to do (borrows its input) must give the input back unchanged.
#![no_main]
use std::borrow::Cow;

use libfuzzer_sys::fuzz_target;
use zentinel_modsec::transformations::create_transformation;

const NAMES: [&str; 37] = [
    "urlDecode",
    "urlDecodeUni",
    "base64Decode",
    "base64DecodeExt",
    "hexDecode",
    "htmlEntityDecode",
    "jsDecode",
    "cssDecode",
    "base64Encode",
    "hexEncode",
    "urlEncode",
    "lowercase",
    "uppercase",
    "compressWhitespace",
    "removeWhitespace",
    "removeNulls",
    "replaceNulls",
    "trim",
    "trimLeft",
    "trimRight",
    "normalizePath",
    "normalizePathWin",
    "removeComments",
    "replaceComments",
    "cmdLine",
    "removeCommentsChar",
    "md5",
    "sha1",
    "length",
    "sqlHexDecode",
    "utf8toUnicode",
    "escapeSeqDecode",
    "parityEven7bit",
    "parityOdd7bit",
    "parityZero7bit",
    "sha256",
    "none",
];

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Some((&picks, value)) = data.split_first() else {
        return;
    };
    // Each transformation alone.
    for name in NAMES {
        let t = create_transformation(name).expect("every listed name is known");
        if let Cow::Borrowed(out) = t.transform(value) {
            // A borrowed answer is the input or a part of it (trim).
            assert!(value.windows(out.len().max(1)).any(|w| w == out) || out.is_empty());
        }
    }
    // A chain: the low bits of the first byte say how long, the next bytes which.
    let len = usize::from(picks % 4) + 1;
    let mut current: Vec<u8> = value.to_vec();
    for (i, pick) in value.iter().take(len).enumerate() {
        let name = NAMES[(usize::from(*pick) + i) % NAMES.len()];
        let t = create_transformation(name).expect("every listed name is known");
        current = t.transform(&current).into_owned();
    }
    let _ = current.len();
});
