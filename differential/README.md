# The detectors against the C libinjection

Development only. `@detectSQLi` and `@detectXSS` call `libinjectionrs`, a Rust
translation of libinjection. This directory links the C library the translation was
made from and compares the two, value by value: the SQL-injection verdict, the
fingerprint and the XSS verdict. The engine itself has no C and no `unsafe`; this crate
is not a dependency of anything.

```
differential/fetch.sh        # the C library, by commit, sha256 checked, into libinjection-c/ (not committed)
cd differential
cargo test --release -- --nocapture                    # the C library's own samples
DIFFERENTIAL_YAML_DIRS=<crs>/tests/regression/tests:<gotestwaf>/testcases \
CRS_DIR=<crs> cargo test --release -- --nocapture      # plus those corpora, and what the misses cost behind the CRS
cargo +nightly fuzz run differential -- -max_total_time=600 -max_len=128
```

`../gate.sh` runs the comparison when `libinjection-c/` is there and says so when it
is not. It needs a C compiler.

The test fails on a disagreement that has none of the causes below; the fuzz target
crashes on one. With `DIFFERENTIAL_COLLECT=<dir>` the fuzz target writes disagreements
to files and goes on, and `DIFFERENTIAL_RAW_DIRS=<dir> cargo test` lists them by kind.

## What it found, and what is left

The first comparison was of `libinjectionrs` 0.1.1 as published, against libinjection
`85e252a`, on 531,480 values (the C library's samples, the OWASP CRS 4.30 regression
tests, GoTestWAF 0.5.10's cases; each as written, URL-decoded and cut at `?&=`), of
which the C library calls 132,933 SQL injection and 115,159 XSS. 2,174 disagreed, and
387 of the values the translation missed passed the CRS at paranoia 1 as a query
argument. Two causes were misses of the translation and are fixed in the project's
fork of it (<https://github.com/marcsvll/libinjectionrs>, 0.2.0), which the engine
builds since 0.10.0:

| Fixed | Values | Smallest case | What was wrong |
|---|---|---|---|
| Three-word keywords | 2,152 | `1 IN BOOLEAN MODE) AND 1` | The keyword table has entries such as `IN BOOLEAN`, `LOCK IN`, `CREATE OR`, typed as plain words, so that `IN BOOLEAN MODE`, `LOCK IN SHARE MODE`, `CREATE OR REPLACE` can be assembled word by word. C merges two words when the pair is in the table; the translation merged only when the pair's type was not "plain word", so those keywords never formed. |
| `INTO` compared with its case | 8 | `1 into outfile 'a'` | A two-token fingerprint is let through unless it is `INTO OUTFILE` or `INTO DUMPFILE`. C compares `INTO` without case; the translation used `starts_with(b"INTO")`. |

With the fork, 14 of the 531,480 values disagree, all for the first cause below, and
none of them passes the CRS.

## Known causes that stay

`src/lib.rs` (`known_cause`) recognizes each by what triggers it, which is broader
than the difference itself: a new disagreement in a value that also has a trigger is
not seen.

| Cause | Which side | Smallest case | What happens |
|---|---|---|---|
| Event handler names compared as a prefix | C, with a memory error | `<img onerrorx=a>` | C compares an attribute with each `on…` handler name over the length of the handler name, so `onerrorx` and `onerror%09` count as `onerror`, and a short attribute at the end of the input is **read past its end** (heap over-read in `is_black_attr`, seen under AddressSanitizer; `src/lib.rs` pads the input for that reason). Upstream's main branch has since bounded that comparison; the commit compared here predates it. The engine compares the whole name. |
| `sp_password` compared without its case | differs; the engine reports more | `sP_password#` | A fingerprint that ends in a comment is SQL injection when the input contains `sp_password`. C looks for it in lower case only; the engine ignores case. Seen under fuzz only. |
| A NUL inside the value | not analysed | `$\0+@` | Disagreements in values with a NUL are not broken down. The CRS applies `t:removeNulls` before both operators (941100, 941101, 942100, 942101), so no such value reaches them through it. Seen under fuzz only. |

After these causes, fuzz runs of about 2 million inputs each found no other
disagreement. That is not exhaustive.
