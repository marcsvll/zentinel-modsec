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

## Known causes (libinjectionrs 0.1.1 against libinjection `85e252a`)

Measured on 531,480 values (the C library's samples, the OWASP CRS 4.30 regression
tests, GoTestWAF 0.5.10's cases; each as written, URL-decoded and cut at `?&=`), of
which the C library calls 132,933 SQL injection and 115,159 XSS. 2,174 disagree, all
for these causes. `src/lib.rs` (`known_cause`) recognizes each by what triggers it,
which is broader than the defect: a new disagreement in a value that also has a
trigger is not seen.

| Cause | Who is wrong | Values | Smallest case | What happens |
|---|---|---|---|---|
| Three-word keywords | the port: **misses** | 2,152 | `1 IN BOOLEAN MODE) AND 1` | The keyword table has entries such as `IN BOOLEAN`, `LOCK IN`, `CREATE OR`, typed as plain words, so that `IN BOOLEAN MODE`, `LOCK IN SHARE MODE`, `CREATE OR REPLACE` can be assembled word by word. C merges two words when the pair is in the table; the port merges only when the pair's type is not "plain word" (`sqli/mod.rs`, the word-merging fold), so those keywords never form. |
| `INTO` compared with its case | the port: **misses** | 8 | `1 into outfile 'a'` | A two-token fingerprint is let through unless it is `INTO OUTFILE` or `INTO DUMPFILE`. C compares `INTO` without case; the port uses `starts_with(b"INTO")`, so any other spelling is taken for harmless. |
| Event handler names compared as a prefix | C, with a memory error | 14 | `<img onerrorx=a>` | C compares an attribute with each `on…` handler name over the length of the handler name, so `onerrorx` and `onerror%09` count as `onerror`, and a short attribute at the end of the input is **read past its end** (heap over-read in `is_black_attr`, seen under AddressSanitizer; `src/lib.rs` pads the input for that reason). Upstream's main branch has since bounded that comparison; the commit compared here predates it. The port compares the whole name. |
| `sp_password` compared without its case | differs; the port reports more | fuzz only | `sP_password#` | A fingerprint that ends in a comment is SQL injection when the input contains `sp_password`. C looks for it in lower case only; the port ignores case. |
| A NUL inside the value | not analysed | fuzz only | `$\0+@` | Disagreements in values with a NUL are not broken down. The CRS applies `t:removeNulls` before both operators (941100, 941101, 942100, 942101), so no such value reaches them through it. |

Behind the CRS at paranoia 1, in blocking mode, 387 of the 1,945 missed values (NULs
aside) are let through when sent as a query argument; the others are refused by
other rules. The values are fragments of real injection strings, so this is an upper
bound on what the two misses cost, not a count of working attacks.

After the causes above, two fuzz runs of about 2.1 million inputs each found no other
disagreement. That is not exhaustive.
