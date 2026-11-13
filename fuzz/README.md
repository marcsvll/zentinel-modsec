# Fuzzing the engine

Two [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets (nightly toolchain):

| Target | What it runs |
|---|---|
| `request` | a CRS-like rule set (`@detectSQLi`, `@detectXSS`, `t:` chains, multiMatch, ctl, chains, every body processor) over an HTTP/1.1 request in wire format |
| `rules` | the SecLang parser and rule compiler over arbitrary text |

```
cargo +nightly fuzz run request fuzz/corpus/request fuzz/seeds/request -- -max_total_time=600 -timeout=10
cargo +nightly fuzz run rules -- -max_total_time=600 -timeout=10
```

`seeds/request/` is committed: requests taken from the OWASP CRS regression tests
(Apache-2.0), one per rule family and body processor. `corpus/` (what a run grows) and
`artifacts/` (reproducers) are not committed. A crash becomes a regression test under
`tests/` in the commit that fixes it.

`./gate.sh` builds both targets when cargo-fuzz is installed, so a change that breaks
them does not land.
