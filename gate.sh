#!/usr/bin/env bash
# The engine's gate: what every commit pushed to this repository has passed.
#
#   ./gate.sh            format, clippy (deny warnings), the test suite, the fuzz targets' build
#
# With a CRS checkout (CRS_DIR, or test-rules/crs) the corpus test runs too; without one
# it is skipped and the gate says so. A pass is recorded for the commit's tree under
# .gate/, which .githooks/pre-push checks (git config core.hooksPath .githooks): a push
# of a commit without a recorded pass is refused. GATE_UNGATED=<reason> lets one through.
set -euo pipefail
cd "$(dirname "$0")"
[ -z "$(git status --porcelain)" ] || { echo "gate: commit or stash first; the pass is recorded for a commit" >&2; exit 2; }

# An empty rustfmt config: a checkout inside another repository must not pick up its rustfmt.toml.
empty=$(mktemp); trap 'rm -f "$empty"' EXIT
echo "==> fmt";    cargo fmt --all --check -- --config-path "$empty"
echo "==> clippy"; cargo clippy --all-targets -- -D warnings
crs=${CRS_DIR:-test-rules/crs}
if [ -f "$crs/crs-setup.conf" ] || [ -f "$crs/crs-setup.conf.example" ]; then
  echo "==> test (with the CRS corpus at $crs)"; CRS_DIR="$crs" cargo test --release
  corpus=with-corpus
else
  echo "==> test (no CRS checkout at $crs: the corpus test is skipped)"; SKIP_CRS_CONFORMANCE=1 cargo test --release
  corpus=without-corpus
fi
if cargo fuzz --version >/dev/null 2>&1; then
  echo "==> fuzz targets build"; cargo +nightly fuzz build
  fuzz=fuzz-built
else
  echo "==> fuzz targets: cargo-fuzz is not installed, not built"; fuzz=fuzz-not-built
fi
mkdir -p .gate
tree=$(git rev-parse 'HEAD^{tree}')
echo "$(git rev-parse HEAD) $(date -u +%Y-%m-%dT%H:%M:%SZ) $corpus $fuzz" > ".gate/$tree.ok"
echo "gate: passed and recorded for $(git rev-parse --short HEAD) ($corpus, $fuzz)"
