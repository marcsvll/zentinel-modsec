#!/usr/bin/env bash
# Fetches the C libinjection this directory compares against: the commit the
# libinjectionrs port was translated from (the submodule of its repository), by commit,
# with the tarball's sha256 checked. The checkout lands in differential/libinjection-c/,
# which git ignores: no C source is committed here.
set -euo pipefail
cd "$(dirname "$0")"
COMMIT=85e252a28981d479822092bad235bb75beb7edfa
SHA256=72f82e86691b535e1bdf103e99fc18a2917eb23dd9c2b07d90a0682dd6bb5ad3
DEST=libinjection-c
if [ -f "$DEST/.commit" ] && [ "$(cat "$DEST/.commit")" = "$COMMIT" ]; then
  echo "differential: libinjection $COMMIT already in differential/$DEST"; exit 0
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/libinjection/libinjection/archive/$COMMIT.tar.gz" -o "$tmp/c.tgz"
echo "$SHA256  $tmp/c.tgz" | sha256sum -c - >/dev/null
rm -rf "$DEST"; mkdir "$DEST"
tar -xzf "$tmp/c.tgz" -C "$DEST" --strip-components=1
echo "$COMMIT" > "$DEST/.commit"
echo "differential: libinjection $COMMIT fetched into differential/$DEST"
