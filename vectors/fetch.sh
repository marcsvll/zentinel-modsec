#!/usr/bin/env bash
# Fetches ModSecurity's input/output vectors for transformations and operators
# (owasp-modsecurity/secrules-language-tests, the set libmodsecurity's own unit tests run),
# by commit, with the tarball's sha256 checked. The repository carries no licence file,
# so nothing of it is committed or distributed here: the checkout lands in
# vectors/secrules-language-tests/, which git ignores, and only tests/modsecurity_vectors.rs
# reads it.
set -euo pipefail
cd "$(dirname "$0")"
COMMIT=f73c73027ef49ccf99c7911744929a71d15ff419
SHA256=a3b33d6708ca94160ee3cbc362c3f9c0ea6471d46d7a1fd10490a18f8dd9085e
DEST=secrules-language-tests
if [ -f "$DEST/.commit" ] && [ "$(cat "$DEST/.commit")" = "$COMMIT" ]; then
  echo "vectors: secrules-language-tests $COMMIT already in vectors/$DEST"; exit 0
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/owasp-modsecurity/secrules-language-tests/archive/$COMMIT.tar.gz" -o "$tmp/v.tgz"
echo "$SHA256  $tmp/v.tgz" | sha256sum -c - >/dev/null
rm -rf "$DEST"; mkdir "$DEST"
tar -xzf "$tmp/v.tgz" -C "$DEST" --strip-components=1
echo "$COMMIT" > "$DEST/.commit"
echo "vectors: secrules-language-tests $COMMIT fetched into vectors/$DEST"
