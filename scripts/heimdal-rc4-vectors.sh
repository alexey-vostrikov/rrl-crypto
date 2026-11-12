#!/bin/sh
# Produce and check the `rc4-hmac` fixtures against Heimdal's libkrb5.
#
# Three steps, and the third is the one that matters: Heimdal is asked to decrypt a ciphertext this
# crate produced, so the agreement is established in both directions rather than asserted in one.
#
#   1. Heimdal derives a key from a password and encrypts known plaintexts — its output is what our
#      `decrypt` is then tested against.
#   2. This crate encrypts the same plaintexts with a *fixed* confounder, so its output is
#      reproducible.
#   3. Heimdal decrypts that output and must get the plaintext back.
#
# The JSON written to tests/fixtures/heimdal_rc4.json carries both directions, including the
# plaintext Heimdal recovered — so a change to our encryption fails a test even though Heimdal is not
# run at test time.
#
# Usage: scripts/heimdal-rc4-vectors.sh [--write]
#   --write   replace tests/fixtures/heimdal_rc4.json (otherwise print it)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.99.1-bullseye}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Everything happens in one container: the reference partner is compiled there against Debian's
# packaged Heimdal, and the example binary this crate builds is run there too — the host has no
# `libkrb5.so.26` and should not have one.
"$ROOT/scripts/cargo.sh" build -q --example rc4_vector
TAG=$(printf '%s' "$IMAGE" | sed 's/.*://')
BIN="$ROOT/target/$TAG/debug/examples"

docker run --rm -v "$ROOT:/w:ro" -v "$BIN:/ours:ro" -v "$TMP:/out" "$IMAGE" sh -ec '
set -eu
apt-get update -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=20 >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq heimdal-dev xxd >/dev/null 2>&1
cc -O1 -o /out/heimdal-rc4 /w/docker/heimdal-rc4.c -I/usr/include/heimdal -L/usr/lib/x86_64-linux-gnu/heimdal -lkrb5 -lasn1 -lroken -lhcrypto -lwind -lcom_err

H=/out/heimdal-rc4
OURS=/ours/rc4_vector
hex() { printf "%s" "$1" | xxd -p | tr -d "\n"; }

# The cases: a password with and without non-ASCII characters, and two usages that are told apart —
# one of which (3) is mapped to 8 before it keys anything.
PASSWORD_ASCII=$(hex "Password123!")
SALT_ASCII=$(hex "EXAMPLE.COMalice")
PASSWORD_UTF8=$(hex "pässwörd")

KEY_A=$("$H" s2k "$PASSWORD_ASCII" "$SALT_ASCII")
KEY_U=$("$H" s2k "$PASSWORD_UTF8" "$SALT_ASCII")

PLAIN_TICKET=$(hex "the encrypted part of an AS-REP")
PLAIN_TS=$(hex "a PA-ENC-TIMESTAMP")

# Heimdal, with its own confounder: what our decryption is tested against.
CT_TICKET=$("$H" encrypt "$KEY_A" 3 "$PLAIN_TICKET")
CT_TS=$("$H" encrypt "$KEY_A" 1 "$PLAIN_TS")

# Ours, with a fixed confounder, so that the fixture can pin the exact octets.
CONFOUNDER=0001020304050607
OUR_CT_TICKET=$("$OURS" "$KEY_A" 3 "$PLAIN_TICKET" "$CONFOUNDER")
OUR_CT_TS=$("$OURS" "$KEY_A" 1 "$PLAIN_TS" "$CONFOUNDER")

# Heimdal reads ours back. If this prints anything but the plaintext, the two implementations
# disagree about the envelope and no fixture should be written.
BACK_TICKET=$("$H" decrypt "$KEY_A" 3 "$OUR_CT_TICKET")
BACK_TS=$("$H" decrypt "$KEY_A" 1 "$OUR_CT_TS")

[ "$BACK_TICKET" = "$PLAIN_TICKET" ] || { echo "Heimdal could not read our usage-3 ciphertext: $BACK_TICKET" >&2; exit 1; }
[ "$BACK_TS" = "$PLAIN_TS" ] || { echo "Heimdal could not read our usage-1 ciphertext: $BACK_TS" >&2; exit 1; }

cat > /out/vectors.json <<JSON
{
  "note": "Produced by scripts/heimdal-rc4-vectors.sh against Heimdal 7.7 (Debian bullseye, heimdal-dev). heimdal: what Heimdal encrypted with its own confounder. ours: what rrl-crypto encrypted with the fixed confounder, which Heimdal then decrypted back to the plaintext recorded in heimdal_read_ours_as.",
  "keys": [
    { "password": "$PASSWORD_ASCII", "salt": "$SALT_ASCII", "key": "$KEY_A" },
    { "password": "$PASSWORD_UTF8", "salt": "$SALT_ASCII", "key": "$KEY_U" }
  ],
  "cases": [
    {
      "key": "$KEY_A", "usage": 3,
      "plaintext": "$PLAIN_TICKET",
      "heimdal": "$CT_TICKET",
      "ours_confounder": "$CONFOUNDER",
      "ours": "$OUR_CT_TICKET",
      "heimdal_read_ours_as": "$BACK_TICKET"
    },
    {
      "key": "$KEY_A", "usage": 1,
      "plaintext": "$PLAIN_TS",
      "heimdal": "$CT_TS",
      "ours_confounder": "$CONFOUNDER",
      "ours": "$OUR_CT_TS",
      "heimdal_read_ours_as": "$BACK_TS"
    }
  ]
}
JSON
'

if [ "${1:-}" = "--write" ]; then
    cp "$TMP/vectors.json" "$ROOT/tests/fixtures/heimdal_rc4.json"
    echo "wrote tests/fixtures/heimdal_rc4.json"
else
    cat "$TMP/vectors.json"
fi
