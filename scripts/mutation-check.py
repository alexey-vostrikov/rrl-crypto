#!/usr/bin/env python3
"""Break each primitive on purpose, and require the suite to notice.

This is the third acceptance rule of the epic this crate belongs to: a green suite says nothing on
its own, because a test that agrees with the code it checks passes whatever that code does. What has
to be shown is the other direction - that a deliberate break fails.

Each entry below is a mutation with the test that should catch it. The script applies one at a time,
runs the suite, and restores the file from a copy taken before the run; a mutation that leaves the
suite green is printed as a **survivor** and makes the script exit non-zero, because a survivor is
either a hole in the tests or a line nothing depends on.

Deliberately **not** a list of every line: a mutation of a comment or of a formatting choice proves
nothing. These are the constructions whose breakage has actually shipped somewhere in this family -
the counter length written in octets instead of bits, the AES-CBC chain fed the previous key instead
of the previous plaintext, a comparison that returns early.

Run inside the toolchain image, where the source is mounted read-write:

    docker run --rm -v "$PWD:/w" -w /w rust:1.99.1-bullseye python3 scripts/mutation-check.py

An argument limits the run to mutations whose description matches it, which is how a single one is
re-run while fixing a survivor:

    python3 scripts/mutation-check.py ct_eq
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (file, what to replace, what with, description, the test that should fail)
MUTATIONS = [
    (
        "src/lib.rs",
        "    core::hint::black_box(diff) == 0\n",
        "    true\n",
        "ct_eq always says equal",
        "the comparison tests",
    ),
    (
        "src/lib.rs",
        "    if a.len() != b.len() {\n        return false;\n    }\n    let mut diff = 0u8;",
        "    if a.len() != b.len() {\n        return true;\n    }\n    let mut diff = 0u8;",
        "ct_eq says equal when the lengths differ",
        "a_difference_in_length_is_a_difference",
    ),
    (
        "src/nt.rs",
        "    if !utf16.len().is_multiple_of(2) {",
        "    if false {",
        "the NT hash accepts an odd number of octets",
        "an odd length is refused",
    ),
    (
        "src/lib.rs",
        "    for part in parts {\n        digest.update(part);\n    }\n    digest.finalize().into()\n}\n\n/// `HMAC-MD5",
        "    for part in parts.iter().take(parts.len().saturating_sub(1)) {\n        digest.update(part);\n    }\n    digest.finalize().into()\n}\n\n/// `HMAC-MD5",
        "md5_parts drops its last part",
        "md5_over_parts_is_the_digest_of_their_concatenation",
    ),
    (
        "src/kdf.rs",
        "    msg.extend_from_slice(&k_bits.to_be_bytes());",
        "    msg.extend_from_slice(&(k_bits / 8).to_be_bytes());",
        "KDF-HMAC-SHA2 writes the key length in octets instead of bits",
        "the RFC 8009 vectors",
    ),
    (
        "src/kdf.rs",
        "            aes::Aes256::new_from_slice(base_key).map_err(|_| Error::Crypto(\"AES-256\".into()))?;\n        while out.len() < k {",
        "            aes::Aes256::new_from_slice(base_key).map_err(|_| Error::Crypto(\"AES-256\".into()))?;\n        while out.len() < 16 {",
        "DR gives the AES-256 branch one block, so a 256-bit key comes out 128 bits long",
        "the MIT derive vector for enctype 18",
    ),
    (
        "src/rc4.rs",
        "    let digest = crate::md5_parts(&digested);",
        "    let digest = crate::md5_parts(&digested[..0]);",
        "the rc4 checksum omits the usage and the data from its MD5",
        "the heimdal rc4 vectors",
    ),
]


def run(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def suite_passes() -> bool:
    """The whole suite, not a filter: a break may be caught by a test with another name."""
    result = run(["cargo", "test", "--quiet"], ROOT)
    return result.returncode == 0


def main() -> int:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    selected = [m for m in MUTATIONS if only is None or only in m[3]]
    if not selected:
        print(f"nothing matches {only!r}; the mutations are:")
        for m in MUTATIONS:
            print("  ", m[3])
        return 2

    # A clean baseline first: a suite that is already red cannot show anything about a mutation.
    if not suite_passes():
        print("the suite is red before any mutation; fix that first")
        return 2

    survivors = []
    backup = Path(tempfile.mkdtemp())
    for index, (relative, old, new, description, expected) in enumerate(selected, start=1):
        path = ROOT / relative
        original = path.read_text()
        (backup / f"{index}.rs").write_text(original)

        if original.count(old) != 1:
            print(f"[{index}] SKIP {description}: the anchor appears {original.count(old)} times")
            survivors.append((description, "the anchor is gone - the mutation is out of date"))
            continue

        path.write_text(original.replace(old, new, 1))
        try:
            caught = not suite_passes()
        finally:
            shutil.copyfile(backup / f"{index}.rs", path)

        if caught:
            print(f"[{index}] caught   {description}  ({expected})")
        else:
            print(f"[{index}] SURVIVED {description}  - nothing failed; {expected} is not watching it")
            survivors.append((description, expected))

    print()
    if survivors:
        print(f"{len(survivors)} survivor(s) of {len(selected)}:")
        for description, expected in survivors:
            print(f"  - {description}: {expected}")
        return 1

    print(f"all {len(selected)} mutations were caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
