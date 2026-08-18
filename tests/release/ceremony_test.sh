#!/usr/bin/env bash
# Focused probes for the release ceremony boundary (entarch P1s).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GEN="$ROOT/scripts/generate-checksums.sh"
VERIFY="$ROOT/scripts/verify-public-keys.sh"
FAIL=0

note() { printf '%s\n' "$*"; }
fail() { note "FAIL: $*"; FAIL=$((FAIL + 1)); }
pass() { note "PASS: $*"; }

# P1: notes+pins without archives must fail.
workdir="$(mktemp -d)"
mkdir -p "$workdir"
printf 'notes\n' >"$workdir/release-notes-v0.1.3.md"
printf 'gpg A\nminisign B\n' >"$workdir/expected-fingerprints.txt"
printf '{}\n' >"$workdir/expected-fingerprints.ndjson"
if "$GEN" "$workdir" v0.1.3 >/dev/null 2>&1; then
	fail "generate-checksums accepted zero archives"
else
	pass "generate-checksums refuses provenance-only dir"
fi
rm -rf "$workdir"

# P1: staged TXT != keys/ must fail (when keys/ exist).
# Use a temp repo-root illusion via verifying DIR only vs ROOT keys.
# If keys/ pins exist in this checkout, copy them then mutate staged TXT.
if [ -f "$ROOT/keys/expected-fingerprints.txt" ]; then
	stage="$(mktemp -d)"
	cp "$ROOT/keys/expected-fingerprints.txt" "$stage/expected-fingerprints.txt"
	cp "$ROOT/keys/expected-fingerprints.ndjson" "$stage/expected-fingerprints.ndjson"
	# dummy pubs so the script gets past file-exists; then cmp on txt fires first
	printf 'not-a-key\n' >"$stage/decernor-minisign.pub"
	printf 'not-a-key\n' >"$stage/decernor-release-signing-key.asc"
	printf 'gpg DEADBEEF\nminisign deadbeef\n' >"$stage/expected-fingerprints.txt"
	if "$VERIFY" "$stage" >/dev/null 2>&1; then
		fail "verify accepted staged TXT that differs from keys/"
	else
		pass "verify refuses staged TXT that differs from keys/"
	fi
	rm -rf "$stage"
else
	note "SKIP: keys/ pins not in tree"
fi

# P1: first-use second-install failure must not leave a half pair.
pair="$(mktemp -d)"
empty="$(mktemp -d)"
printf '{}\n{}\n' >"$pair/expected-fingerprints.ndjson"
printf 'gpg A\nminisign B\n' >"$pair/expected-fingerprints.txt"
if DECERNOR_TEST_FAIL_SECOND=1 "$ROOT/scripts/atomic-install-pair.sh" "$pair" "$empty" >/dev/null 2>&1; then
	fail "first-use second-install failure returned success"
else
	if [ -e "$empty/expected-fingerprints.ndjson" ] || [ -e "$empty/expected-fingerprints.txt" ]; then
		fail "first-use rollback left a half pair"
	else
		pass "first-use second-install failure leaves no dest files"
	fi
fi
rm -rf "$pair" "$empty"

# P2: extra TXT token / extra NDJSON record.
if [ -f "$ROOT/keys/expected-fingerprints.txt" ]; then
	stage="$(mktemp -d)"
	cp "$ROOT/keys/expected-fingerprints.txt" "$stage/expected-fingerprints.txt"
	cp "$ROOT/keys/expected-fingerprints.ndjson" "$stage/expected-fingerprints.ndjson"
	printf 'not-a-key\n' >"$stage/decernor-minisign.pub"
	printf 'not-a-key\n' >"$stage/decernor-release-signing-key.asc"
	# extra field: still two lines but third token
	awk '{print $0, "extra"}' "$ROOT/keys/expected-fingerprints.txt" >"$stage/expected-fingerprints.txt"
	if "$VERIFY" "$stage" >/dev/null 2>&1; then
		fail "verify accepted extra TXT token"
	else
		pass "verify refuses extra TXT token"
	fi
	cp "$ROOT/keys/expected-fingerprints.txt" "$stage/expected-fingerprints.txt"
	# extra NDJSON record
	cat "$ROOT/keys/expected-fingerprints.ndjson" "$ROOT/keys/expected-fingerprints.ndjson" >"$stage/expected-fingerprints.ndjson"
	if "$VERIFY" "$stage" >/dev/null 2>&1; then
		fail "verify accepted extra NDJSON record"
	else
		pass "verify refuses extra NDJSON record"
	fi
	rm -rf "$stage"
fi

if [ "$FAIL" -ne 0 ]; then
	note "$FAIL ceremony probe(s) failed"
	exit 1
fi
note "all ceremony probes passed"
