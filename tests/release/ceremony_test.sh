#!/usr/bin/env bash
# Focused probes for the release ceremony boundary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GEN="$ROOT/scripts/generate-checksums.sh"
VERIFY="$ROOT/scripts/verify-public-keys.sh"
VALIDATE="$ROOT/scripts/validate-pin-pair.sh"
INSTALL="$ROOT/scripts/atomic-install-pair.sh"
FAIL=0

note() { printf '%s\n' "$*"; }
fail() { note "FAIL: $*"; FAIL=$((FAIL + 1)); }
pass() { note "PASS: $*"; }

expect_err() {
	local haystack=$1
	local needle=$2
	local label=$3
	if printf '%s\n' "$haystack" | grep -Fq "$needle"; then
		pass "$label"
	else
		fail "$label (wanted: $needle; got: $haystack)"
	fi
}

# notes+pins without archives must fail.
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

# staged TXT != keys/ must fail (when keys/ exist).
if [ -f "$ROOT/keys/expected-fingerprints.txt" ]; then
	stage="$(mktemp -d)"
	cp "$ROOT/keys/expected-fingerprints.txt" "$stage/expected-fingerprints.txt"
	cp "$ROOT/keys/expected-fingerprints.ndjson" "$stage/expected-fingerprints.ndjson"
	printf 'not-a-key\n' >"$stage/decernor-minisign.pub"
	printf 'not-a-key\n' >"$stage/decernor-release-signing-key.asc"
	printf 'gpg DEADBEEF\nminisign deadbeef\n' >"$stage/expected-fingerprints.txt"
	out="$("$VERIFY" "$stage" 2>&1)" && status=0 || status=$?
	if [ "$status" -eq 0 ]; then
		fail "verify accepted staged TXT that differs from keys/"
	else
		expect_err "$out" "staged TXT differs from keys/expected-fingerprints.txt" \
			"verify refuses staged TXT that differs from keys/"
	fi
	rm -rf "$stage"
else
	note "SKIP: keys/ pins not in tree"
fi

# first-use second-install failure must not leave a half pair.
pair="$(mktemp -d)"
empty="$(mktemp -d)"
printf '{}\n{}\n' >"$pair/expected-fingerprints.ndjson"
printf 'gpg A\nminisign B\n' >"$pair/expected-fingerprints.txt"
if DECERNOR_TEST_FAIL_SECOND=1 "$INSTALL" "$pair" "$empty" >/dev/null 2>&1; then
	fail "first-use second-install failure returned success"
else
	if [ -e "$empty/expected-fingerprints.ndjson" ] || [ -e "$empty/expected-fingerprints.txt" ]; then
		fail "first-use rollback left a half pair"
	else
		pass "first-use second-install failure leaves no dest files"
	fi
fi
rm -rf "$pair" "$empty"

# signal after first dest install must roll back (install-window trap).
pair="$(mktemp -d)"
empty="$(mktemp -d)"
printf '{}\n{}\n' >"$pair/expected-fingerprints.ndjson"
printf 'gpg A\nminisign B\n' >"$pair/expected-fingerprints.txt"
set +e
DECERNOR_TEST_KILL_AFTER_FIRST=1 "$INSTALL" "$pair" "$empty" >/dev/null 2>&1
set -e
if [ -e "$empty/expected-fingerprints.ndjson" ] || [ -e "$empty/expected-fingerprints.txt" ] ||
	[ -e "$empty/expected-fingerprints.ndjson.new" ] || [ -e "$empty/expected-fingerprints.txt.new" ]; then
	fail "signal-after-first-install left dest residue"
else
	pass "signal-after-first-install leaves no dest files"
fi
rm -rf "$pair" "$empty"

# extra TXT token: helper must emit the two-field error (not keys/ cmp).
if [ -f "$ROOT/keys/expected-fingerprints.txt" ]; then
	mut="$(mktemp -d)"
	awk '{print $0, "extra"}' "$ROOT/keys/expected-fingerprints.txt" >"$mut/expected-fingerprints.txt"
	cp "$ROOT/keys/expected-fingerprints.ndjson" "$mut/expected-fingerprints.ndjson"
	out="$("$VALIDATE" "$mut/expected-fingerprints.txt" "$mut/expected-fingerprints.ndjson" 2>&1)" && status=0 || status=$?
	if [ "$status" -eq 0 ]; then
		fail "validate accepted extra TXT token"
	else
		expect_err "$out" "exactly two fields" "validate refuses extra TXT token"
	fi
	rm -rf "$mut"
fi

# extra NDJSON record: helper must emit the two-record error (not keys/ cmp).
if [ -f "$ROOT/keys/expected-fingerprints.ndjson" ]; then
	mut="$(mktemp -d)"
	cp "$ROOT/keys/expected-fingerprints.txt" "$mut/expected-fingerprints.txt"
	cat "$ROOT/keys/expected-fingerprints.ndjson" "$ROOT/keys/expected-fingerprints.ndjson" \
		>"$mut/expected-fingerprints.ndjson"
	out="$("$VALIDATE" "$mut/expected-fingerprints.txt" "$mut/expected-fingerprints.ndjson" 2>&1)" && status=0 || status=$?
	if [ "$status" -eq 0 ]; then
		fail "validate accepted extra NDJSON record"
	else
		expect_err "$out" "exactly two records" "validate refuses extra NDJSON record"
	fi
	rm -rf "$mut"
fi

if [ "$FAIL" -ne 0 ]; then
	note "$FAIL ceremony probe(s) failed"
	exit 1
fi
note "all ceremony probes passed"
