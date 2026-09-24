#!/usr/bin/env bash
# Run the built binary outside its repository with synthetic public material.
set -euo pipefail

BIN=${1:?binary path required}
TMP=$(mktemp -d "${TMPDIR:-/var/tmp}/decernor-verify.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
cp "$BIN" "$TMP/decernor"
cat >"$TMP/gpg" <<'SH'
#!/bin/sh
case " $* " in
  *" --list-packets "*)
    case "${FAKE_GPG_PACKET_MODE:-}" in
      public) printf ':public key packet:\n'; exit 0 ;;
      revoked) printf ':public key packet:\n:signature packet:\n sigclass 0x20\n'; exit 0 ;;
      subkey_revoked) printf ':public key packet:\n:public sub key packet:\n:signature packet:\n sigclass 0x28\n reason for revocation\n'; exit 0 ;;
      indicator_only) printf ':public key packet:\n:signature packet:\n reason for revocation\n'; exit 0 ;;
      cert) printf ':signature packet:\n sigclass 0x20\n'; exit 0 ;;
      secret) printf ':secret key packet:\n:signature packet:\n sigclass 0x20\n'; exit 0 ;;
    esac
    exit 1 ;;
  *" --with-colons "*)
    case "${FAKE_GPG_MODE:-match}" in
      fail) exit 1 ;;
      revoked) printf 'pub:r:3072:1:0000111122223333:1000:3000:::::\nfpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:\n' ;;
      revoked_mismatch) printf 'pub:r:3072:1:1111222233334444:1000:3000:::::\nfpr:::::::::BBBBCCCCDDDDEEEEFFFF00001111222233334444:\n' ;;
      unverified) printf 'pub:u:3072:1:0000111122223333:1000:3000:::::\nfpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:\n' ;;
      mismatch) printf 'pub:u:3072:1:1111222233334444:1000:3000:::::\nfpr:::::::::BBBBCCCCDDDDEEEEFFFF00001111222233334444:\n' ;;
      expired) printf 'pub:e:3072:1:0000111122223333:1000:1500:::::\nfpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:\n' ;;
      *) printf 'pub:u:3072:1:0000111122223333:1000:3000:::::\nfpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:\n' ;;
    esac ;;
esac
SH
chmod +x "$TMP/gpg"
python3 - "$TMP" <<'PY'
import base64, hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
gpg = 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333'
blob = b'Ed12345678' + bytes(32)
mini = hashlib.sha256(blob).hexdigest()
(root / 'public.asc').write_text('-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n')
(root / 'public.pub').write_text('untrusted comment: minisign public key\n' + base64.b64encode(blob).decode() + '\n')
(root / 'anchors.txt').write_text(f'gpg {gpg}\nminisign {mini}\n')
records = [
    dict(schema_version='v0', kind='gpg', class_='public', algorithm='openpgp-fingerprint', fingerprint=gpg,
         fingerprint_scheme='openpgp-fingerprint-v1', key_id=gpg[-16:], key_role='primary', confidence='high'),
    dict(schema_version='v0', kind='minisign', class_='public', algorithm='sha256', fingerprint=mini,
         fingerprint_scheme='minisign-public-blob-sha256-v1', confidence='high'),
]
for record in records:
    record['class'] = record.pop('class_')
(root / 'anchors.ndjson').write_text(''.join(json.dumps(record, separators=(',', ':')) + '\n' for record in records))
PY

cd "$TMP"
if [ -e schemas ]; then
    echo 'standalone fixture unexpectedly has schemas directory' >&2
    exit 1
fi
common=(./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg public.asc --minisign public.pub --as-of 1970-01-01T00:33:20Z)
check_code() {
    want=$1
    shift
    set +e
    PATH="${VERIFY_PATH:-$TMP:$PATH}" "$@" >out 2>err
    got=$?
    set -e
    if [ "$got" -ne "$want" ]; then
        echo "verify exit $got; wanted $want" >&2
        exit 1
    fi
    if [ "$want" -ge 2 ] && [ "$want" -le 4 ] && [ -s out ]; then
        echo "verify wrote stdout on exit $want" >&2
        exit 1
    fi
    if { [ "$want" -eq 0 ] || [ "$want" -eq 5 ] || [ "$want" -eq 6 ]; } && [ ! -s out ]; then
        echo "verify omitted records on exit $want" >&2
        exit 1
    fi
}
check_code 0 "${common[@]}"
cp out first.out
check_code 0 "${common[@]}"
cmp -s first.out out
check_code 0 "${common[@]}" --format json
python3 - <<'PY'
import json
records = json.load(open('out'))
assert [record['kind'] for record in records] == ['gpg', 'minisign']
for record in records:
    assert 'fingerprint' not in record and 'path' not in record
PY
cp public.pub ./verify
PATH="$TMP:$PATH" ./decernor fingerprint ./verify --kind minisign --path-mode none >out 2>err
test -s out
check_code 2 ./decernor fingerprint verify --anchors anchors.txt
check_code 2 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg public.asc --minisign public.pub --as-of 2026-09-24
check_code 3 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg public.asc --minisign gpg --as-of 1970-01-01T00:33:20Z
cp anchors.txt anchors.good
printf 'invalid\n' >anchors.txt
check_code 4 "${common[@]}"
mv anchors.good anchors.txt
FAKE_GPG_MODE=mismatch check_code 5 "${common[@]}"
FAKE_GPG_MODE=expired check_code 6 "${common[@]}"
check_code 6 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg public.asc --minisign public.pub --as-of 0001-01-01T00:00:00Z
FAKE_GPG_MODE=fail check_code 2 "${common[@]}"
FAKE_GPG_PACKET_MODE=revoked FAKE_GPG_MODE=revoked check_code 6 "${common[@]}" --allow-expired
FAKE_GPG_PACKET_MODE=revoked FAKE_GPG_MODE=revoked_mismatch check_code 5 "${common[@]}"
FAKE_GPG_PACKET_MODE=revoked FAKE_GPG_MODE=unverified check_code 3 "${common[@]}"
FAKE_GPG_PACKET_MODE=cert FAKE_GPG_MODE=revoked check_code 3 "${common[@]}"
FAKE_GPG_PACKET_MODE=secret FAKE_GPG_MODE=revoked check_code 3 "${common[@]}"
FAKE_GPG_PACKET_MODE=subkey_revoked check_code 0 "${common[@]}"
FAKE_GPG_PACKET_MODE=indicator_only check_code 3 "${common[@]}"
cp public.asc revocation.asc
check_code 0 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg revocation.asc --minisign public.pub --as-of 1970-01-01T00:33:20Z
mkdir no-gpg-path
printf '\231\001\002\003' >public.gpg
FAKE_GPG_PACKET_MODE=public check_code 0 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg public.gpg --minisign public.pub --as-of 1970-01-01T00:33:20Z
VERIFY_PATH="$TMP/no-gpg-path" check_code 2 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg public.gpg --minisign public.pub --as-of 1970-01-01T00:33:20Z
VERIFY_PATH="$TMP/no-gpg-path" check_code 2 "${common[@]}"
VERIFY_PATH="$TMP/no-gpg-path" check_code 2 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg revocation.asc --minisign public.pub --as-of 1970-01-01T00:33:20Z
printf 'not an OpenPGP key\n' >non-key.gpg
FAKE_GPG_MODE=fail check_code 3 ./decernor fingerprint verify --anchors anchors.txt --anchors-ndjson anchors.ndjson --gpg non-key.gpg --minisign public.pub --as-of 1970-01-01T00:33:20Z
echo 'standalone fingerprint verify passed'
