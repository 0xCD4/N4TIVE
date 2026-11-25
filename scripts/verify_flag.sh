#!/bin/bash
# verify_flag.sh - Offline flag verification
# Usage: ./verify_flag.sh <challenge_id> "<FLAG{...}>"

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <challenge_id> \"<flag>\""
    echo "  challenge_id: ch01 to ch08"
    echo "  flag: FLAG{...} format"
    exit 1
fi

CHALLENGE="$1"
FLAG="$2"

# Challenge salts and stored HMAC digests (hex-encoded).
# Same values as app/src/main/jni/flag_core.c.
# Written by scripts/gen_flags.py. Do not edit by hand.
declare -A SALTS
declare -A DIGESTS
# gen_flags begin tables
SALTS[ch01]="a37f128e4bc901d6553ae87c902fb46317de48a15c09f36b82c73e94d0561aef"
SALTS[ch02]="b14c9327e5680adf71bc3f85c2169d54e0437a2eb905f68cd361a84f972bce70"
SALTS[ch03]="c538a419f76d02e18bd453962acf7440b81e650ca9f237db894ec176035deab6"
SALTS[ch04]="d72cb541980ef463a259cc873be6107d4abf26d15e9308f86cc335a7e9421b80"
SALTS[ch05]="e914c65ba03df1728fd846bb079e23e458cd317eb30af569ac47d5821f966ec0"
SALTS[ch06]="f20bd964b728e35a91ce43a61d8d36f075de49bc0267ab5fc438ea137bd28450"
SALTS[ch07]="1f7ebd3376c75bd536c539531d7460204cd90699b8f21bff9e56c3ff82f1331b"
SALTS[ch08]="f736485ded0f2abd0c686b0d9013487abd54e3334c9729f2aefd7256306c67d5"
DIGESTS[ch01]="ea054f63bdf30bfeab40e91bb7adcb487433db66a8dbcb528472f9ec5b8342cc"
DIGESTS[ch02]="d87a5f502fe4f14c4e45d8d121bae8e98e9eb9862c71c47b67553f4c769653a1"
DIGESTS[ch03]="fafced114fc4f1ce14ae22cf6e63799110041a14e8ad3210f561b082a07038f5"
DIGESTS[ch04]="1e5cc26c6186abef6a25f2b9e36818a2d8d52816ef03f959e1fa339a343945dc"
DIGESTS[ch05]="504d9b67f93b0381fc1f0768296aa23ffe29b96c5e08dd6bdb3c6f4037f2e428"
DIGESTS[ch06]="0cd6a3a2ba1ede1bbdcd21d736a985ee5204fa71f37d83fd2d3577148ba7c9ec"
DIGESTS[ch07]="a319ec9ea60d97cb33b66f47b5a2e5fec731bc600e54cf4afb0bbafd145c73f9"
DIGESTS[ch08]="f4489b668d2201ee7e22aff132037cc583e3c73bedac7254919a90d9c0edadee"
# gen_flags end tables

if [ -z "${SALTS[$CHALLENGE]+x}" ]; then
    echo "[-] Unknown challenge: $CHALLENGE"
    echo "    Valid: ch01 ch02 ch03 ch04 ch05 ch06 ch07 ch08"
    exit 1
fi

# Compute HMAC-SHA256
SALT_HEX="${SALTS[$CHALLENGE]}"
COMPUTED=$(echo -n "$FLAG" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SALT_HEX" -hex 2>/dev/null | awk '{print $NF}')

EXPECTED="${DIGESTS[$CHALLENGE]}"

if [ "$COMPUTED" = "$EXPECTED" ]; then
    echo "[+] CORRECT! Challenge $CHALLENGE solved."
else
    echo "[-] Wrong flag for $CHALLENGE. Keep digging."
fi
