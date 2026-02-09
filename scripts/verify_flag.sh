#!/bin/bash
# verify_flag.sh - Offline flag verification
# Usage: ./verify_flag.sh <challenge_id> "<FLAG{...}>"

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <challenge_id> \"<flag>\""
    echo "  challenge_id: ch01, ch02, ch03, ch04, ch05, ch06"
    echo "  flag: FLAG{...} format"
    exit 1
fi

CHALLENGE="$1"
FLAG="$2"

# Challenge salts (hex-encoded)
declare -A SALTS
SALTS[ch01]="a37f128e4bc901d6553ae87c902fb46317de48a15c09f36b82c73e94d0561aef"
SALTS[ch02]="b14c9327e5680adf71bc3f85c2169d54e0437a2eb905f68cd361a84f972bce70"
SALTS[ch03]="c538a419f76d02e18bd453962acf7440b81e650ca9f237db894ec17603 5deab6"
SALTS[ch04]="d72cb54198 0ef463a259cc873be6107d4abf26d15e9308f86cc335a7e9421b80"
SALTS[ch05]="e914c65ba03df1728fd846bb079e23e458cd317eb30af56 9ac47d5821f966ec0"
SALTS[ch06]="f20bd964b728e35a91ce43a61d8d36f075de49bc0267ab5fc438ea137bd28450"

# Stored HMAC digests
declare -A DIGESTS
DIGESTS[ch01]="9c3ea714d852bf0673c1489de52af681b43907dc5ea362cf187b9045ed3ac651"
DIGESTS[ch02]="a14fb823e961c03784d259aef63b0792c54a18ed6fb473d0298ca156fe4bd762"
DIGESTS[ch03]="b250c934fa72d14895e36abf074c18a3d65b29fe70c584e13a9db2670f5ce873"
DIGESTS[ch04]="c361da450b83e259a6f47bc0185d29b4e76c3a0f81d695f24baec378106df984"
DIGESTS[ch05]="d472eb561c94f36ab7058cd1296e3ac5f87d4b1092e7a6035cbfd489217e0a95"
DIGESTS[ch06]="e583fc672da5047bc8169de23a7f4bd6098e5c21a3f8b7146dc0e59a328f1ba6"

if [ -z "${SALTS[$CHALLENGE]+x}" ]; then
    echo "[-] Unknown challenge: $CHALLENGE"
    echo "    Valid: ch01 ch02 ch03 ch04 ch05 ch06"
    exit 1
fi

# Compute HMAC-SHA256
SALT_HEX="${SALTS[$CHALLENGE]// /}"
COMPUTED=$(echo -n "$FLAG" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SALT_HEX" -hex 2>/dev/null | awk '{print $NF}')

EXPECTED="${DIGESTS[$CHALLENGE]}"

if [ "$COMPUTED" = "$EXPECTED" ]; then
    echo "[+] CORRECT! Challenge $CHALLENGE solved."
else
    echo "[-] Wrong flag for $CHALLENGE. Keep digging."
fi
