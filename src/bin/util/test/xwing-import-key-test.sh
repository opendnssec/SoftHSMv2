#! /bin/bash
# Copyright (c) 2026 SoftHSMv2 contributors
# SPDX-License-Identifier: BSD-2-Clause

CI_TEST_ENABLED="true"
ALGO_NAME="X-Wing"
OPENSSL_ALGO="X-Wing"
TOKEN_DIR_NAME="tokens-xwing"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PKCS#8 encoding of the first private seed in the existing X-Wing test vectors.
KEY_FILE_SOURCE="$SCRIPT_DIR/xwing-test-key.pem"
. "$SCRIPT_DIR/import-key-test-common.sh"
