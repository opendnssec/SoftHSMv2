#! /bin/bash
# Copyright (c) 2026 SoftHSMv2 contributors
# SPDX-License-Identifier: BSD-2-Clause

CI_TEST_ENABLED="true"
ALGO_NAME="Falcon"
OPENSSL_ALGO="falcon512"
TOKEN_DIR_NAME="tokens-falcon512"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/import-key-test-common.sh"
