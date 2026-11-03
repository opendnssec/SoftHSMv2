/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <openssl/evp.h>

int main()
{
    EVP_PKEY_CTX *mlkem;
    EVP_PKEY_CTX *x25519;

    mlkem = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    x25519 = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
    if (mlkem == NULL || x25519 == NULL)
    {
        EVP_PKEY_CTX_free(mlkem);
        EVP_PKEY_CTX_free(x25519);
        return 1;
    }

    EVP_PKEY_CTX_free(mlkem);
    EVP_PKEY_CTX_free(x25519);
    return 0;
}
