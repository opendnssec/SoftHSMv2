/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <openssl/evp.h>

int main()
{
    const char *names[] = { "falcon512", "falcon1024" };
    unsigned int i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, names[i], NULL);
        if (ctx == NULL)
            return 1;
        EVP_PKEY_CTX_free(ctx);
    }
    return 0;
}
