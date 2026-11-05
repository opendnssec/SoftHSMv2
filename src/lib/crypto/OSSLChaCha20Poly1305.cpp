/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 OSSLChaCha20Poly1305.cpp

 OpenSSL ChaCha20-Poly1305 implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLChaCha20Poly1305.h"

const EVP_CIPHER* OSSLChaCha20Poly1305::getCipher() const
{
	if (currentCipherMode != SymMode::ChaCha20Poly1305)
	{
		ERROR_MSG("Invalid cipher mode %i for ChaCha20-Poly1305", currentCipherMode);
		return NULL;
	}

	// ChaCha20-Poly1305 requires a 256-bit key
	if (currentKey == NULL || currentKey->getBitLen() != 256)
	{
		ERROR_MSG("ChaCha20-Poly1305 requires a 256-bit key");
		return NULL;
	}

	return EVP_chacha20_poly1305();
}
