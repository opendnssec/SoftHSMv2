/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanChaCha20Poly1305.cpp

 Botan ChaCha20-Poly1305 implementation
 *****************************************************************************/

#include "config.h"
#include "BotanChaCha20Poly1305.h"

std::string BotanChaCha20Poly1305::getCipher() const
{
	if (currentKey == NULL) return "";

	// ChaCha20-Poly1305 requires a 256-bit key
	if (currentKey->getBitLen() != 256)
	{
		ERROR_MSG("Invalid ChaCha20-Poly1305 currentKey length (%d bits)", currentKey->getBitLen());

		return "";
	}

	if (currentCipherMode != SymMode::ChaCha20Poly1305)
	{
		ERROR_MSG("Invalid ChaCha20-Poly1305 cipher mode %i", currentCipherMode);

		return "";
	}

	return "ChaCha20Poly1305";
}

size_t BotanChaCha20Poly1305::getBlockSize() const
{
	// ChaCha20-Poly1305 is a stream cipher
	return 1;
}
