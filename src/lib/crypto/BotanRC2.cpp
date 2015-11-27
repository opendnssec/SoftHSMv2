/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 BotanRC2.cpp

 Botan (3)RC2 implementation
 *****************************************************************************/

#include "config.h"
#include "BotanRC2.h"
#include <algorithm>

bool BotanRC2::wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("RC2 does not support key wrapping");

	return false;
}

bool BotanRC2::unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("RC2 does not support key unwrapping");

	return false;
}

std::string BotanRC2::getCipher() const
{
	std::string algo;
	std::string mode;
	std::string padding;

	if (currentKey == NULL) return "";

	if ((currentKey->getBitLen() % 8) != 0 ||
            (currentKey->getBitLen() < 8 || currentKey->getBitLen() > 1024))
        {
		ERROR_MSG("Invalid RC2 currentKey length (%d bits)", currentKey->getBitLen());
		return "";
	}
        else
        {
		algo = "RC2";
	}

	// Determine the cipher mode
	switch (currentCipherMode)
	{
		case SymMode::CBC:
			mode = "CBC";
			break;
		case SymMode::CFB:
			mode = "CFB";
			break;
		case SymMode::ECB:
			mode = "ECB";
			break;
		case SymMode::OFB:
			mode = "OFB";
			break;
		default:
			ERROR_MSG("Invalid RC2 cipher mode %i", currentCipherMode);

			return "";
	}

	// Check padding mode
	if (currentCipherMode == SymMode::OFB ||
	    currentCipherMode == SymMode::CFB)
	{
		padding = "";
	}
	else if (currentPaddingMode)
	{
		padding = "/PKCS7";
	}
	else
	{
		padding = "/NoPadding";
	}

	return algo + "/" + mode + padding;
}

size_t BotanRC2::getBlockSize() const
{
	// The block size is 64 bits
	return 64 >> 3;
}

