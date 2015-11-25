/*
 * Copyright (c) 2010 SURFnet bv
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
 OSSLRC2.cpp

 OpenSSL (3)RC2 implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLRC2.h"
#include <algorithm>
#include "odd.h"

bool OSSLRC2::wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("RC2 does not support key wrapping");

	return false;
}

bool OSSLRC2::unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("RC2 does not support key unwrapping");

	return false;
}

const EVP_CIPHER* OSSLRC2::getCipher() const
{
	if (currentKey == NULL) return NULL;

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
	if (currentCipherMode == SymMode::CBC)
	{
		return EVP_rc2_cbc();
	}
	else if (currentCipherMode == SymMode::ECB)
	{
		return EVP_rc2_ecb();
	}
	else if (currentCipherMode == SymMode::OFB)
	{
		return EVP_rc2_ofb();
	}
	else if (currentCipherMode == SymMode::CFB)
	{
		return EVP_rc2_cfb();
	}

	ERROR_MSG("Invalid RC2 cipher mode %i", currentCipherMode);

	return NULL;
}

size_t OSSLRC2::getBlockSize() const
{
	// The block size is 64 bits
	return 64 >> 3;
}

