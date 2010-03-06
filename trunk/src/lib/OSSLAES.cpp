/* $Id$ */

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
 OSSLAES.cpp

 OpenSSL AES implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLAES.h"
#include <algorithm>

const EVP_CIPHER* OSSLAES::getCipher() const
{
	// Check currentKey bit length; AES only supports 128 or 256 bit currentKeys
	if ((currentKey->getBitLen() != 128) && (currentKey->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES currentKey length (%d bits)", currentKey->getBitLen());

		return NULL;
	}

	// Determine the cipher mode
	if (currentCipherMode == "cbc")
	{
		if (currentKey->getBitLen() == 128)
		{
			return EVP_aes_128_cbc();
		}
		else if (currentKey->getBitLen() == 256)
		{
			return EVP_aes_256_cbc();
		}
	}
	else if (currentCipherMode == "ecb")
	{
		if (currentKey->getBitLen() == 128)
		{
			return EVP_aes_128_ecb();
		}
		else if (currentKey->getBitLen() == 256)
		{
			return EVP_aes_256_ecb();
		}
	}

	ERROR_MSG("Invalid AES cipher mode %s", currentCipherMode.c_str());

	return NULL;
}

size_t OSSLAES::getBlockSize() const
{
	return 8;
}

