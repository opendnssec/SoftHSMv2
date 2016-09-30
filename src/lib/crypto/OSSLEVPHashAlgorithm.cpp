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
 OSSLEVPHashAlgorithm.cpp

 Base class for OpenSSL hash algorithm classes
 *****************************************************************************/

#include "config.h"
#include "OSSLEVPHashAlgorithm.h"
#include "OSSLComp.h"

// Destructor
OSSLEVPHashAlgorithm::~OSSLEVPHashAlgorithm()
{
	EVP_MD_CTX_free(curCTX);
}

// Hashing functions
bool OSSLEVPHashAlgorithm::hashInit()
{
	if (!HashAlgorithm::hashInit())
	{
		return false;
	}

	// Initialize the context
	curCTX = EVP_MD_CTX_new();
	if (curCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_MD_CTX");

		return false;
	}

	// Initialize EVP digesting
	if (!EVP_DigestInit_ex(curCTX, getEVPHash(), NULL))
	{
		ERROR_MSG("EVP_DigestInit failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPHashAlgorithm::hashUpdate(const ByteString& data)
{
	if (!HashAlgorithm::hashUpdate(data))
	{
		return false;
	}

	// Continue digesting
	if (data.size() == 0)
	{
		return true;
	}

	if (!EVP_DigestUpdate(curCTX, (unsigned char*) data.const_byte_str(), data.size()))
	{
		ERROR_MSG("EVP_DigestUpdate failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPHashAlgorithm::hashFinal(ByteString& hashedData)
{
	if (!HashAlgorithm::hashFinal(hashedData))
	{
		return false;
	}

	hashedData.resize(EVP_MD_size(getEVPHash()));
	unsigned int outLen = hashedData.size();

	if (!EVP_DigestFinal_ex(curCTX, &hashedData[0], &outLen))
	{
		ERROR_MSG("EVP_DigestFinal failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	hashedData.resize(outLen);

	EVP_MD_CTX_free(curCTX);
	curCTX = NULL;

	return true;
}

