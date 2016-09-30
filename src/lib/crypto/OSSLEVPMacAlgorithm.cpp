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

// TODO: Store context in securely allocated memory

/*****************************************************************************
 OSSLEVPMacAlgorithm.cpp

 OpenSSL MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLEVPMacAlgorithm.h"
#include "OSSLComp.h"

// Destructor
OSSLEVPMacAlgorithm::~OSSLEVPMacAlgorithm()
{
	HMAC_CTX_free(curCTX);
}

// Signing functions
bool OSSLEVPMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Initialize the context
	curCTX = HMAC_CTX_new();
	if (curCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for HMAC_CTX");

		return false;
	}

	// Initialize EVP signing
	if (!HMAC_Init_ex(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), getEVPHash(), NULL))
	{
		ERROR_MSG("HMAC_Init failed");

		HMAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	// The GOST implementation in OpenSSL will segfault if we update with zero length.
	if (dataToSign.size() == 0) return true;

	if (!HMAC_Update(curCTX, dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("HMAC_Update failed");

		HMAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	signature.resize(EVP_MD_size(getEVPHash()));
	unsigned int outLen = signature.size();

	if (!HMAC_Final(curCTX, &signature[0], &outLen))
	{
		ERROR_MSG("HMAC_Final failed");

		HMAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	signature.resize(outLen);

	HMAC_CTX_free(curCTX);
	curCTX = NULL;

	return true;
}

// Verification functions
bool OSSLEVPMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Initialize the context
	curCTX = HMAC_CTX_new();
	if (curCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for HMAC_CTX");

		return false;
	}

	// Initialize EVP signing
	if (!HMAC_Init_ex(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), getEVPHash(), NULL))
	{
		ERROR_MSG("HMAC_Init failed");

		HMAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	// The GOST implementation in OpenSSL will segfault if we update with zero length.
	if (originalData.size() == 0) return true;

	if (!HMAC_Update(curCTX, originalData.const_byte_str(), originalData.size()))
	{
		ERROR_MSG("HMAC_Update failed");

		HMAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString macResult;
	unsigned int outLen = EVP_MD_size(getEVPHash());
	macResult.resize(outLen);

	if (!HMAC_Final(curCTX, &macResult[0], &outLen))
	{
		ERROR_MSG("HMAC_Final failed");

		HMAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	HMAC_CTX_free(curCTX);
	curCTX = NULL;

	return macResult == signature;
}
