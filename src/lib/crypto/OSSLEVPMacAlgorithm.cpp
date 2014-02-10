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

// Destructor
OSSLEVPMacAlgorithm::~OSSLEVPMacAlgorithm()
{
	HMAC_CTX_cleanup(&curCTX);
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
	HMAC_CTX_init(&curCTX);

	// Initialize EVP signing
	if (!HMAC_Init(&curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), getEVPHash()))
	{
		ERROR_MSG("HMAC_Init failed");

		HMAC_CTX_cleanup(&curCTX);

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

	if (!HMAC_Update(&curCTX, dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("HMAC_Update failed");

		HMAC_CTX_cleanup(&curCTX);

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

	if (!HMAC_Final(&curCTX, &signature[0], &outLen))
	{
		ERROR_MSG("HMAC_Final failed");

		HMAC_CTX_cleanup(&curCTX);

		return false;
	}

	signature.resize(outLen);

	HMAC_CTX_cleanup(&curCTX);

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
	HMAC_CTX_init(&curCTX);

	// Initialize EVP signing
	if (!HMAC_Init(&curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), getEVPHash()))
	{
		ERROR_MSG("HMAC_Init failed");

		HMAC_CTX_cleanup(&curCTX);

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

	if (!HMAC_Update(&curCTX, originalData.const_byte_str(), originalData.size()))
	{
		ERROR_MSG("HMAC_Update failed");

		HMAC_CTX_cleanup(&curCTX);

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

	if (!HMAC_Final(&curCTX, &macResult[0], &outLen))
	{
		ERROR_MSG("HMAC_Final failed");

		HMAC_CTX_cleanup(&curCTX);

		return false;
	}

	HMAC_CTX_cleanup(&curCTX);

	return macResult == signature;
}
