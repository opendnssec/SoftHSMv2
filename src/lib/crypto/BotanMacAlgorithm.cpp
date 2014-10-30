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
 BotanMacAlgorithm.cpp

 Botan MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "BotanMacAlgorithm.h"
#include "salloc.h"

#include <botan/symkey.h>
#include <botan/botan.h>

// Constructor
BotanMacAlgorithm::BotanMacAlgorithm()
{
	hmac = NULL;
}

// Destructor
BotanMacAlgorithm::~BotanMacAlgorithm()
{
	delete hmac;
	hmac = NULL;
}

// Signing functions
bool BotanMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Determine the hash name
	std::string hashName = getHash();

	if (hashName == "")
	{
		ERROR_MSG("Invalid sign hmac hash");

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	// Allocate the context
	try
	{
		hmac = new Botan::HMAC(Botan::get_hash(hashName));
		hmac->set_key(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the sign hmac token");

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		delete hmac;
		hmac = NULL;

		return false;
	}

	return true;
}

bool BotanMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		delete hmac;
		hmac = NULL;

		return false;
	}

	try
	{
		if (dataToSign.size() != 0)
		{
			hmac->update(dataToSign.const_byte_str(),
				     dataToSign.size());
		}
	}
	catch (...)
	{
		ERROR_MSG("Failed to update the sign hmac token");

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		delete hmac;
		hmac = NULL;

		return false;
	}

	return true;
}

bool BotanMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	// Perform the signature operation
#if BOTAN_VERSION_MINOR == 11
	Botan::secure_vector<Botan::byte> signResult;
#else
	Botan::SecureVector<Botan::byte> signResult;
#endif
	try
	{
		signResult = hmac->final();
	}
	catch (...)
	{
		ERROR_MSG("Could not sign the data");

		delete hmac;
		hmac = NULL;

		return false;
	}

	// Return the result
	signature.resize(signResult.size());
#if BOTAN_VERSION_MINOR == 11
	memcpy(&signature[0], signResult.data(), signResult.size());
#else
	memcpy(&signature[0], signResult.begin(), signResult.size());
#endif

	delete hmac;
	hmac = NULL;

	return true;
}

// Verification functions
bool BotanMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Determine the hash name
	std::string hashName = getHash();

	if (hashName == "")
	{
		ERROR_MSG("Invalid verify hmac hash");

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	// Allocate the context
	try
	{
		hmac = new Botan::HMAC(Botan::get_hash(hashName));
		hmac->set_key(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the verify hmac token");

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		delete hmac;
		hmac = NULL;

		return false;
	}

	return true;
}

bool BotanMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		delete hmac;
		hmac = NULL;

		return false;
	}

	try
	{
		if (originalData.size() != 0)
		{
			hmac->update(originalData.const_byte_str(),
				     originalData.size());
		}
	}
	catch (...)
	{
		ERROR_MSG("Failed to update the verify hmac token");

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		delete hmac;
		hmac = NULL;

		return false;
	}

	return true;
}

bool BotanMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	// Perform the verify operation
#if BOTAN_VERSION_MINOR == 11
	Botan::secure_vector<Botan::byte> macResult;
#else
	Botan::SecureVector<Botan::byte> macResult;
#endif
	try
	{
		macResult = hmac->final();
	}
	catch (...)
	{
		ERROR_MSG("Failed to verify the data");

		delete hmac;
		hmac = NULL;

		return false;
	}

	if (macResult.size() != signature.size())
	{
		ERROR_MSG("Bad verify result size");

		delete hmac;
		hmac = NULL;

		return false;
	}

	delete hmac;
	hmac = NULL;

#if BOTAN_VERSION_MINOR == 11
	return memcmp(&signature[0], macResult.data(), macResult.size()) == 0;
#else
	return memcmp(&signature[0], macResult.begin(), macResult.size()) == 0;
#endif
}
