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
#include <botan/mac.h>
#include <botan/botan.h>
#include <botan/version.h>
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,26)
#include <botan/lookup.h>
#endif

// Constructor
BotanMacAlgorithm::BotanMacAlgorithm()
{
	mac = NULL;
}

// Destructor
BotanMacAlgorithm::~BotanMacAlgorithm()
{
	delete mac;
	mac = NULL;
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
	std::string macName = getAlgorithm();

	if (macName == "")
	{
		ERROR_MSG("Invalid sign mac algorithm");

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	// Allocate the context
	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,26)
		mac = Botan::MessageAuthenticationCode::create(macName).release();
#else
		mac = Botan::get_mac(macName);
#endif
		mac->set_key(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	}
	catch (std::exception &e)
	{
		ERROR_MSG("Failed to create the sign mac token: %s", e.what());

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		delete mac;
		mac = NULL;

		return false;
	}

	return true;
}

bool BotanMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		delete mac;
		mac = NULL;

		return false;
	}

	try
	{
		if (dataToSign.size() != 0)
		{
			mac->update(dataToSign.const_byte_str(),
				     dataToSign.size());
		}
	}
	catch (...)
	{
		ERROR_MSG("Failed to update the sign mac token");

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		delete mac;
		mac = NULL;

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
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	Botan::secure_vector<Botan::byte> signResult;
#else
	Botan::SecureVector<Botan::byte> signResult;
#endif
	try
	{
		signResult = mac->final();
	}
	catch (...)
	{
		ERROR_MSG("Could not sign the data");

		delete mac;
		mac = NULL;

		return false;
	}

	// Return the result
	signature.resize(signResult.size());
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	memcpy(&signature[0], signResult.data(), signResult.size());
#else
	memcpy(&signature[0], signResult.begin(), signResult.size());
#endif

	delete mac;
	mac = NULL;

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
	std::string macName = getAlgorithm();

	if (macName == "")
	{
		ERROR_MSG("Invalid verify mac algorithm");

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	// Allocate the context
	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,26)
		mac = Botan::MessageAuthenticationCode::create(macName).release();
#else
		mac = Botan::get_mac(macName);
#endif
		mac->set_key(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	}
	catch (std::exception &e)
	{
		ERROR_MSG("Failed to create the verify mac token: %s", e.what());

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		delete mac;
		mac = NULL;

		return false;
	}

	return true;
}

bool BotanMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		delete mac;
		mac = NULL;

		return false;
	}

	try
	{
		if (originalData.size() != 0)
		{
			mac->update(originalData.const_byte_str(),
				     originalData.size());
		}
	}
	catch (...)
	{
		ERROR_MSG("Failed to update the verify mac token");

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		delete mac;
		mac = NULL;

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
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	Botan::secure_vector<Botan::byte> macResult;
#else
	Botan::SecureVector<Botan::byte> macResult;
#endif
	try
	{
		macResult = mac->final();
	}
	catch (...)
	{
		ERROR_MSG("Failed to verify the data");

		delete mac;
		mac = NULL;

		return false;
	}

	if (macResult.size() != signature.size())
	{
		ERROR_MSG("Bad verify result size");

		delete mac;
		mac = NULL;

		return false;
	}

	delete mac;
	mac = NULL;

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	return memcmp(&signature[0], macResult.data(), macResult.size()) == 0;
#else
	return memcmp(&signature[0], macResult.begin(), macResult.size()) == 0;
#endif
}
