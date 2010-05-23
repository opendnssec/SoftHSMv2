/* $Id$ */

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
 BotanSymmetricAlgorithm.cpp

 Botan symmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "BotanSymmetricAlgorithm.h"
#include "salloc.h"
#include <iostream>

#include <botan/symkey.h>
#include <botan/botan.h>

// Constructor
BotanSymmetricAlgorithm::BotanSymmetricAlgorithm()
{
	cryption = NULL;
}

// Destructor
BotanSymmetricAlgorithm::~BotanSymmetricAlgorithm()
{
	delete cryption;
}

// Encryption functions
bool BotanSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString()*/)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::encryptInit(key, mode, IV))
	{
		return false;
	}

	// Check the IV
	if ((IV.size() > 0) && (IV.size() != getBlockSize()))
	{
		ERROR_MSG("Invalid IV size (%d bytes, expected %d bytes)", IV.size(), getBlockSize());

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	ByteString iv;

	if (IV.size() > 0)
	{
		iv = IV;
	}
	else
	{
		iv.wipe(getBlockSize());
	}

	// Determine the cipher
	std::string cipherName = getCipher();
	Botan::SymmetricKey botanKey = Botan::SymmetricKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	Botan::InitializationVector botanIV = Botan::InitializationVector(IV.const_byte_str(), IV.size());

	if (cipherName == "")
	{
		ERROR_MSG("Failed to initialise encrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Allocate the context
	cryption = new Botan::Pipe(Botan::get_cipher(cipherName, botanKey, botanIV, Botan::ENCRYPTION));
	cryption->start_msg();

	return true;
}

bool BotanSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		delete cryption;
		cryption = NULL;

		return false;
	}

	// Prepare the output block
	encryptedData.resize(data.size() + getBlockSize() - 1);

	// Write and read data
	int outLen = encryptedData.size();
	cryption->write(data.const_byte_str(), data.size());
	int bytesRead = cryption->read(&encryptedData[0], outLen);

	// Resize the output block
	encryptedData.resize(bytesRead);

	return true;
}

bool BotanSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptFinal(encryptedData))
	{
		delete cryption;
		cryption = NULL;

		return false;
	}

	// Prepare the output block
	encryptedData.resize(getBlockSize());

	// Read data
	int outLen = encryptedData.size();
	cryption->end_msg();
	int bytesRead = cryption->read(&encryptedData[0], outLen);

	// Clean up
	delete cryption;
	cryption = NULL;

	// Resize the output block
	encryptedData.resize(bytesRead);

	return true;
}

// Decryption functions
bool BotanSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString() */)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::decryptInit(key, mode, IV))
	{
		return false;
	}

	// Check the IV
	if ((IV.size() > 0) && (IV.size() != getBlockSize()))
	{
		ERROR_MSG("Invalid IV size (%d bytes, expected %d bytes)", IV.size(), getBlockSize());

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	ByteString iv;

	if (IV.size() > 0)
	{
		iv = IV;
	}
	else
	{
		iv.wipe(getBlockSize());
	}

	// Determine the cipher class
	std::string cipherName = getCipher();
	Botan::SymmetricKey botanKey = Botan::SymmetricKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	Botan::InitializationVector botanIV = Botan::InitializationVector(IV.const_byte_str(), IV.size());

	if (cipherName == "")
	{
		ERROR_MSG("Failed to initialise encrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Allocate the context
	cryption = new Botan::Pipe(Botan::get_cipher(cipherName, botanKey, botanIV, Botan::DECRYPTION));
	cryption->start_msg();

	return true;
}

bool BotanSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		delete cryption;
		cryption = NULL;

		return false;
	}

	// Prepare the output block
	data.resize(encryptedData.size() + getBlockSize() - 1);

	// Write and read data
	int outLen = data.size();
	cryption->write(encryptedData.const_byte_str(), encryptedData.size());
	int bytesRead = cryption->read(&data[0], outLen);
	
	// Resize the output block
	data.resize(bytesRead);

	return true;
}

bool BotanSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		delete cryption;
		cryption = NULL;

		return false;
	}

	// Prepare the output block
	data.resize(getBlockSize());

	// Read data
	int outLen = data.size();
	cryption->end_msg();
	int bytesRead = cryption->read(&data[0], outLen);

	// Clean up
	delete cryption;
	cryption = NULL;

	// Resize the output block
	data.resize(bytesRead);

	return true;
}

