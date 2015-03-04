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
#include <botan/version.h>

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,14)
#include <botan/key_filt.h>
#endif

// Constructor
BotanSymmetricAlgorithm::BotanSymmetricAlgorithm()
{
	cryption = NULL;
}

// Destructor
BotanSymmetricAlgorithm::~BotanSymmetricAlgorithm()
{
	delete cryption;
	cryption = NULL;
}

// Encryption functions
bool BotanSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode:CBC */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::encryptInit(key, mode, IV, padding))
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

	if (cipherName == "")
	{
		ERROR_MSG("Invalid encryption cipher");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Allocate the context
	try
	{
		Botan::SymmetricKey botanKey = Botan::SymmetricKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
		if (mode == SymMode::ECB)
		{
			cryption = new Botan::Pipe(Botan::get_cipher(cipherName, botanKey, Botan::ENCRYPTION));
		}
		else
		{
			Botan::InitializationVector botanIV = Botan::InitializationVector(IV.const_byte_str(), IV.size());
			cryption = new Botan::Pipe(Botan::get_cipher(cipherName, botanKey, botanIV, Botan::ENCRYPTION));
		}
		cryption->start_msg();
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the encryption token");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		delete cryption;
		cryption = NULL;

		return false;
	}

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

	// Write data
	try
	{
		if (data.size() > 0)
			cryption->write(data.const_byte_str(), data.size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to write to the encryption token");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		delete cryption;
		cryption = NULL;

		return false;
	}

	// Read data
	int bytesRead = 0;
	try
	{
		size_t outLen = cryption->remaining();
		encryptedData.resize(outLen);
		if (outLen > 0)
			bytesRead = cryption->read(&encryptedData[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to encrypt the data");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		delete cryption;
		cryption = NULL;

		return false;
	}

	// Resize the output block
	encryptedData.resize(bytesRead);
	currentBufferSize -= bytesRead;

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

	// Read data
	int bytesRead = 0;
	try
	{
		cryption->end_msg();
		size_t outLen = cryption->remaining();
		encryptedData.resize(outLen);
		if (outLen > 0)
			bytesRead = cryption->read(&encryptedData[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to encrypt the data");

		delete cryption;
		cryption = NULL;

		return false;
	}

	// Clean up
	delete cryption;
	cryption = NULL;

	// Resize the output block
	encryptedData.resize(bytesRead);

	return true;
}

// Decryption functions
bool BotanSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString() */, bool padding /* = true */)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::decryptInit(key, mode, IV, padding))
	{
		return false;
	}

	// Check the IV
	if ((IV.size() > 0) && (IV.size() != getBlockSize()))
	{
		ERROR_MSG("Invalid IV size (%d bytes, expected %d bytes)", IV.size(), getBlockSize());

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

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

	if (cipherName == "")
	{
		ERROR_MSG("Invalid decryption cipher");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Allocate the context
	try
	{
		Botan::SymmetricKey botanKey = Botan::SymmetricKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
		if (mode == SymMode::ECB)
		{
			cryption = new Botan::Pipe(Botan::get_cipher(cipherName, botanKey, Botan::DECRYPTION));
		}
		else
		{
			Botan::InitializationVector botanIV = Botan::InitializationVector(IV.const_byte_str(), IV.size());
			cryption = new Botan::Pipe(Botan::get_cipher(cipherName, botanKey, botanIV, Botan::DECRYPTION));
		}
		cryption->start_msg();
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the decryption token");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		delete cryption;
		cryption = NULL;

		return false;
	}

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

	// Write data
	try
	{
		if (encryptedData.size() > 0)
			cryption->write(encryptedData.const_byte_str(), encryptedData.size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to write to the decryption token");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		delete cryption;
		cryption = NULL;

		return false;
	}

	// Read data
	int bytesRead = 0;
	try
	{
		size_t outLen = cryption->remaining();
		data.resize(outLen);
		if (outLen > 0)
			bytesRead = cryption->read(&data[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to decrypt the data");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		delete cryption;
		cryption = NULL;

		return false;
	}

	// Resize the output block
	data.resize(bytesRead);
	currentBufferSize -= bytesRead;

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

	// Read data
	int bytesRead = 0;
	try
	{
		cryption->end_msg();
		size_t outLen = cryption->remaining();
		data.resize(outLen);
		if (outLen > 0)
			bytesRead = cryption->read(&data[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to decrypt the data");

		delete cryption;
		cryption = NULL;

		return false;
	}

	// Clean up
	delete cryption;
	cryption = NULL;

	// Resize the output block
	data.resize(bytesRead);

	return true;
}

