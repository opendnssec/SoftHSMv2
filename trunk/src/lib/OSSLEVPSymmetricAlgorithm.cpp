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

// TODO: Store EVP context in securely allocated memory

/*****************************************************************************
 OSSLEVPSymmetricAlgorithm.cpp

 OpenSSL AES implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLEVPSymmetricAlgorithm.h"

// Encryption functions
bool OSSLEVPSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString()*/)
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
	const EVP_CIPHER* cipher = getCipher();

	if (cipher == NULL)
	{
		ERROR_MSG("Failed to initialise EVP encrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Wipe the current context
	memset(&curCTX, 0, sizeof(curCTX));

	int rv = EVP_EncryptInit(&curCTX, cipher, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());

	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP encrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		return false;
	}

	// Prepare the output block
	encryptedData.resize(data.size() + getBlockSize() - 1);

	int outLen = encryptedData.size();
	if (!EVP_EncryptUpdate(&curCTX, &encryptedData[0], &outLen, (unsigned char*) data.const_byte_str(), data.size()))
	{
		ERROR_MSG("EVP_EncryptUpdate failed");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	return true;
}

bool OSSLEVPSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptFinal(encryptedData))
	{
		return false;
	}

	// Prepare the output block
	encryptedData.resize(getBlockSize());

	int outLen = encryptedData.size();

	if (!EVP_EncryptFinal(&curCTX, &encryptedData[0], &outLen))
	{
		ERROR_MSG("EVP_EncryptFinal failed");

		return false;
	}

	return true;
}

// Decryption functions
bool OSSLEVPSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString() */)
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
	const EVP_CIPHER* cipher = getCipher();

	if (cipher == NULL)
	{
		ERROR_MSG("Failed to initialise EVP decrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Wipe the current context
	memset(&curCTX, 0, sizeof(curCTX));

	int rv = EVP_DecryptInit(&curCTX, cipher, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());

	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP decrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		return false;
	}

	// Prepare the output block
	data.resize(encryptedData.size() + getBlockSize() - 1);

	int outLen = data.size();
	if (!EVP_DecryptUpdate(&curCTX, &data[0], &outLen, (unsigned char*) encryptedData.const_byte_str(), encryptedData.size()))
	{
		ERROR_MSG("EVP_DecryptUpdate failed");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Resize the output block
	data.resize(outLen);

	return true;
}

bool OSSLEVPSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		return false;
	}

	// Prepare the output block
	data.resize(getBlockSize());

	int outLen = data.size();

	if (!EVP_DecryptFinal(&curCTX, &data[0], &outLen))
	{
		ERROR_MSG("EVP_DecryptFinal failed");

		return false;
	}

	return true;
}

