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

 OpenSSL symmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLEVPSymmetricAlgorithm.h"
#include "salloc.h"

// Constructor
OSSLEVPSymmetricAlgorithm::OSSLEVPSymmetricAlgorithm()
{
	pCurCTX = NULL;
}

// Destructor
OSSLEVPSymmetricAlgorithm::~OSSLEVPSymmetricAlgorithm()
{
	EVP_CIPHER_CTX_free(pCurCTX);
}

// Encryption functions
bool OSSLEVPSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */)
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

	// Determine the cipher class
	const EVP_CIPHER* cipher = getCipher();

	if (cipher == NULL)
	{
		ERROR_MSG("Failed to initialise EVP encrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Allocate the EVP context
	pCurCTX = EVP_CIPHER_CTX_new();

	if (pCurCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_CIPHER_CTX");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	int rv = EVP_EncryptInit(pCurCTX, cipher, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());

	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP encrypt operation");

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	EVP_CIPHER_CTX_set_padding(pCurCTX, padding ? 1 : 0);

	return true;
}

bool OSSLEVPSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	if (data.size() == 0)
	{
		encryptedData.resize(0);

		return true;
	}

	// Prepare the output block
	encryptedData.resize(data.size() + getBlockSize() - 1);

	int outLen = encryptedData.size();
	if (!EVP_EncryptUpdate(pCurCTX, &encryptedData[0], &outLen, (unsigned char*) data.const_byte_str(), data.size()))
	{
		ERROR_MSG("EVP_EncryptUpdate failed");

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);
	currentBufferSize -= outLen;

	return true;
}

bool OSSLEVPSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptFinal(encryptedData))
	{
		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	// Prepare the output block
	encryptedData.resize(getBlockSize());

	int outLen = encryptedData.size();

	if (!EVP_EncryptFinal(pCurCTX, &encryptedData[0], &outLen))
	{
		ERROR_MSG("EVP_EncryptFinal failed");

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	EVP_CIPHER_CTX_free(pCurCTX);
	pCurCTX = NULL;

	return true;
}

// Decryption functions
bool OSSLEVPSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString() */, bool padding /* = true */)
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
	const EVP_CIPHER* cipher = getCipher();

	if (cipher == NULL)
	{
		ERROR_MSG("Failed to initialise EVP decrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Allocate the EVP context
	pCurCTX = EVP_CIPHER_CTX_new();

	if (pCurCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_CIPHER_CTX");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	int rv = EVP_DecryptInit(pCurCTX, cipher, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());

	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP decrypt operation");

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	EVP_CIPHER_CTX_set_padding(pCurCTX, padding ? 1 : 0);

	return true;
}

bool OSSLEVPSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	// Prepare the output block
	data.resize(encryptedData.size() + getBlockSize());

	int outLen = data.size();

	DEBUG_MSG("Decrypting %d bytes into buffer of %d bytes", encryptedData.size(), data.size());

	if (!EVP_DecryptUpdate(pCurCTX, &data[0], &outLen, (unsigned char*) encryptedData.const_byte_str(), encryptedData.size()))
	{
		ERROR_MSG("EVP_DecryptUpdate failed");

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	DEBUG_MSG("Decrypt returned %d bytes of data", outLen);

	// Resize the output block
	data.resize(outLen);
	currentBufferSize -= outLen;

	return true;
}

bool OSSLEVPSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	// Prepare the output block
	data.resize(getBlockSize());

	int outLen = data.size();
	int rv;

	if (!(rv = EVP_DecryptFinal(pCurCTX, &data[0], &outLen)))
	{
		ERROR_MSG("EVP_DecryptFinal failed (0x%08X)", rv);

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	// Resize the output block
	data.resize(outLen);

	EVP_CIPHER_CTX_free(pCurCTX);
	pCurCTX = NULL;

	return true;
}

