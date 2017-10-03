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
#include "OSSLUtil.h"
#include "salloc.h"
#include <openssl/err.h>

// Constructor
OSSLEVPSymmetricAlgorithm::OSSLEVPSymmetricAlgorithm()
{
	pCurCTX = NULL;
	maximumBytes = BN_new();
	BN_one(maximumBytes);
	BN_set_negative(maximumBytes, 1);
	counterBytes = BN_new();
	BN_zero(counterBytes);
}

// Destructor
OSSLEVPSymmetricAlgorithm::~OSSLEVPSymmetricAlgorithm()
{
	EVP_CIPHER_CTX_free(pCurCTX);
	BN_free(maximumBytes);
	BN_free(counterBytes);
}

// Encryption functions
bool OSSLEVPSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */, size_t counterBits /* = 0 */, const ByteString& aad /* = ByteString() */, size_t tagBytes /* = 0 */)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::encryptInit(key, mode, IV, padding, counterBits, aad, tagBytes))
	{
		return false;
	}

	// Check the IV
	if (mode != SymMode::GCM && (IV.size() > 0) && (IV.size() != getBlockSize()))
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

	// Check the counter bits
	if (counterBits > 0)
	{
		BIGNUM* counter = OSSL::byteString2bn(iv);
		BN_mask_bits(counter, counterBits);

		// Reverse the bits
		while (counterBits > 0)
		{
			counterBits--;
			if (BN_is_bit_set(counter, counterBits))
			{
				BN_clear_bit(counter, counterBits);
			}
			else
			{
				BN_set_bit(counter, counterBits);
			}
		}

		// Set the maximum bytes
		BN_add_word(counter, 1);
		BN_mul_word(counter, getBlockSize());
		BN_copy(maximumBytes, counter);
		BN_free(counter);
		BN_zero(counterBytes);
	}
	else
	{
		BN_one(maximumBytes);
		BN_set_negative(maximumBytes, 1);
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

	int rv;
	if (mode == SymMode::GCM)
	{
		rv = EVP_EncryptInit_ex(pCurCTX, cipher, NULL, NULL, NULL);

		if (rv)
		{
			EVP_CIPHER_CTX_ctrl(pCurCTX, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
			rv = EVP_EncryptInit_ex(pCurCTX, NULL, NULL, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());
		}
	}
	else
	{
		rv = EVP_EncryptInit(pCurCTX, cipher, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());
	}

	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP encrypt operation: %s", ERR_error_string(ERR_get_error(), NULL));

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	EVP_CIPHER_CTX_set_padding(pCurCTX, padding ? 1 : 0);

	if (mode == SymMode::GCM)
	{
		int outLen = 0;
		if (aad.size() && !EVP_EncryptUpdate(pCurCTX, NULL, &outLen, (unsigned char*) aad.const_byte_str(), aad.size()))
		{
			ERROR_MSG("Failed to update with AAD: %s", ERR_error_string(ERR_get_error(), NULL));

			EVP_CIPHER_CTX_free(pCurCTX);
			pCurCTX = NULL;

			ByteString dummy;
			SymmetricAlgorithm::encryptFinal(dummy);

			return false;
		}
	}

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

	// Count number of bytes written
	if (!BN_is_negative(maximumBytes))
	{
		BN_add_word(counterBytes, data.size());
	}

	// Prepare the output block
	encryptedData.resize(data.size() + getBlockSize() - 1);

	int outLen = encryptedData.size();
	if (!EVP_EncryptUpdate(pCurCTX, &encryptedData[0], &outLen, (unsigned char*) data.const_byte_str(), data.size()))
	{
		ERROR_MSG("EVP_EncryptUpdate failed: %s", ERR_error_string(ERR_get_error(), NULL));

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
	SymMode::Type mode = currentCipherMode;
	size_t tagBytes = currentTagBytes;

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
		ERROR_MSG("EVP_EncryptFinal failed: %s", ERR_error_string(ERR_get_error(), NULL));

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	if (mode == SymMode::GCM)
	{
		ByteString tag;
		tag.resize(tagBytes);
		EVP_CIPHER_CTX_ctrl(pCurCTX, EVP_CTRL_GCM_GET_TAG, tagBytes, &tag[0]);
		encryptedData += tag;
	}

	EVP_CIPHER_CTX_free(pCurCTX);
	pCurCTX = NULL;

	return true;
}

// Decryption functions
bool OSSLEVPSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString() */, bool padding /* = true */, size_t counterBits /* = 0 */, const ByteString& aad /* = ByteString() */, size_t tagBytes /* = 0 */)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::decryptInit(key, mode, IV, padding, counterBits, aad, tagBytes))
	{
		return false;
	}

	// Check the IV
	if (mode != SymMode::GCM && (IV.size() > 0) && (IV.size() != getBlockSize()))
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

	// Check the counter bits
	if (counterBits > 0)
	{
		BIGNUM* counter = OSSL::byteString2bn(iv);
		BN_mask_bits(counter, counterBits);

		// Reverse the bits
		while (counterBits > 0)
		{
			counterBits--;
			if (BN_is_bit_set(counter, counterBits))
			{
				BN_clear_bit(counter, counterBits);
			}
			else
			{
				BN_set_bit(counter, counterBits);
			}
		}

		// Set the maximum bytes
		BN_add_word(counter, 1);
		BN_mul_word(counter, getBlockSize());
		BN_copy(maximumBytes, counter);
		BN_free(counter);
		BN_zero(counterBytes);
	}
	else
	{
		BN_one(maximumBytes);
		BN_set_negative(maximumBytes, 1);
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

	int rv;
	if (mode == SymMode::GCM)
	{
		rv = EVP_DecryptInit_ex(pCurCTX, cipher, NULL, NULL, NULL);

		if (rv)
		{
			EVP_CIPHER_CTX_ctrl(pCurCTX, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
			rv = EVP_DecryptInit_ex(pCurCTX, NULL, NULL, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());
		}
	}
	else
	{
		rv = EVP_DecryptInit(pCurCTX, cipher, (unsigned char*) currentKey->getKeyBits().const_byte_str(), iv.byte_str());
	}

	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP decrypt operation: %s", ERR_error_string(ERR_get_error(), NULL));

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	EVP_CIPHER_CTX_set_padding(pCurCTX, padding ? 1 : 0);

	if (mode == SymMode::GCM)
	{
		int outLen = 0;
		if (aad.size() && !EVP_DecryptUpdate(pCurCTX, NULL, &outLen, (unsigned char*) aad.const_byte_str(), aad.size()))
		{
			ERROR_MSG("Failed to update with AAD: %s", ERR_error_string(ERR_get_error(), NULL));

			EVP_CIPHER_CTX_free(pCurCTX);
			pCurCTX = NULL;

			ByteString dummy;
			SymmetricAlgorithm::decryptFinal(dummy);

			return false;
		}
	}

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

	// AEAD ciphers should not return decrypted data until final is called
	if (currentCipherMode == SymMode::GCM)
	{
		data.resize(0);
		return true;
	}

	// Count number of bytes written
	if (!BN_is_negative(maximumBytes))
	{
		BN_add_word(counterBytes, encryptedData.size());
	}

	// Prepare the output block
	data.resize(encryptedData.size() + getBlockSize());

	int outLen = data.size();

	DEBUG_MSG("Decrypting %d bytes into buffer of %d bytes", encryptedData.size(), data.size());

	if (!EVP_DecryptUpdate(pCurCTX, &data[0], &outLen, (unsigned char*) encryptedData.const_byte_str(), encryptedData.size()))
	{
		ERROR_MSG("EVP_DecryptUpdate failed: %s", ERR_error_string(ERR_get_error(), NULL));

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
	SymMode::Type mode = currentCipherMode;
	size_t tagBytes = currentTagBytes;
	ByteString aeadBuffer = currentAEADBuffer;

	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	data.resize(0);
	if (mode == SymMode::GCM)
	{
		// Check buffer size
		if (aeadBuffer.size() < tagBytes)
		{
			ERROR_MSG("Tag bytes (%d) does not fit in AEAD buffer (%d)", tagBytes, aeadBuffer.size());

			EVP_CIPHER_CTX_free(pCurCTX);
			pCurCTX = NULL;

			return false;
		}

		// Set the tag
		EVP_CIPHER_CTX_ctrl(pCurCTX, EVP_CTRL_GCM_SET_TAG, tagBytes, &aeadBuffer[aeadBuffer.size()-tagBytes]);

		// Prepare the output block
		data.resize(aeadBuffer.size() - tagBytes + getBlockSize());
		int outLen = data.size();

		if (!EVP_DecryptUpdate(pCurCTX, &data[0], &outLen, (unsigned char*) aeadBuffer.const_byte_str(), aeadBuffer.size() - tagBytes))
		{
			ERROR_MSG("EVP_DecryptUpdate failed: %s", ERR_error_string(ERR_get_error(), NULL));

			EVP_CIPHER_CTX_free(pCurCTX);
			pCurCTX = NULL;

			return false;
		}

		data.resize(outLen);
	}

	// Prepare the output block
	int initialSize = data.size();
	data.resize(initialSize + getBlockSize());

	int outLen = data.size() - initialSize;
	int rv;

	if (!(rv = EVP_DecryptFinal(pCurCTX, &data[initialSize], &outLen)))
	{
		ERROR_MSG("EVP_DecryptFinal failed (0x%08X): %s", rv, ERR_error_string(ERR_get_error(), NULL));

		EVP_CIPHER_CTX_free(pCurCTX);
		pCurCTX = NULL;

		return false;
	}

	// Resize the output block
	data.resize(initialSize + outLen);

	EVP_CIPHER_CTX_free(pCurCTX);
	pCurCTX = NULL;

	return true;
}

// Check if more bytes of data can be encrypted
bool OSSLEVPSymmetricAlgorithm::checkMaximumBytes(unsigned long bytes)
{
	if (BN_is_negative(maximumBytes)) return true;

	BIGNUM* bigNum = BN_new();
	BN_copy(bigNum, counterBytes);
	BN_add_word(bigNum, bytes);

	bool rv = false;
	if (BN_cmp(maximumBytes, bigNum) >= 0) rv = true;

	BN_free(bigNum);

	return rv;
}
