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
 SymmetricAlgorithm.cpp

 Base class for symmetric algorithm classes
 *****************************************************************************/

#include "SymmetricAlgorithm.h"
#include <algorithm>
#include <string.h>

SymmetricAlgorithm::SymmetricAlgorithm()
{
	currentKey = NULL;
	currentCipherMode = SymMode::Unknown;
	currentPaddingMode = true;
	currentCounterBits = 0;
	currentTagBytes = 0;
	currentOperation = NONE;
	currentBufferSize = 0;
}

bool SymmetricAlgorithm::encryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& /*IV = ByteString() */, bool padding /* = true */, size_t counterBits /* = 0 */, const ByteString& /*aad = ByteString()*/, size_t tagBytes /* = 0 */)
{
	if ((key == NULL) || (currentOperation != NONE))
	{
		return false;
	}

	currentKey = key;
	currentCipherMode = mode;
	currentPaddingMode = padding;
	currentCounterBits = counterBits;
	currentTagBytes = tagBytes;
	currentOperation = ENCRYPT;
	currentBufferSize = 0;

	return true;
}

bool SymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& /*encryptedData*/)
{
	if (currentOperation != ENCRYPT)
	{
		return false;
	}

	currentBufferSize += data.size();

	return true;
}

bool SymmetricAlgorithm::encryptFinal(ByteString& /*encryptedData*/)
{
	if (currentOperation != ENCRYPT)
	{
		return false;
	}

	currentKey = NULL;
	currentCipherMode = SymMode::Unknown;
	currentPaddingMode = true;
	currentCounterBits = 0;
	currentTagBytes = 0;
	currentOperation = NONE;
	currentBufferSize = 0;

	return true;
}

bool SymmetricAlgorithm::decryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& /*IV = ByteString() */, bool padding /* = true */, size_t counterBits /* = 0 */, const ByteString& /*aad = ByteString()*/, size_t tagBytes /* = 0 */)
{
	if ((key == NULL) || (currentOperation != NONE))
	{
		return false;
	}

	currentKey = key;
	currentCipherMode = mode;
	currentPaddingMode = padding;
	currentCounterBits = counterBits;
	currentTagBytes = tagBytes;
	currentOperation = DECRYPT;
	currentBufferSize = 0;
	currentAEADBuffer.wipe();

	return true;
}


bool SymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& /*data*/)
{
	if (currentOperation != DECRYPT)
	{
		return false;
	}

	currentBufferSize += encryptedData.size();
	currentAEADBuffer += encryptedData;

	return true;
}

bool SymmetricAlgorithm::decryptFinal(ByteString& /*data*/)
{
	if (currentOperation != DECRYPT)
	{
		return false;
	}

	currentKey = NULL;
	currentCipherMode = SymMode::Unknown;
	currentPaddingMode = true;
	currentCounterBits = 0;
	currentTagBytes = 0;
	currentOperation = NONE;
	currentBufferSize = 0;
	currentAEADBuffer.wipe();

	return true;
}

// Key factory
void SymmetricAlgorithm::recycleKey(SymmetricKey* toRecycle)
{
	delete toRecycle;
}

bool SymmetricAlgorithm::generateKey(SymmetricKey& key, RNG* rng /* = NULL */)
{
	if (rng == NULL)
	{
		return false;
	}

	if (key.getBitLen() == 0)
	{
		return false;
	}

	ByteString keyBits;

	if (!rng->generateRandom(keyBits, key.getBitLen()/8))
	{
		return false;
	}

	return key.setKeyBits(keyBits);
}

bool SymmetricAlgorithm::reconstructKey(SymmetricKey& key, const ByteString& serialisedData)
{
	return key.setKeyBits(serialisedData);
}

SymMode::Type SymmetricAlgorithm::getCipherMode()
{
	return currentCipherMode;
}

bool SymmetricAlgorithm::getPaddingMode()
{
	return currentPaddingMode;
}

unsigned long SymmetricAlgorithm::getBufferSize()
{
	return currentBufferSize;
}

size_t SymmetricAlgorithm::getTagBytes()
{
	return currentTagBytes;
}

bool SymmetricAlgorithm::isStreamCipher()
{
	switch (currentCipherMode)
	{
		case SymMode::CFB:
		case SymMode::CTR:
		case SymMode::GCM:
		case SymMode::OFB:
			return true;
		default:
			break;
	}

	return false;
}

bool SymmetricAlgorithm::isBlockCipher()
{
	switch (currentCipherMode)
	{
		case SymMode::CBC:
		case SymMode::ECB:
			return true;
		default:
			break;
	}

	return false;
}
