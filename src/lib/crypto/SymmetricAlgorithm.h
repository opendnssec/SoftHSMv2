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
 SymmetricAlgorithm.h

 Base class for symmetric algorithm classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMMETRICALGORITHM_H
#define _SOFTHSM_V2_SYMMETRICALGORITHM_H

#include <string>
#include "config.h"
#include "SymmetricKey.h"
#include "RNG.h"

struct SymAlgo
{
	enum Type
	{
		Unknown,
		AES,
		DES,
		DES3
	};
};

struct SymMode
{
	enum Type
	{
		Unknown,
		CBC,
		CFB,
		CTR,
		ECB,
		GCM,
		OFB
	};
};

struct SymWrap
{
	enum Type
	{
		Unknown,
		AES_KEYWRAP,
		AES_KEYWRAP_PAD
	};
};

class SymmetricAlgorithm
{
public:
	// Base constructors
	SymmetricAlgorithm();

	// Destructor
	virtual ~SymmetricAlgorithm() { }

	// Encryption functions
	virtual bool encryptInit(const SymmetricKey* key, const SymMode::Type mode = SymMode::CBC, const ByteString& IV = ByteString(), bool padding = true, size_t counterBits = 0, const ByteString& aad = ByteString(), size_t tagBytes = 0);
	virtual bool encryptUpdate(const ByteString& data, ByteString& encryptedData);
	virtual bool encryptFinal(ByteString& encryptedData);

	// Decryption functions
	virtual bool decryptInit(const SymmetricKey* key, const SymMode::Type mode = SymMode::CBC, const ByteString& IV = ByteString(), bool padding = true, size_t counterBits = 0, const ByteString& aad = ByteString(), size_t tagBytes = 0);
	virtual bool decryptUpdate(const ByteString& encryptedData, ByteString& data);
	virtual bool decryptFinal(ByteString& data);

	// Wrap/Unwrap keys
	virtual bool wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out) = 0;

	virtual bool unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out) = 0;

	// Key factory
	virtual void recycleKey(SymmetricKey* toRecycle);
	virtual bool generateKey(SymmetricKey& key, RNG* rng = NULL);
	virtual bool reconstructKey(SymmetricKey& key, const ByteString& serialisedData);

	// Return cipher information
	virtual size_t getBlockSize() const = 0;
	virtual SymMode::Type getCipherMode();
	virtual bool getPaddingMode();
	virtual unsigned long getBufferSize();
	virtual size_t getTagBytes();
	virtual bool isStreamCipher();
	virtual bool isBlockCipher();
	virtual bool checkMaximumBytes(unsigned long bytes) = 0;

protected:
	// The current key
	const SymmetricKey* currentKey;

	// The current cipher mode
	SymMode::Type currentCipherMode;

	// The current padding
	bool currentPaddingMode;

	// The current counter bits
	size_t currentCounterBits;

	// The current tag bytes
	size_t currentTagBytes;

	// The current operation
	enum
	{
		NONE,
		ENCRYPT,
		DECRYPT
	}
	currentOperation;

	// The current number of bytes in buffer
	unsigned long currentBufferSize;

	// The current AEAD buffer
	ByteString currentAEADBuffer;
};

#endif // !_SOFTHSM_V2_SYMMETRICALGORITHM_H

