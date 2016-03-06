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
 SymmetricKey.cpp

 Base class for symmetric key classes
 *****************************************************************************/

#include "config.h"
#include "ByteString.h"
#include "Serialisable.h"
#include "SymmetricKey.h"
#include "CryptoFactory.h"

// Base constructors
SymmetricKey::SymmetricKey(size_t inBitLen /* = 0 */)
{
	bitLen = inBitLen;
}

SymmetricKey::SymmetricKey(const SymmetricKey& in)
{
	keyData = in.keyData;
	bitLen = in.bitLen;
}

// Set the key
bool SymmetricKey::setKeyBits(const ByteString& keybits)
{
	if ((bitLen > 0) && ((keybits.size() * 8) != bitLen))
	{
		return false;
	}

	keyData = keybits;

	return true;
}

// Get the key
const ByteString& SymmetricKey::getKeyBits() const
{
	return keyData;
}

// Get the key check value
ByteString SymmetricKey::getKeyCheckValue() const
{
	ByteString digest;

	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA1);
	if (hash == NULL) return digest;

	if (!hash->hashInit() ||
	    !hash->hashUpdate(keyData) ||
	    !hash->hashFinal(digest))
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return digest;
	}
	CryptoFactory::i()->recycleHashAlgorithm(hash);

	digest.resize(3);

	return digest;
}

// Serialisation
ByteString SymmetricKey::serialise() const
{
	return keyData;
}

// Set the bit length
void SymmetricKey::setBitLen(const size_t inBitLen)
{
	bitLen = inBitLen;
}

// Retrieve the bit length
size_t SymmetricKey::getBitLen() const
{
	return bitLen;
}

