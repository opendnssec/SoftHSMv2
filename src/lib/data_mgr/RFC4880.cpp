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
 RFC4880.cpp

 Implements a secure password-based key derivation scheme. It is not a generic
 implementation of the RFC but only generates 256-bit AES keys according to
 the "iterated and salted" scheme.
 *****************************************************************************/

#include "config.h"
#include "RFC4880.h"
#include "CryptoFactory.h"
#include "HashAlgorithm.h"

// This function derives a 256-bit AES key from the supplied password data
bool RFC4880::PBEDeriveKey(const ByteString& password, ByteString& salt, AESKey** ppKey)
{
	// Check that a proper salt value was supplied; it should be at least 8 bytes long
	if (salt.size() < 8)
	{
		ERROR_MSG("Insufficient salt data supplied for password-based encryption");

		return false;
	}

	// Check other parameters
	if ((password.size() == 0) || (ppKey == NULL))
	{
		return false;
	}

	// Determine the iteration count based on the last byte of the salt
	unsigned int iter = PBE_ITERATION_BASE_COUNT + salt[salt.size() - 1];

	// Get a hash instance
	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA256);

	if (hash == NULL)
	{
		ERROR_MSG("Could not get a SHA-256 instance");

		return false;
	}

	// Perform the first iteration which takes as input the salt value and
	// the password
	ByteString intermediate;

	if (!hash->hashInit() ||
	    !hash->hashUpdate(salt) ||
	    !hash->hashUpdate(password) ||
	    !hash->hashFinal(intermediate))
	{
		ERROR_MSG("Hashing failed");

		CryptoFactory::i()->recycleHashAlgorithm(hash);

		return false;
	}

	// Perform the remaining iteration
	while (--iter > 0)
	{
		if (!hash->hashInit() ||
		    !hash->hashUpdate(intermediate) ||
		    !hash->hashFinal(intermediate))
		{
			ERROR_MSG("Hashing failed");

			CryptoFactory::i()->recycleHashAlgorithm(hash);

			return false;
		}
	}

	// Create the AES key instance
	*ppKey = new AESKey(256);
	(*ppKey)->setKeyBits(intermediate);

	// Release the hash instance
	CryptoFactory::i()->recycleHashAlgorithm(hash);

	return true;
}

