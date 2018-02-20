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
 OSSLAES.cpp

 OpenSSL AES implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLAES.h"
#include <algorithm>
#include <openssl/aes.h>
#include "salloc.h"

// Wrap/Unwrap keys
#ifdef HAVE_AES_KEY_WRAP
bool OSSLAES::wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	// RFC 3394 input length checks do not apply to RFC 5649 mode with padding
	if (mode == SymWrap::AES_KEYWRAP && !checkLength(in.size(), 16, "wrap"))
		return false;

	return wrapUnwrapKey(key, mode, in, out, 1);
}
#else
bool OSSLAES::wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	return false;
}
#endif

#ifdef HAVE_AES_KEY_WRAP
bool OSSLAES::unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	// RFC 3394 algorithm produce at least 3 blocks of data
	if ((mode == SymWrap::AES_KEYWRAP && !checkLength(in.size(), 24, "unwrap")) ||
	// RFC 5649 algorithm produce at least 2 blocks of data
	    (mode == SymWrap::AES_KEYWRAP_PAD && !checkLength(in.size(), 16, "unwrap")))
		return false;
	return wrapUnwrapKey(key, mode, in, out, 0);
}
#else
bool OSSLAES::unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	return false;
}
#endif

#ifdef HAVE_AES_KEY_WRAP
// RFC 3394 wrapping and all unwrapping algorithms require aligned blocks
bool OSSLAES::checkLength(const int insize, const int minsize, const char * const operation) const
{
	if (insize < minsize)
	{
		ERROR_MSG("key data to %s too small", operation);
		return false;
	}
	if ((insize % 8) != 0)
	{
		ERROR_MSG("key data to %s not aligned", operation);
		return false;
	}
	return true;
}

const EVP_CIPHER* OSSLAES::getWrapCipher(const SymWrap::Type mode, const SymmetricKey* key) const
{
	if (key == NULL)
		return NULL;

	// Check currentKey bit length; AES only supports 128, 192 or 256 bit keys
	if ((key->getBitLen() != 128) &&
	    (key->getBitLen() != 192) &&
	    (key->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES key length (%d bits)", key->getBitLen());

		return NULL;
	}

#ifdef HAVE_AES_KEY_WRAP
	// Determine the un/wrapping mode
	if (mode == SymWrap::AES_KEYWRAP)
	{
		// RFC 3394 AES key wrap
		switch(key->getBitLen())
		{
			case 128:
				return EVP_aes_128_wrap();
			case 192:
				return EVP_aes_192_wrap();
			case 256:
				return EVP_aes_256_wrap();
		};
	}
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
	if (mode == SymWrap::AES_KEYWRAP_PAD)
	{
		// RFC 5649 AES key wrap with pad
		switch(key->getBitLen())
		{
			case 128:
				return EVP_aes_128_wrap_pad();
			case 192:
				return EVP_aes_192_wrap_pad();
			case 256:
				return EVP_aes_256_wrap_pad();
		};
	}
#endif

	ERROR_MSG("unknown AES key wrap mode %i", mode);
	return NULL;
}

// EVP wrapping/unwrapping
// wrap = 1 -> wrapping
// wrap = 0 -> unwrapping
bool OSSLAES::wrapUnwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out, const int wrap) const
{
	const char *prefix = "";
	if (wrap == 0)
		prefix = "un";

	// Determine the cipher method
	const EVP_CIPHER* cipher = getWrapCipher(mode, key);
	if (cipher == NULL)
	{
		ERROR_MSG("Failed to get EVP %swrap cipher", prefix);
		return false;
	}

	// Allocate the EVP context
	EVP_CIPHER_CTX* pWrapCTX = EVP_CIPHER_CTX_new();
	if (pWrapCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_CIPHER_CTX");
		return false;
	}
	EVP_CIPHER_CTX_set_flags(pWrapCTX, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	int rv = EVP_CipherInit_ex(pWrapCTX, cipher, NULL, (unsigned char*) key->getKeyBits().const_byte_str(), NULL, wrap);
	if (rv)
		// Padding is handled by cipher mode separately
		rv = EVP_CIPHER_CTX_set_padding(pWrapCTX, 0);
	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP cipher %swrap operation", prefix);

		EVP_CIPHER_CTX_free(pWrapCTX);
		return false;
	}

	// 1 input byte could be expanded to two AES blocks
	out.resize(in.size() + 2 * EVP_CIPHER_CTX_block_size(pWrapCTX) - 1);
	int outLen = 0;
	int curBlockLen = 0;
	rv = EVP_CipherUpdate(pWrapCTX, &out[0], &curBlockLen, in.const_byte_str(), in.size());
	if (rv == 1) {
		outLen = curBlockLen;
		rv = EVP_CipherFinal_ex(pWrapCTX, &out[0] + outLen, &curBlockLen);
	}
	if (rv != 1)
	{
		ERROR_MSG("Failed EVP %swrap operation", prefix);

		EVP_CIPHER_CTX_free(pWrapCTX);
		return false;
	}
	EVP_CIPHER_CTX_free(pWrapCTX);
	outLen += curBlockLen;
	out.resize(outLen);
	return true;
}
#endif

const EVP_CIPHER* OSSLAES::getCipher() const
{
	if (currentKey == NULL) return NULL;

	// Check currentKey bit length; AES only supports 128, 192 or 256 bit keys
	if ((currentKey->getBitLen() != 128) &&
	    (currentKey->getBitLen() != 192) &&
            (currentKey->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES currentKey length (%d bits)", currentKey->getBitLen());

		return NULL;
	}

	// Determine the cipher mode
	if (currentCipherMode == SymMode::CBC)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return EVP_aes_128_cbc();
			case 192:
				return EVP_aes_192_cbc();
			case 256:
				return EVP_aes_256_cbc();
		};
	}
	else if (currentCipherMode == SymMode::ECB)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return EVP_aes_128_ecb();
			case 192:
				return EVP_aes_192_ecb();
			case 256:
				return EVP_aes_256_ecb();
		};
	}
	else if (currentCipherMode == SymMode::CTR)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return EVP_aes_128_ctr();
			case 192:
				return EVP_aes_192_ctr();
			case 256:
				return EVP_aes_256_ctr();
		};
	}
	else if (currentCipherMode == SymMode::GCM)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return EVP_aes_128_gcm();
			case 192:
				return EVP_aes_192_gcm();
			case 256:
				return EVP_aes_256_gcm();
		};
	}

	ERROR_MSG("Invalid AES cipher mode %i", currentCipherMode);

	return NULL;
}

size_t OSSLAES::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}
