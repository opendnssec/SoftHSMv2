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
 OSSLPBKDF2.cpp

 OpenSSL pbkdf2 algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLPBKDF2.h"
#include "CryptoFactory.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/err.h>

bool OSSLPBKDF2::generateKey(SymmetricKey **ppSymmetricKey, PBKDF2Algo::Type algo, const ByteString& passwd, const ByteString& salt, int iterations, int keyLen)
{
	int ret;
	const EVP_MD *md = NULL;

	// Check parameters
	if (ppSymmetricKey == NULL)
	{
		return false;
	}

	switch(algo) {
		case PBKDF2Algo::PKCS5_PBKD2_HMAC_SHA224:
			md = EVP_sha224();
			break;
		case PBKDF2Algo::PKCS5_PBKD2_HMAC_SHA256:
			md = EVP_sha256();
			break;
		case PBKDF2Algo::PKCS5_PBKD2_HMAC_SHA384:
			md = EVP_sha384();
			break;
		case PBKDF2Algo::PKCS5_PBKD2_HMAC_SHA512:
			md = EVP_sha512();
			break;
		default:
			return false;
	}

	// Derive the secret
	ByteString secret, derivedSecret;
	secret.wipe(keyLen);
	ret = PKCS5_PBKDF2_HMAC((const char *)passwd.const_byte_str(), passwd.size(), salt.const_byte_str(), salt.size(), iterations, md, keyLen, &secret[0]);
	if (ret != 1)
	{
		ERROR_MSG("PBKDF2 derivation failed (0x%08X)", ERR_get_error());

		return false;
	}

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
		return false;
	if (!(*ppSymmetricKey)->setKeyBits(secret))
	{
		delete *ppSymmetricKey;
		*ppSymmetricKey = NULL;
		return false;
	}

	return true;
}

unsigned long OSSLPBKDF2::getMinKeySize()
{
	return 1;
}

unsigned long OSSLPBKDF2::getMaxKeySize()
{
	return 512;
}
