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
 OSSLGOSTPrivateKey.cpp

 OpenSSL GOST R 34.10-2001 private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "OSSLGOSTPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/ec.h>

// DER of a private key
const ByteString dummyKey = "3045020100301c06062a8503020213301206072a85030202230106072a850302021e01042202201b3f94f71a5f2fe7e5740b8cd4b718dd656826d154fb77ba6372d9f06387e0d6";

// Constructors
OSSLGOSTPrivateKey::OSSLGOSTPrivateKey()
{
	pkey = EVP_PKEY_new();
}

OSSLGOSTPrivateKey::OSSLGOSTPrivateKey(const EVP_PKEY* inPKEY)
{
	OSSLGOSTPrivateKey();

	setFromOSSL(inPKEY);
}

// Destructor
OSSLGOSTPrivateKey::~OSSLGOSTPrivateKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLGOSTPrivateKey::type = "OpenSSL GOST Private Key";

// Get the output length
unsigned long OSSLGOSTPrivateKey::getOutputLength() const
{
	return 64;
}

// Set from OpenSSL representation
void OSSLGOSTPrivateKey::setFromOSSL(const EVP_PKEY* pkey)
{
	const EC_KEY* ec = (const EC_KEY*) EVP_PKEY_get0((EVP_PKEY*) pkey);
	const BIGNUM* priv = EC_KEY_get0_private_key(ec);
	setD(OSSL::bn2ByteString(priv));
}

// Check if the key is of the given type
bool OSSLGOSTPrivateKey::isOfType(const char* type)
{
	return !strcmp(OSSLGOSTPrivateKey::type, type);
}

// Setters for the GOST private key components
void OSSLGOSTPrivateKey::setD(const ByteString& d)
{
	GOSTPrivateKey::setD(d);

	EC_KEY* ec = (EC_KEY*) EVP_PKEY_get0((EVP_PKEY*) pkey);
	if (ec == NULL)
	{
		ByteString der = dummyKey;
		const unsigned char *p = &der[0];
		if (d2i_PrivateKey(NID_id_GostR3410_2001, &pkey, &p, (long) der.size()) == NULL)
		{
			ERROR_MSG("d2i_PrivateKey failed");

			return;
		}
		ec = (EC_KEY*) EVP_PKEY_get0((EVP_PKEY*) pkey);
	}

	const BIGNUM* priv = OSSL::byteString2bn(d);
	if (EC_KEY_set_private_key(ec, priv) <= 0)
	{
		ERROR_MSG("EC_KEY_set_private_key failed");
		return;
	}

#ifdef notyet
	if (gost2001_compute_public(ec) <= 0)
		ERROR_MSG("gost2001_compute_public failed");
#endif		
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLGOSTPrivateKey::getOSSLKey()
{
	return pkey;
}

// Serialisation
ByteString OSSLGOSTPrivateKey::serialise() const
{
	return d.serialise();
}

bool OSSLGOSTPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dD = ByteString::chainDeserialise(serialised);

	if (dD.size() == 0)
	{
		return false;
	}

	setD(dD);

	return true;
}
#endif
