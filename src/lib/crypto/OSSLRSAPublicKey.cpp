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
 OSSLRSAPublicKey.cpp

 OpenSSL RSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLComp.h"
#include "OSSLRSAPublicKey.h"
#include "OSSLUtil.h"
#include <string.h>
#include <openssl/bn.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif

// Constructors
OSSLRSAPublicKey::OSSLRSAPublicKey()
{
	rsa = NULL;
}

OSSLRSAPublicKey::OSSLRSAPublicKey(const RSA* inRSA)
{
	rsa = NULL;

	setFromOSSL(inRSA);
}

// Destructor
OSSLRSAPublicKey::~OSSLRSAPublicKey()
{
	RSA_free(rsa);
}

// The type
/*static*/ const char* OSSLRSAPublicKey::type = "OpenSSL RSA Public Key";

// Check if the key is of the given type
bool OSSLRSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Set from OpenSSL representation
void OSSLRSAPublicKey::setFromOSSL(const RSA* inRSA)
{
	const BIGNUM* bn_n = NULL;
	const BIGNUM* bn_e = NULL;

	RSA_get0_key(inRSA, &bn_n, &bn_e, NULL);

	if (bn_n)
	{
		ByteString inN = OSSL::bn2ByteString(bn_n);
		setN(inN);
	}
	if (bn_e)
	{
		ByteString inE = OSSL::bn2ByteString(bn_e);
		setE(inE);
	}
}

// Setters for the RSA public key components
void OSSLRSAPublicKey::setN(const ByteString& inN)
{
	RSAPublicKey::setN(inN);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPublicKey::setE(const ByteString& inE)
{
	RSAPublicKey::setE(inE);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
RSA* OSSLRSAPublicKey::getOSSLKey()
{
	if (rsa == NULL) createOSSLKey();

	return rsa;
}

// Create the OpenSSL representation of the key
void OSSLRSAPublicKey::createOSSLKey()
{
	if (rsa != NULL) return;

	rsa = RSA_new();
	if (rsa == NULL)
	{
		ERROR_MSG("Could not create RSA object");
		return;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		RSA_set_method(rsa, FIPS_rsa_pkcs1_ssleay());
	else
		RSA_set_method(rsa, RSA_PKCS1_SSLeay());
#else
	RSA_set_method(rsa, RSA_PKCS1_SSLeay());
#endif

#else
	RSA_set_method(rsa, RSA_PKCS1_OpenSSL());
#endif

	BIGNUM* bn_n = OSSL::byteString2bn(n);
	BIGNUM* bn_e = OSSL::byteString2bn(e);

	RSA_set0_key(rsa, bn_n, bn_e, NULL);
}
