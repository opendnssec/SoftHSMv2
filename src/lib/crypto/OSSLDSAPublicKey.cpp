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
 OSSLDSAPublicKey.cpp

 OpenSSL DSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDSAPublicKey.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

// Constructors
OSSLDSAPublicKey::OSSLDSAPublicKey()
{
	dsa = NULL;
}

OSSLDSAPublicKey::OSSLDSAPublicKey(const DSA* inDSA)
{
	dsa = NULL;

	setFromOSSL(inDSA);
}

// Destructor
OSSLDSAPublicKey::~OSSLDSAPublicKey()
{
	DSA_free(dsa);
}

// The type
/*static*/ const char* OSSLDSAPublicKey::type = "OpenSSL DSA Public Key";

// Set from OpenSSL representation
void OSSLDSAPublicKey::setFromOSSL(const DSA* inDSA)
{
	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_q = NULL;
	const BIGNUM* bn_g = NULL;
	const BIGNUM* bn_pub_key = NULL;

	DSA_get0_pqg(inDSA, &bn_p, &bn_q, &bn_g);
	DSA_get0_key(inDSA, &bn_pub_key, NULL);

	if (bn_p)
	{
		ByteString inP = OSSL::bn2ByteString(bn_p);
		setP(inP);
	}
	if (bn_q)
	{
		ByteString inQ = OSSL::bn2ByteString(bn_q);
		setQ(inQ);
	}
	if (bn_g)
	{
		ByteString inG = OSSL::bn2ByteString(bn_g);
		setG(inG);
	}
	if (bn_pub_key)
	{
		ByteString inY = OSSL::bn2ByteString(bn_pub_key);
		setY(inY);
	}
}

// Check if the key is of the given type
bool OSSLDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DSA public key components
void OSSLDSAPublicKey::setP(const ByteString& inP)
{
	DSAPublicKey::setP(inP);

	if (dsa)
	{
		DSA_free(dsa);
		dsa = NULL;
	}
}

void OSSLDSAPublicKey::setQ(const ByteString& inQ)
{
	DSAPublicKey::setQ(inQ);

	if (dsa)
	{
		DSA_free(dsa);
		dsa = NULL;
	}
}

void OSSLDSAPublicKey::setG(const ByteString& inG)
{
	DSAPublicKey::setG(inG);

	if (dsa)
	{
		DSA_free(dsa);
		dsa = NULL;
	}
}

void OSSLDSAPublicKey::setY(const ByteString& inY)
{
	DSAPublicKey::setY(inY);

	if (dsa)
	{
		DSA_free(dsa);
		dsa = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
DSA* OSSLDSAPublicKey::getOSSLKey()
{
	if (dsa == NULL) createOSSLKey();

	return dsa;
}

// Create the OpenSSL representation of the key
void OSSLDSAPublicKey::createOSSLKey()
{
	if (dsa != NULL) return;

	dsa = DSA_new();
	if (dsa == NULL)
	{
		ERROR_MSG("Could not create DSA object");
		return;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		DSA_set_method(dsa, FIPS_dsa_openssl());
	else
		DSA_set_method(dsa, DSA_OpenSSL());
#else
	DSA_set_method(dsa, DSA_OpenSSL());
#endif

#else
	DSA_set_method(dsa, DSA_OpenSSL());
#endif

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_q = OSSL::byteString2bn(q);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_pub_key = OSSL::byteString2bn(y);

	DSA_set0_pqg(dsa, bn_p, bn_q, bn_g);
	DSA_set0_key(dsa, bn_pub_key, NULL);
}
