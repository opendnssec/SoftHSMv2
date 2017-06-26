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
 OSSLDHPublicKey.cpp

 OpenSSL Diffie-Hellman public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLComp.h"
#include "OSSLDHPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

// Constructors
OSSLDHPublicKey::OSSLDHPublicKey()
{
	dh = NULL;
}

OSSLDHPublicKey::OSSLDHPublicKey(const DH* inDH)
{
	dh = NULL;

	setFromOSSL(inDH);
}

// Destructor
OSSLDHPublicKey::~OSSLDHPublicKey()
{
	DH_free(dh);
}

// The type
/*static*/ const char* OSSLDHPublicKey::type = "OpenSSL DH Public Key";

// Set from OpenSSL representation
void OSSLDHPublicKey::setFromOSSL(const DH* inDH)
{
	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_g = NULL;
	const BIGNUM* bn_pub_key = NULL;

	DH_get0_pqg(inDH, &bn_p, NULL, &bn_g);
	DH_get0_key(inDH, &bn_pub_key, NULL);

	if (bn_p)
	{
		ByteString inP = OSSL::bn2ByteString(bn_p);
		setP(inP);
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
bool OSSLDHPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DH public key components
void OSSLDHPublicKey::setP(const ByteString& inP)
{
	DHPublicKey::setP(inP);

	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}

void OSSLDHPublicKey::setG(const ByteString& inG)
{
	DHPublicKey::setG(inG);

	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}

void OSSLDHPublicKey::setY(const ByteString& inY)
{
	DHPublicKey::setY(inY);

	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
DH* OSSLDHPublicKey::getOSSLKey()
{
	if (dh == NULL) createOSSLKey();

	return dh;
}

// Create the OpenSSL representation of the key
void OSSLDHPublicKey::createOSSLKey()
{
	if (dh != NULL) return;

	dh = DH_new();
	if (dh == NULL)
	{
		ERROR_MSG("Could not create DH object");
		return;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		DH_set_method(dh, FIPS_dh_openssl());
	else
		DH_set_method(dh, DH_OpenSSL());
#else
	DH_set_method(dh, DH_OpenSSL());
#endif

#else
	DH_set_method(dh, DH_OpenSSL());
#endif

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_pub_key = OSSL::byteString2bn(y);

	DH_set0_pqg(dh, bn_p, NULL, bn_g);
	DH_set0_key(dh, bn_pub_key, NULL);
}
