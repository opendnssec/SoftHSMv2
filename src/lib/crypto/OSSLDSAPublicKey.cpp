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
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLDSAPublicKey::OSSLDSAPublicKey()
{
	dsa = DSA_new();

	// Use the OpenSSL implementation and not any engine
	DSA_set_method(dsa, DSA_get_default_method());
}

OSSLDSAPublicKey::OSSLDSAPublicKey(const DSA* inDSA)
{
	dsa = DSA_new();

	// Use the OpenSSL implementation and not any engine
	DSA_set_method(dsa, DSA_OpenSSL());

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
	if (inDSA->p)
	{
		ByteString inP = OSSL::bn2ByteString(inDSA->p);
		setP(inP);
	}
	if (inDSA->q)
	{
		ByteString inQ = OSSL::bn2ByteString(inDSA->q);
		setQ(inQ);
	}
	if (inDSA->g)
	{
		ByteString inG = OSSL::bn2ByteString(inDSA->g);
		setG(inG);
	}
	if (inDSA->pub_key)
	{
		ByteString inY = OSSL::bn2ByteString(inDSA->pub_key);
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

	if (dsa->p)
	{
		BN_clear_free(dsa->p);
		dsa->p = NULL;
	}

	dsa->p = OSSL::byteString2bn(inP);
}

void OSSLDSAPublicKey::setQ(const ByteString& inQ)
{
	DSAPublicKey::setQ(inQ);

	if (dsa->q)
	{
		BN_clear_free(dsa->q);
		dsa->q = NULL;
	}

	dsa->q = OSSL::byteString2bn(inQ);
}

void OSSLDSAPublicKey::setG(const ByteString& inG)
{
	DSAPublicKey::setG(inG);

	if (dsa->g)
	{
		BN_clear_free(dsa->g);
		dsa->g = NULL;
	}

	dsa->g = OSSL::byteString2bn(inG);
}

void OSSLDSAPublicKey::setY(const ByteString& inY)
{
	DSAPublicKey::setY(inY);

	if (dsa->pub_key)
	{
		BN_clear_free(dsa->pub_key);
		dsa->pub_key = NULL;
	}

	dsa->pub_key = OSSL::byteString2bn(inY);
}

// Retrieve the OpenSSL representation of the key
DSA* OSSLDSAPublicKey::getOSSLKey()
{
	return dsa;
}

