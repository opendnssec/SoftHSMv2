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
 OSSLDSAPrivateKey.cpp

 OpenSSL DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDSAPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLDSAPrivateKey::OSSLDSAPrivateKey()
{
	dsa = DSA_new();
}

OSSLDSAPrivateKey::OSSLDSAPrivateKey(const DSA* inDSA)
{
	OSSLDSAPrivateKey();
	setFromOSSL(inDSA);
}

// Destructor
OSSLDSAPrivateKey::~OSSLDSAPrivateKey()
{
	DSA_free(dsa);
}

// The type
/*static*/ const char* OSSLDSAPrivateKey::type = "OpenSSL DSA Private Key";

// Set from OpenSSL representation
void OSSLDSAPrivateKey::setFromOSSL(const DSA* dsa)
{
	if (dsa->p) { ByteString p = OSSL::bn2ByteString(dsa->p); setP(p); }
	if (dsa->q) { ByteString q = OSSL::bn2ByteString(dsa->q); setQ(q); }
	if (dsa->g) { ByteString g = OSSL::bn2ByteString(dsa->g); setG(g); }
	if (dsa->priv_key) { ByteString x = OSSL::bn2ByteString(dsa->priv_key); setX(x); }
}

// Check if the key is of the given type
bool OSSLDSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(OSSLDSAPrivateKey::type, type);
}

// Setters for the DSA private key components
void OSSLDSAPrivateKey::setX(const ByteString& x)
{
	DSAPrivateKey::setX(x);

	if (dsa->priv_key) 
	{
		BN_clear_free(dsa->priv_key);
		dsa->priv_key = NULL;
	}

	dsa->priv_key = OSSL::byteString2bn(x);
}


// Setters for the DSA domain parameters
void OSSLDSAPrivateKey::setP(const ByteString& p)
{
	DSAPrivateKey::setP(p);

	if (dsa->p) 
	{
		BN_clear_free(dsa->p);
		dsa->p = NULL;
	}

	dsa->p = OSSL::byteString2bn(p);
}

void OSSLDSAPrivateKey::setQ(const ByteString& q)
{
	DSAPrivateKey::setQ(q);

	if (dsa->q) 
	{
		BN_clear_free(dsa->q);
		dsa->q = NULL;
	}

	dsa->q = OSSL::byteString2bn(q);
}

void OSSLDSAPrivateKey::setG(const ByteString& g)
{
	DSAPrivateKey::setG(g);

	if (dsa->g) 
	{
		BN_clear_free(dsa->g);
		dsa->g = NULL;
	}

	dsa->g = OSSL::byteString2bn(g);
}

// Retrieve the OpenSSL representation of the key
DSA* OSSLDSAPrivateKey::getOSSLKey()
{
	return dsa;
}

