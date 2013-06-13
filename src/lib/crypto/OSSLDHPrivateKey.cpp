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
 OSSLDHPrivateKey.cpp

 OpenSSL Diffie-Hellman private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDHPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLDHPrivateKey::OSSLDHPrivateKey()
{
	dh = DH_new();
}

OSSLDHPrivateKey::OSSLDHPrivateKey(const DH* inDH)
{
	OSSLDHPrivateKey();
	setFromOSSL(inDH);
}

// Destructor
OSSLDHPrivateKey::~OSSLDHPrivateKey()
{
	DH_free(dh);
}

// The type
/*static*/ const char* OSSLDHPrivateKey::type = "OpenSSL DH Private Key";

// Set from OpenSSL representation
void OSSLDHPrivateKey::setFromOSSL(const DH* dh)
{
	if (dh->p) { ByteString p = OSSL::bn2ByteString(dh->p); setP(p); }
	if (dh->g) { ByteString g = OSSL::bn2ByteString(dh->g); setG(g); }
	if (dh->priv_key) { ByteString x = OSSL::bn2ByteString(dh->priv_key); setX(x); }
}

// Check if the key is of the given type
bool OSSLDHPrivateKey::isOfType(const char* type)
{
	return !strcmp(OSSLDHPrivateKey::type, type);
}

// Setters for the DH private key components
void OSSLDHPrivateKey::setX(const ByteString& x)
{
	DHPrivateKey::setX(x);

	if (dh->priv_key) 
	{
		BN_clear_free(dh->priv_key);
		dh->priv_key = NULL;
	}

	dh->priv_key = OSSL::byteString2bn(x);
}


// Setters for the DH public key components
void OSSLDHPrivateKey::setP(const ByteString& p)
{
	DHPrivateKey::setP(p);

	if (dh->p) 
	{
		BN_clear_free(dh->p);
		dh->p = NULL;
	}

	dh->p = OSSL::byteString2bn(p);
}

void OSSLDHPrivateKey::setG(const ByteString& g)
{
	DHPrivateKey::setG(g);

	if (dh->g) 
	{
		BN_clear_free(dh->g);
		dh->g = NULL;
	}

	dh->g = OSSL::byteString2bn(g);
}

// Retrieve the OpenSSL representation of the key
DH* OSSLDHPrivateKey::getOSSLKey()
{
	return dh;
}

