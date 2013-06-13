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
#include "OSSLDHPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLDHPublicKey::OSSLDHPublicKey()
{
	dh = DH_new();
}

OSSLDHPublicKey::OSSLDHPublicKey(const DH* inDH)
{
	OSSLDHPublicKey();

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
void OSSLDHPublicKey::setFromOSSL(const DH* dh)
{
	if (dh->p) { ByteString p = OSSL::bn2ByteString(dh->p); setP(p); }
	if (dh->g) { ByteString g = OSSL::bn2ByteString(dh->g); setG(g); }
	if (dh->pub_key) { ByteString y = OSSL::bn2ByteString(dh->pub_key); setY(y); }
}

// Check if the key is of the given type
bool OSSLDHPublicKey::isOfType(const char* type)
{
	return !strcmp(OSSLDHPublicKey::type, type);
}

// Setters for the DH public key components
void OSSLDHPublicKey::setP(const ByteString& p)
{
	DHPublicKey::setP(p);

	if (dh->p) 
	{
		BN_clear_free(dh->p);
		dh->p = NULL;
	}

	dh->p = OSSL::byteString2bn(p);
}

void OSSLDHPublicKey::setG(const ByteString& g)
{
	DHPublicKey::setG(g);

	if (dh->g) 
	{
		BN_clear_free(dh->g);
		dh->g = NULL;
	}

	dh->g = OSSL::byteString2bn(g);
}

void OSSLDHPublicKey::setY(const ByteString& y)
{
	DHPublicKey::setY(y);

	if (dh->pub_key) 
	{
		BN_clear_free(dh->pub_key);
		dh->pub_key = NULL;
	}

	dh->pub_key = OSSL::byteString2bn(y);
}

// Retrieve the OpenSSL representation of the key
DH* OSSLDHPublicKey::getOSSLKey()
{
	return dh;
}

