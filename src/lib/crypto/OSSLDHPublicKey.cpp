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

	// Use the OpenSSL implementation and not any engine
	DH_set_method(dh, DH_get_default_method());
}

OSSLDHPublicKey::OSSLDHPublicKey(const DH* inDH)
{
	dh = DH_new();

	// Use the OpenSSL implementation and not any engine
	DH_set_method(dh, DH_OpenSSL());

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
	if (inDH->p)
	{
		ByteString inP = OSSL::bn2ByteString(inDH->p);
		setP(inP);
	}
	if (inDH->g)
	{
		ByteString inG = OSSL::bn2ByteString(inDH->g);
		setG(inG);
	}
	if (inDH->pub_key)
	{
		ByteString inY = OSSL::bn2ByteString(inDH->pub_key);
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

	if (dh->p)
	{
		BN_clear_free(dh->p);
		dh->p = NULL;
	}

	dh->p = OSSL::byteString2bn(inP);
}

void OSSLDHPublicKey::setG(const ByteString& inG)
{
	DHPublicKey::setG(inG);

	if (dh->g)
	{
		BN_clear_free(dh->g);
		dh->g = NULL;
	}

	dh->g = OSSL::byteString2bn(inG);
}

void OSSLDHPublicKey::setY(const ByteString& inY)
{
	DHPublicKey::setY(inY);

	if (dh->pub_key)
	{
		BN_clear_free(dh->pub_key);
		dh->pub_key = NULL;
	}

	dh->pub_key = OSSL::byteString2bn(inY);
}

// Retrieve the OpenSSL representation of the key
DH* OSSLDHPublicKey::getOSSLKey()
{
	return dh;
}

