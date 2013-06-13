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
 OSSLGOSTPublicKey.cpp

 OpenSSL GOST R 34.10-2001 public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "OSSLGOSTPublicKey.h"
#include <openssl/x509.h>
#include <string.h>

// the 37 bytes of prefix
const ByteString gost_prefix = "3063301c06062a8503020213301206072a85030202230106072a850302021e010343000440";

// Constructors
OSSLGOSTPublicKey::OSSLGOSTPublicKey()
{
	pkey = EVP_PKEY_new();
}

OSSLGOSTPublicKey::OSSLGOSTPublicKey(const EVP_PKEY* inPKEY)
{
	OSSLGOSTPublicKey();

	setFromOSSL(inPKEY);
}

// Destructor
OSSLGOSTPublicKey::~OSSLGOSTPublicKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLGOSTPublicKey::type = "OpenSSL GOST Public Key";

// Get the output length
unsigned long OSSLGOSTPublicKey::getOutputLength() const
{
	return getQ().size();
}

// Set from OpenSSL representation
void OSSLGOSTPublicKey::setFromOSSL(const EVP_PKEY* pkey)
{
	ByteString der;
	int len = i2d_PUBKEY((EVP_PKEY*) pkey, NULL);
	if (len != 37 + 64)
	{
		ERROR_MSG("bad GOST public key encoding length %d", len);
		return;
	}
	der.resize(len);
	unsigned char *p = &der[0];
	i2d_PUBKEY((EVP_PKEY*) pkey, &p);
	// can check: der is prefix + 64 bytes
	setQ(der.substr(37));
}

// Check if the key is of the given type
bool OSSLGOSTPublicKey::isOfType(const char* type)
{
	return !strcmp(OSSLGOSTPublicKey::type, type);
}

// Setters for the GOST public key components
void OSSLGOSTPublicKey::setQ(const ByteString& q)
{
	this->q = q;

	if (q.size() != 64)
	{
		ERROR_MSG("bad GOST public key size %zu", q.size());
		return;
	}

	ByteString der;
	der.resize(37 + 64);
	memcpy(&der[0], gost_prefix.const_byte_str(), 37);
	memcpy(&der[37], q.const_byte_str(), 64);
	const unsigned char *p = &der[0];
	if (d2i_PUBKEY(&pkey, &p, (long) der.size()) == NULL)
		ERROR_MSG("d2i_PUBKEY failed");
}

// Serialisation
ByteString OSSLGOSTPublicKey::serialise() const
{
	return q.serialise();
}

bool OSSLGOSTPublicKey::deserialise(ByteString& serialised)
{
	ByteString dQ = ByteString::chainDeserialise(serialised);

	if (dQ.size() == 0)
	{
		return false;
	}

	setQ(dQ);

	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLGOSTPublicKey::getOSSLKey()
{
	return pkey;
}
#endif
