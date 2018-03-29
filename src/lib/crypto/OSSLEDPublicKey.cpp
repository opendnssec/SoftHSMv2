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
 OSSLEDPublicKey.cpp

 OpenSSL EDDSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "log.h"
#include "DerUtil.h"
#include "OSSLEDPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/x509.h>
#include <string.h>

#define X25519_KEYLEN	32
#define X448_KEYLEN	57

#define PREFIXLEN	12

// Prefixes
const unsigned char x25519_prefix[] = {
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x6e, 0x03, 0x21, 0x00
};

const unsigned char x448_prefix[] = {
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x6f, 0x03, 0x21, 0x00
};

const unsigned char ed25519_prefix[] = {
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x70, 0x03, 0x21, 0x00
};

const unsigned char ed448_prefix[] = {
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x71, 0x03, 0x21, 0x00
};

// Constructors
OSSLEDPublicKey::OSSLEDPublicKey()
{
	nid = NID_undef;
	pkey = NULL;
}

OSSLEDPublicKey::OSSLEDPublicKey(const EVP_PKEY* inPKEY)
{
	nid = NID_undef;
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLEDPublicKey::~OSSLEDPublicKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLEDPublicKey::type = "OpenSSL EDDSA Public Key";

// Get the base point order length
unsigned long OSSLEDPublicKey::getOrderLength() const
{
	if (nid == NID_ED25519)
		return X25519_KEYLEN;
	if (nid == NID_ED448)
		return X448_KEYLEN;
	return 0;
}

// Set from OpenSSL representation
void OSSLEDPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	nid = EVP_PKEY_id(inPKEY);
	if (nid == NID_undef)
	{
		return;
	}
	ByteString inEC = OSSL::oid2ByteString(nid);
	EDPublicKey::setEC(inEC);

	// i2d_PUBKEY incorrectly does not const the key argument?!
        EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
	int len = i2d_PUBKEY(key, NULL);
	if (len <= 0)
	{
		ERROR_MSG("Could not encode EDDSA public key");
		return;
	}
	ByteString der;
	der.resize(len);
	unsigned char *p = &der[0];
	i2d_PUBKEY(key, &p);
	ByteString raw;
	switch (nid) {
	case NID_X25519:
	case NID_ED25519:
		if (len != (X25519_KEYLEN + PREFIXLEN))
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN + PREFIXLEN, len);
			return;
		}
		raw.resize(X25519_KEYLEN);
		memcpy(&raw[0], &der[PREFIXLEN], X25519_KEYLEN);
		break;
	case NID_X448:
	case NID_ED448:
		if (len != (X448_KEYLEN + PREFIXLEN))
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN + PREFIXLEN, len);
			return;
		}
		raw.resize(X448_KEYLEN);
		memcpy(&raw[0], &der[PREFIXLEN], X448_KEYLEN);
		break;
	default:
		return;
	}
	setA(DERUTIL::raw2Octet(raw));
}

// Check if the key is of the given type
bool OSSLEDPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EDDSA public key components
void OSSLEDPublicKey::setEC(const ByteString& inEC)
{
	EDPublicKey::setEC(inEC);

	nid = OSSL::byteString2oid(inEC);
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

void OSSLEDPublicKey::setA(const ByteString& inA)
{
	EDPublicKey::setA(inA);

	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLEDPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLEDPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString der;
	ByteString raw = DERUTIL::octet2Raw(a);
	size_t len = raw.size();
	if (len == 0) return;

	switch (nid) {
	case NID_X25519:
		if (len != X25519_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + X25519_KEYLEN);
		memcpy(&der[0], x25519_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), X25519_KEYLEN);
		break;
	case NID_ED25519:
		if (len != X25519_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + X25519_KEYLEN);
		memcpy(&der[0], ed25519_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), X25519_KEYLEN);
		break;
	case NID_X448:
		if (len != X448_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + X448_KEYLEN);
		memcpy(&der[0], x448_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), X448_KEYLEN);
		break;
	case NID_ED448:
		if (len != X448_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + X448_KEYLEN);
		memcpy(&der[0], ed448_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), X448_KEYLEN);
		break;
	default:
		return;
	}
	const unsigned char *p = &der[0];
	pkey = d2i_PUBKEY(NULL, &p, (long)der.size());
}
#endif
