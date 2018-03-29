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
 OSSLEDPrivateKey.cpp

 OpenSSL EDDSA private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "log.h"
#include "OSSLEDPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/x509.h>

#define X25519_KEYLEN	32
#define X448_KEYLEN	57

#define PREFIXLEN	16

// Prefixes
const unsigned char x25519_prefix[] = {
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
};

const unsigned char x448_prefix[] = {
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x6f, 0x04, 0x22, 0x04, 0x20
};

const unsigned char ed25519_prefix[] = {
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
};

const unsigned char ed448_prefix[] = {
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x71, 0x04, 0x22, 0x04, 0x20
};

// Constructors
OSSLEDPrivateKey::OSSLEDPrivateKey()
{
	nid = NID_undef;
	pkey = NULL;
}

OSSLEDPrivateKey::OSSLEDPrivateKey(const EVP_PKEY* inPKEY)
{
	nid = NID_undef;
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLEDPrivateKey::~OSSLEDPrivateKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLEDPrivateKey::type = "OpenSSL EDDSA Private Key";

// Get the base point order length
unsigned long OSSLEDPrivateKey::getOrderLength() const
{
	if (nid == NID_ED25519)
		return X25519_KEYLEN;
	if (nid == NID_ED448)
		return X448_KEYLEN;
	return 0;
}

// Set from OpenSSL representation
void OSSLEDPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	nid = EVP_PKEY_id(inPKEY);
	if (nid == NID_undef)
	{
		return;
	}
	ByteString inEC = OSSL::oid2ByteString(nid);
	EDPrivateKey::setEC(inEC);

	// i2d_PrivateKey incorrectly does not const the key argument?!
	EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
	int len = i2d_PrivateKey(key, NULL);
	if (len <= 0)
	{
		ERROR_MSG("Could not encode EDDSA private key");
		return;
	}
	ByteString der;
	der.resize(len);
	unsigned char *p = &der[0];
	i2d_PrivateKey(key, &p);
	ByteString inK;
	switch (nid) {
	case NID_X25519:
	case NID_ED25519:
		if (len != (X25519_KEYLEN + PREFIXLEN))
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN + PREFIXLEN, len);
			return;
		}
		inK.resize(X25519_KEYLEN);
		memcpy(&inK[0], &der[PREFIXLEN], X25519_KEYLEN);
		break;
	case NID_X448:
	case NID_ED448:
		if (len != (X448_KEYLEN + PREFIXLEN))
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN + PREFIXLEN, len);
			return;
		}
		inK.resize(X448_KEYLEN);
		memcpy(&inK[0], &der[PREFIXLEN], X448_KEYLEN);
		break;
	default:
		return;
	}
	setK(inK);
}

// Check if the key is of the given type
bool OSSLEDPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EDDSA private key components
void OSSLEDPrivateKey::setK(const ByteString& inK)
{
	EDPrivateKey::setK(inK);

	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}


// Setters for the EDDSA public key components
void OSSLEDPrivateKey::setEC(const ByteString& inEC)
{
	EDPrivateKey::setEC(inEC);

	nid = OSSL::byteString2oid(inEC);
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString OSSLEDPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(key);
	if (p8 == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
	if (len <= 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		return der;
	}
	der.resize(len);
	unsigned char* p = &der[0];
	i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return der;
}

// Decode from PKCS#8 BER
bool OSSLEDPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* p = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
	if (p8 == NULL) return false;
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL) return false;
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLEDPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLEDPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString der;
	switch (nid) {
	case NID_X25519:
		if (k.size() != X25519_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN, k.size());
			return;
		}
		der.resize(PREFIXLEN + X25519_KEYLEN);
		memcpy(&der[0], x25519_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], k.const_byte_str(), X25519_KEYLEN);
		break;
	case NID_ED25519:
		if (k.size() != X25519_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN, k.size());
			return;
		}
		der.resize(PREFIXLEN + X25519_KEYLEN);
		memcpy(&der[0], ed25519_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], k.const_byte_str(), X25519_KEYLEN);
		break;
	case NID_X448:
		if (k.size() != X448_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN, k.size());
			return;
		}
		der.resize(PREFIXLEN + X448_KEYLEN);
		memcpy(&der[0], x448_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], k.const_byte_str(), X448_KEYLEN);
		break;
	case NID_ED448:
		if (k.size() != X448_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN, k.size());
			return;
		}
		der.resize(PREFIXLEN + X448_KEYLEN);
		memcpy(&der[0], ed448_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], k.const_byte_str(), X448_KEYLEN);
		break;
	default:
		return;
	}
	const unsigned char *p = &der[0];
	pkey = d2i_PrivateKey(nid, NULL, &p, (long)der.size());
}
#endif
