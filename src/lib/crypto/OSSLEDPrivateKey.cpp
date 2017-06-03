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

// OpenSSL internal representation
typedef struct {
	unsigned char pubkey[32];
	unsigned char *privkey;
} X25519_KEY;

extern "C" void ED25519_public_from_private(uint8_t pub[32], const uint8_t priv[32]);

// Constructors
OSSLEDPrivateKey::OSSLEDPrivateKey()
{
	nid = NID_undef;
	pkey = EVP_PKEY_new();
}

OSSLEDPrivateKey::OSSLEDPrivateKey(const EVP_PKEY* inPKEY)
{
	nid = NID_undef;
	pkey = EVP_PKEY_new();

	setFromOSSL(inPKEY);
}

// Destructor
OSSLEDPrivateKey::~OSSLEDPrivateKey()
{
	EVP_PKEY_free(pkey);
	pkey = NULL;
}

// The type
/*static*/ const char* OSSLEDPrivateKey::type = "OpenSSL EDDSA Private Key";

// Get the base point order length
unsigned long OSSLEDPrivateKey::getOrderLength() const
{
	if (nid == NID_ED25519)
		return 32;
	return 0;
}

// Set from OpenSSL representation
void OSSLEDPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	nid = EVP_PKEY_id(inPKEY);
	if (nid == NID_ED25519) {
		ByteString inEC = OSSL::oid2ByteString(nid);
		setEC(inEC);
		const X25519_KEY* xk = (X25519_KEY*) EVP_PKEY_get0(inPKEY);
		if (xk != NULL && xk->privkey != NULL) {
			ByteString inK;
			inK.resize(32);
			memcpy(&inK[0], xk->privkey, 32);
			setK(inK);
		}
	}
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

	if (nid == NID_ED25519) {
		X25519_KEY* xk = (X25519_KEY*)OPENSSL_malloc(sizeof(*xk));
		xk->privkey = (unsigned char*)OPENSSL_secure_malloc(32);
		memcpy(xk->privkey, inK.const_byte_str(), 32);
		ED25519_public_from_private(xk->pubkey, xk->privkey);
		(void)EVP_PKEY_assign(pkey, nid, xk);
	}
}


// Setters for the EDDSA public key components
void OSSLEDPrivateKey::setEC(const ByteString& inEC)
{
	EDPrivateKey::setEC(inEC);

	nid = OSSL::byteString2oid(inEC);
}

// Encode into PKCS#8 DER
ByteString OSSLEDPrivateKey::PKCS8Encode()
{
	ByteString der;
	// TODO
	return der;
}

// Decode from PKCS#8 BER
bool OSSLEDPrivateKey::PKCS8Decode(const ByteString& /*ber*/)
{
	// TODO
	return false;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLEDPrivateKey::getOSSLKey()
{
	return pkey;
}
#endif
