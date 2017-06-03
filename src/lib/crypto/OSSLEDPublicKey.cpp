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
#include "OSSLEDPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// OpenSSL internal representation
typedef struct {
	unsigned char pubkey[32];
	unsigned char *privkey;
} X25519_KEY;

// Constructors
OSSLEDPublicKey::OSSLEDPublicKey()
{
	nid = NID_undef;
	pkey = EVP_PKEY_new();
}

OSSLEDPublicKey::OSSLEDPublicKey(const EVP_PKEY* inPKEY)
{
	nid = NID_undef;
	pkey = EVP_PKEY_new();

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
		return 32;
	return 0;
}

// Set from OpenSSL representation
void OSSLEDPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	nid = EVP_PKEY_id(inPKEY);
	if (nid == NID_ED25519) {
		ByteString inEC = OSSL::oid2ByteString(nid);
		setEC(inEC);
		const X25519_KEY* xk = (X25519_KEY*) EVP_PKEY_get0(inPKEY);
		if (xk != NULL) {
			ByteString inA;
			inA.resize(32);
			memcpy(&inA[0], xk->pubkey, 32);
			setA(inA);
		}
	}
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
}

void OSSLEDPublicKey::setA(const ByteString& inA)
{
	EDPublicKey::setA(inA);

	if (nid == NID_ED25519) {
		X25519_KEY* xk = (X25519_KEY*)OPENSSL_malloc(sizeof(*xk));
		xk->privkey = NULL;
		memcpy(xk->pubkey, inA.const_byte_str(), 32);
		(void)EVP_PKEY_assign(pkey, nid, xk);
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLEDPublicKey::getOSSLKey()
{
	return pkey;
}
#endif
