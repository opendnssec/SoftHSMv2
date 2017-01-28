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
#include "OSSLComp.h"
#include "OSSLDHPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

// Constructors
OSSLDHPrivateKey::OSSLDHPrivateKey()
{
	dh = NULL;
}

OSSLDHPrivateKey::OSSLDHPrivateKey(const DH* inDH)
{
	dh = NULL;

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
void OSSLDHPrivateKey::setFromOSSL(const DH* inDH)
{
	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_g = NULL;
	const BIGNUM* bn_priv_key = NULL;

	DH_get0_pqg(inDH, &bn_p, NULL, &bn_g);
	DH_get0_key(inDH, NULL, &bn_priv_key);

	if (bn_p)
	{
		ByteString inP = OSSL::bn2ByteString(bn_p);
		setP(inP);
	}
	if (bn_g)
	{
		ByteString inG = OSSL::bn2ByteString(bn_g);
		setG(inG);
	}
	if (bn_priv_key)
	{
		ByteString inX = OSSL::bn2ByteString(bn_priv_key);
		setX(inX);
	}
}

// Check if the key is of the given type
bool OSSLDHPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DH private key components
void OSSLDHPrivateKey::setX(const ByteString& inX)
{
	DHPrivateKey::setX(inX);

	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}


// Setters for the DH public key components
void OSSLDHPrivateKey::setP(const ByteString& inP)
{
	DHPrivateKey::setP(inP);

	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}

void OSSLDHPrivateKey::setG(const ByteString& inG)
{
	DHPrivateKey::setG(inG);

	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString OSSLDHPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (dh == NULL) createOSSLKey();
	if (dh == NULL) return der;
	EVP_PKEY* pkey = EVP_PKEY_new();
	if (pkey == NULL) return der;
	if (!EVP_PKEY_set1_DH(pkey, dh))
	{
		EVP_PKEY_free(pkey);
		return der;
	}
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(pkey);
	EVP_PKEY_free(pkey);
	if (p8inf == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLDHPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL) return false;
	DH* key = EVP_PKEY_get1_DH(pkey);
	EVP_PKEY_free(pkey);
	if (key == NULL) return false;
	setFromOSSL(key);
	DH_free(key);
	return true;
}

// Retrieve the OpenSSL representation of the key
DH* OSSLDHPrivateKey::getOSSLKey()
{
	if (dh == NULL) createOSSLKey();

	return dh;
}

// Create the OpenSSL representation of the key
void OSSLDHPrivateKey::createOSSLKey()
{
	if (dh != NULL) return;

	BN_CTX *ctx = BN_CTX_new();
	if (ctx == NULL)
	{
		ERROR_MSG("Could not create BN_CTX");
		return;
	}

	dh = DH_new();
	if (dh == NULL)
	{
		ERROR_MSG("Could not create DH object");
		return;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		DH_set_method(dh, FIPS_dh_openssl());
	else
		DH_set_method(dh, DH_OpenSSL());
#else
	DH_set_method(dh, DH_OpenSSL());
#endif

#else
	DH_set_method(dh, DH_OpenSSL());
#endif

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_priv_key = OSSL::byteString2bn(x);
	BIGNUM* bn_pub_key = BN_new();

	BN_mod_exp(bn_pub_key, bn_g, bn_priv_key, bn_p, ctx);
	BN_CTX_free(ctx);

	DH_set0_pqg(dh, bn_p, NULL, bn_g);
	DH_set0_key(dh, bn_pub_key, bn_priv_key);
}

