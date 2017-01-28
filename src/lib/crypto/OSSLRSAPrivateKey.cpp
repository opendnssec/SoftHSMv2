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
 OSSLRSAPrivateKey.cpp

 OpenSSL RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLComp.h"
#include "OSSLRSAPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

// Constructors
OSSLRSAPrivateKey::OSSLRSAPrivateKey()
{
	rsa = NULL;
}

OSSLRSAPrivateKey::OSSLRSAPrivateKey(const RSA* inRSA)
{
	rsa = NULL;

	setFromOSSL(inRSA);
}

// Destructor
OSSLRSAPrivateKey::~OSSLRSAPrivateKey()
{
	RSA_free(rsa);
}

// The type
/*static*/ const char* OSSLRSAPrivateKey::type = "OpenSSL RSA Private Key";

// Set from OpenSSL representation
void OSSLRSAPrivateKey::setFromOSSL(const RSA* inRSA)
{
	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_q = NULL;
	const BIGNUM* bn_dmp1 = NULL;
	const BIGNUM* bn_dmq1 = NULL;
	const BIGNUM* bn_iqmp = NULL;
	const BIGNUM* bn_n = NULL;
	const BIGNUM* bn_e = NULL;
	const BIGNUM* bn_d = NULL;

	RSA_get0_factors(inRSA, &bn_p, &bn_q);
	RSA_get0_crt_params(inRSA, &bn_dmp1, &bn_dmq1, &bn_iqmp);
	RSA_get0_key(inRSA, &bn_n, &bn_e, &bn_d);

	if (bn_p)
	{
		ByteString inP = OSSL::bn2ByteString(bn_p);
		setP(inP);
	}
	if (bn_q)
	{
		ByteString inQ = OSSL::bn2ByteString(bn_q);
		setQ(inQ);
	}
	if (bn_dmp1)
	{
		ByteString inDP1 = OSSL::bn2ByteString(bn_dmp1);
		setDP1(inDP1);
	}
	if (bn_dmq1)
	{
		ByteString inDQ1 = OSSL::bn2ByteString(bn_dmq1);
		setDQ1(inDQ1);
	}
	if (bn_iqmp)
	{
		ByteString inPQ = OSSL::bn2ByteString(bn_iqmp);
		setPQ(inPQ);
	}
	if (bn_n)
	{
		ByteString inN = OSSL::bn2ByteString(bn_n);
		setN(inN);
	}
	if (bn_e)
	{
		ByteString inE = OSSL::bn2ByteString(bn_e);
		setE(inE);
	}
	if (bn_d)
	{
		ByteString inD = OSSL::bn2ByteString(bn_d);
		setD(inD);
	}
}

// Check if the key is of the given type
bool OSSLRSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the RSA private key components
void OSSLRSAPrivateKey::setP(const ByteString& inP)
{
	RSAPrivateKey::setP(inP);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setQ(const ByteString& inQ)
{
	RSAPrivateKey::setQ(inQ);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setPQ(const ByteString& inPQ)
{
	RSAPrivateKey::setPQ(inPQ);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setDP1(const ByteString& inDP1)
{
	RSAPrivateKey::setDP1(inDP1);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setDQ1(const ByteString& inDQ1)
{
	RSAPrivateKey::setDQ1(inDQ1);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setD(const ByteString& inD)
{
	RSAPrivateKey::setD(inD);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}


// Setters for the RSA public key components
void OSSLRSAPrivateKey::setN(const ByteString& inN)
{
	RSAPrivateKey::setN(inN);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setE(const ByteString& inE)
{
	RSAPrivateKey::setE(inE);

	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString OSSLRSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (rsa == NULL) createOSSLKey();
	if (rsa == NULL) return der;
	EVP_PKEY* pkey = EVP_PKEY_new();
	if (pkey == NULL) return der;
	if (!EVP_PKEY_set1_RSA(pkey, rsa))
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
bool OSSLRSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL) return false;
	RSA* key = EVP_PKEY_get1_RSA(pkey);
	EVP_PKEY_free(pkey);
	if (key == NULL) return false;
	setFromOSSL(key);
	RSA_free(key);
	return true;
}

// Retrieve the OpenSSL representation of the key
RSA* OSSLRSAPrivateKey::getOSSLKey()
{
	if (rsa == NULL) createOSSLKey();

	return rsa;
}

// Create the OpenSSL representation of the key
void OSSLRSAPrivateKey::createOSSLKey()
{
	if (rsa != NULL) return;

	rsa = RSA_new();
	if (rsa == NULL)
	{
		ERROR_MSG("Could not create RSA object");
		return;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		RSA_set_method(rsa, FIPS_rsa_pkcs1_ssleay());
	else
		RSA_set_method(rsa, RSA_PKCS1_SSLeay());
#else
	RSA_set_method(rsa, RSA_PKCS1_SSLeay());
#endif

#else
	RSA_set_method(rsa, RSA_PKCS1_OpenSSL());
#endif

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_q = OSSL::byteString2bn(q);
	BIGNUM* bn_dmp1 = OSSL::byteString2bn(dp1);
	BIGNUM* bn_dmq1 = OSSL::byteString2bn(dq1);
	BIGNUM* bn_iqmp = OSSL::byteString2bn(pq);
	BIGNUM* bn_n = OSSL::byteString2bn(n);
	BIGNUM* bn_e = OSSL::byteString2bn(e);
	BIGNUM* bn_d = OSSL::byteString2bn(d);

	RSA_set0_factors(rsa, bn_p, bn_q);
	RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp);
	RSA_set0_key(rsa, bn_n, bn_e, bn_d);
}

