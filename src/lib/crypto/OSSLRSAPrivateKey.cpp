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
#include "OSSLRSAPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <string.h>

// Constructors
OSSLRSAPrivateKey::OSSLRSAPrivateKey()
{
	rsa = RSA_new();

	// Use the OpenSSL implementation and not any engine
	RSA_set_method(rsa, RSA_get_default_method());
}

OSSLRSAPrivateKey::OSSLRSAPrivateKey(const RSA* inRSA)
{
	rsa = RSA_new();

	// Use the OpenSSL implementation and not any engine
	RSA_set_method(rsa, RSA_PKCS1_SSLeay());

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
	if (inRSA->p)
	{
		ByteString inP = OSSL::bn2ByteString(inRSA->p);
		setP(inP);
	}
	if (inRSA->q)
	{
		ByteString inQ = OSSL::bn2ByteString(inRSA->q);
		setQ(inQ);
	}
	if (inRSA->dmp1)
	{
		ByteString inDP1 = OSSL::bn2ByteString(inRSA->dmp1);
		setDP1(inDP1);
	}
	if (inRSA->dmq1)
	{
		ByteString inDQ1 = OSSL::bn2ByteString(inRSA->dmq1);
		setDQ1(inDQ1);
	}
	if (inRSA->iqmp)
	{
		ByteString inPQ = OSSL::bn2ByteString(inRSA->iqmp);
		setPQ(inPQ);
	}
	if (inRSA->d)
	{
		ByteString inD = OSSL::bn2ByteString(inRSA->d);
		setD(inD);
	}
	if (inRSA->n)
	{
		ByteString inN = OSSL::bn2ByteString(inRSA->n);
		setN(inN);
	}
	if (inRSA->e)
	{
		ByteString inE = OSSL::bn2ByteString(inRSA->e);
		setE(inE);
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

	if (rsa->p)
	{
		BN_clear_free(rsa->p);
		rsa->p = NULL;
	}

	rsa->p = OSSL::byteString2bn(inP);
}

void OSSLRSAPrivateKey::setQ(const ByteString& inQ)
{
	RSAPrivateKey::setQ(inQ);

	if (rsa->q)
	{
		BN_clear_free(rsa->q);
		rsa->q = NULL;
	}

	rsa->q = OSSL::byteString2bn(inQ);
}

void OSSLRSAPrivateKey::setPQ(const ByteString& inPQ)
{
	RSAPrivateKey::setPQ(inPQ);

	if (rsa->iqmp)
	{
		BN_clear_free(rsa->iqmp);
		rsa->iqmp = NULL;
	}

	rsa->iqmp = OSSL::byteString2bn(inPQ);
}

void OSSLRSAPrivateKey::setDP1(const ByteString& inDP1)
{
	RSAPrivateKey::setDP1(inDP1);

	if (rsa->dmp1)
	{
		BN_clear_free(rsa->dmp1);
		rsa->dmp1 = NULL;
	}

	rsa->dmp1 = OSSL::byteString2bn(inDP1);
}

void OSSLRSAPrivateKey::setDQ1(const ByteString& inDQ1)
{
	RSAPrivateKey::setDQ1(inDQ1);

	if (rsa->dmq1)
	{
		BN_clear_free(rsa->dmq1);
		rsa->dmq1 = NULL;
	}

	rsa->dmq1 = OSSL::byteString2bn(inDQ1);
}

void OSSLRSAPrivateKey::setD(const ByteString& inD)
{
	RSAPrivateKey::setD(inD);

	if (rsa->d)
	{
		BN_clear_free(rsa->d);
		rsa->d = NULL;
	}

	rsa->d = OSSL::byteString2bn(inD);
}


// Setters for the RSA public key components
void OSSLRSAPrivateKey::setN(const ByteString& inN)
{
	RSAPrivateKey::setN(inN);

	if (rsa->n)
	{
		BN_clear_free(rsa->n);
		rsa->n = NULL;
	}

	rsa->n = OSSL::byteString2bn(inN);
}

void OSSLRSAPrivateKey::setE(const ByteString& inE)
{
	RSAPrivateKey::setE(inE);

	if (rsa->e)
	{
		BN_clear_free(rsa->e);
		rsa->e = NULL;
	}

	rsa->e = OSSL::byteString2bn(inE);
}

// Encode into PKCS#8 DER
ByteString OSSLRSAPrivateKey::PKCS8Encode()
{
	ByteString der;
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
	return rsa;
}

