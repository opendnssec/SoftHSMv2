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
 OSSLGOSTPrivateKey.cpp

 OpenSSL GOST R 34.10-2001 private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "OSSLGOSTPrivateKey.h"
#include "OSSLUtil.h"
#include <string.h>
#include <openssl/x509.h>
#include <openssl/ec.h>

// DER of a private key
const unsigned char dummyKey[] = {
	0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x1c, 0x06,
	0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13, 0x30,
	0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02,
	0x23, 0x01, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02,
	0x02, 0x1e, 0x01, 0x04, 0x22, 0x02, 0x20, 0x1b,
	0x3f, 0x94, 0xf7, 0x1a, 0x5f, 0x2f, 0xe7, 0xe5,
	0x74, 0x0b, 0x8c, 0xd4, 0xb7, 0x18, 0xdd, 0x65,
	0x68, 0x26, 0xd1, 0x54, 0xfb, 0x77, 0xba, 0x63,
	0x72, 0xd9, 0xf0, 0x63, 0x87, 0xe0, 0xd6
};

// Constructors
OSSLGOSTPrivateKey::OSSLGOSTPrivateKey()
{
	pkey = EVP_PKEY_new();
}

OSSLGOSTPrivateKey::OSSLGOSTPrivateKey(const EVP_PKEY* inPKEY)
{
	OSSLGOSTPrivateKey();

	setFromOSSL(inPKEY);
}

// Destructor
OSSLGOSTPrivateKey::~OSSLGOSTPrivateKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLGOSTPrivateKey::type = "OpenSSL GOST Private Key";

// Get the output length
unsigned long OSSLGOSTPrivateKey::getOutputLength() const
{
	return 64;
}

// Set from OpenSSL representation
void OSSLGOSTPrivateKey::setFromOSSL(const EVP_PKEY* pkey)
{
	const EC_KEY* eckey = (const EC_KEY*) EVP_PKEY_get0((EVP_PKEY*) pkey);
	const BIGNUM* priv = EC_KEY_get0_private_key(eckey);
	setD(OSSL::bn2ByteString(priv));

	ByteString inEC;
	int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey));
	inEC.resize(i2d_ASN1_OBJECT(OBJ_nid2obj(nid), NULL));
	unsigned char *p = &inEC[0];
	i2d_ASN1_OBJECT(OBJ_nid2obj(nid), &p);
	setEC(inEC);
}

// Check if the key is of the given type
bool OSSLGOSTPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the GOST private key components
void OSSLGOSTPrivateKey::setD(const ByteString& inD)
{
	GOSTPrivateKey::setD(inD);

	EC_KEY* inEC = (EC_KEY*) EVP_PKEY_get0((EVP_PKEY*) pkey);
	if (inEC == NULL)
	{
		const unsigned char* p = dummyKey;
		if (d2i_PrivateKey(NID_id_GostR3410_2001, &pkey, &p, (long) sizeof(dummyKey)) == NULL)
		{
			ERROR_MSG("d2i_PrivateKey failed");

			return;
		}
		inEC = (EC_KEY*) EVP_PKEY_get0((EVP_PKEY*) pkey);
	}

	const BIGNUM* priv = OSSL::byteString2bn(inD);
	if (EC_KEY_set_private_key(inEC, priv) <= 0)
	{
		ERROR_MSG("EC_KEY_set_private_key failed");
		return;
	}
	BN_clear_free((BIGNUM*)priv);

#ifdef notyet
	if (gost2001_compute_public(inEC) <= 0)
		ERROR_MSG("gost2001_compute_public failed");
#endif
}

// Setters for the GOST public key components
void OSSLGOSTPrivateKey::setEC(const ByteString& inEC)
{
        GOSTPrivateKey::setEC(inEC);
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLGOSTPrivateKey::getOSSLKey()
{
	return pkey;
}

// Serialisation
ByteString OSSLGOSTPrivateKey::serialise() const
{
	return ec.serialise() +
	       d.serialise();
}

bool OSSLGOSTPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dEC = ByteString::chainDeserialise(serialised);
	ByteString dD = ByteString::chainDeserialise(serialised);

	if ((dEC.size() == 0) ||
	    (dD.size() == 0))
	{
		return false;
	}

	setEC(dEC);
	setD(dD);

	return true;
}

// Encode into PKCS#8 DER
ByteString OSSLGOSTPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (pkey == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(pkey);
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
bool OSSLGOSTPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL) return false;
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}
#endif
