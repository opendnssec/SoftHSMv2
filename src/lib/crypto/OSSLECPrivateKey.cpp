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
 OSSLECPrivateKey.cpp

 OpenSSL EC private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>

// Constructors
OSSLECPrivateKey::OSSLECPrivateKey()
{
	eckey = EC_KEY_new();
}

OSSLECPrivateKey::OSSLECPrivateKey(const EC_KEY* inECKEY)
{
	OSSLECPrivateKey();

	setFromOSSL(inECKEY);
}

// Destructor
OSSLECPrivateKey::~OSSLECPrivateKey()
{
	EC_KEY_free(eckey);
}

// The type
/*static*/ const char* OSSLECPrivateKey::type = "OpenSSL EC Private Key";

// Get the base point order length
unsigned long OSSLECPrivateKey::getOrderLength() const
{
	const EC_GROUP* grp = EC_KEY_get0_group(eckey);
	if (grp != NULL)
	{
		BIGNUM* order = BN_new();
		if (order == NULL)
			return 0;
		if (!EC_GROUP_get_order(grp, order, NULL))
		{
			BN_clear_free(order);
			return 0;
		}
		unsigned long len = BN_num_bytes(order);
		BN_clear_free(order);
		return len;
	}
	return 0;
}

// Set from OpenSSL representation
void OSSLECPrivateKey::setFromOSSL(const EC_KEY* eckey)
{
	const EC_GROUP* grp = EC_KEY_get0_group(eckey);
	if (grp != NULL)
	{
		ByteString ec = OSSL::grp2ByteString(grp);
		setEC(ec);
	}
	const BIGNUM* pk = EC_KEY_get0_private_key(eckey);
	if (pk != NULL)
	{
		ByteString d = OSSL::bn2ByteString(pk);
		setD(d);
	}
}

// Check if the key is of the given type
bool OSSLECPrivateKey::isOfType(const char* type)
{
	return !strcmp(OSSLECPrivateKey::type, type);
}

// Setters for the EC private key components
void OSSLECPrivateKey::setD(const ByteString& d)
{
	ECPrivateKey::setD(d);

	BIGNUM* pk = OSSL::byteString2bn(d);
	EC_KEY_set_private_key(eckey, pk);
	BN_clear_free(pk);
}


// Setters for the EC public key components
void OSSLECPrivateKey::setEC(const ByteString& ec)
{
	ECPrivateKey::setEC(ec);

	EC_GROUP* grp = OSSL::byteString2grp(ec);
	EC_KEY_set_group(eckey, grp);
	EC_GROUP_free(grp);
}

// Retrieve the OpenSSL representation of the key
EC_KEY* OSSLECPrivateKey::getOSSLKey()
{
	return eckey;
}
#endif
