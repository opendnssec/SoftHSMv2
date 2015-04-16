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
 OSSLECPublicKey.cpp

 OpenSSL Elliptic Curve public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLECPublicKey::OSSLECPublicKey()
{
	eckey = EC_KEY_new();
}

OSSLECPublicKey::OSSLECPublicKey(const EC_KEY* inECKEY)
{
	eckey = EC_KEY_new();

	setFromOSSL(inECKEY);
}

// Destructor
OSSLECPublicKey::~OSSLECPublicKey()
{
	EC_KEY_free(eckey);
}

// The type
/*static*/ const char* OSSLECPublicKey::type = "OpenSSL EC Public Key";

// Get the base point order length
unsigned long OSSLECPublicKey::getOrderLength() const
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
void OSSLECPublicKey::setFromOSSL(const EC_KEY* inECKEY)
{
	const EC_GROUP* grp = EC_KEY_get0_group(inECKEY);
	if (grp != NULL)
	{
		ByteString inEC = OSSL::grp2ByteString(grp);
		setEC(inEC);
	}
	const EC_POINT* pub = EC_KEY_get0_public_key(inECKEY);
	if (pub != NULL && grp != NULL)
	{
		ByteString inQ = OSSL::pt2ByteString(pub, grp);
		setQ(inQ);
	}
}

// Check if the key is of the given type
bool OSSLECPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EC public key components
void OSSLECPublicKey::setEC(const ByteString& inEC)
{
	ECPublicKey::setEC(inEC);

	EC_GROUP* grp = OSSL::byteString2grp(inEC);
	EC_KEY_set_group(eckey, grp);
	EC_GROUP_free(grp);
}

void OSSLECPublicKey::setQ(const ByteString& inQ)
{
	ECPublicKey::setQ(inQ);

	EC_POINT* pub = OSSL::byteString2pt(inQ, EC_KEY_get0_group(eckey));
	EC_KEY_set_public_key(eckey, pub);
	EC_POINT_free(pub);
}

// Retrieve the OpenSSL representation of the key
EC_KEY* OSSLECPublicKey::getOSSLKey()
{
	return eckey;
}
#endif
