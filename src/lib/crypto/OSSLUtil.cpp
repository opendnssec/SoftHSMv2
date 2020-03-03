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
 OSSLUtil.h

 OpenSSL convenience functions
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "DerUtil.h"
#include "OSSLUtil.h"
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// Convert an OpenSSL BIGNUM to a ByteString
ByteString OSSL::bn2ByteString(const BIGNUM* bn)
{
	ByteString rv;

	if (bn != NULL)
	{
		rv.resize(BN_num_bytes(bn));
		BN_bn2bin(bn, &rv[0]);
	}

	return rv;
}

// Convert a ByteString to an OpenSSL BIGNUM
BIGNUM* OSSL::byteString2bn(const ByteString& byteString)
{
	if (byteString.size() == 0) return NULL;

	return BN_bin2bn(byteString.const_byte_str(), byteString.size(), NULL);
}

#ifdef WITH_ECC
// Convert an OpenSSL EC GROUP to a ByteString
ByteString OSSL::grp2ByteString(const EC_GROUP* grp)
{
	ByteString rv;

	if (grp != NULL)
	{
		rv.resize(i2d_ECPKParameters(grp, NULL));
		unsigned char *p = &rv[0];
		i2d_ECPKParameters(grp, &p);
	}

	return rv;
}

// Convert a ByteString to an OpenSSL EC GROUP
EC_GROUP* OSSL::byteString2grp(const ByteString& byteString)
{
	const unsigned char *p = byteString.const_byte_str();
	return d2i_ECPKParameters(NULL, &p, byteString.size());
}

// POINT_CONVERSION_UNCOMPRESSED		0x04

// Convert an OpenSSL EC POINT in the given EC GROUP to a ByteString
ByteString OSSL::pt2ByteString(const EC_POINT* pt, const EC_GROUP* grp)
{
	ByteString raw;

	if (pt == NULL || grp == NULL)
		return raw;

	size_t len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	raw.resize(len);
	EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, &raw[0], len, NULL);

	return DERUTIL::raw2Octet(raw);
}

// Convert a ByteString to an OpenSSL EC POINT in the given EC GROUP
EC_POINT* OSSL::byteString2pt(const ByteString& byteString, const EC_GROUP* grp)
{
	ByteString raw = DERUTIL::octet2Raw(byteString);
	size_t len = raw.size();
	if (len == 0) return NULL;

	EC_POINT* pt = EC_POINT_new(grp);
	if (!EC_POINT_oct2point(grp, pt, &raw[0], len, NULL))
	{
		ERROR_MSG("EC_POINT_oct2point failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_POINT_free(pt);
		return NULL;
	}
	return pt;
}
#endif

#ifdef WITH_EDDSA
// Convert an OpenSSL NID to a ByteString
ByteString OSSL::oid2ByteString(int nid)
{
	ByteString rv;
	std::string name;

	switch (nid)
	{
		case EVP_PKEY_ED25519:
			name = "edwards25519";
			break;

		case EVP_PKEY_X25519:
			name = "curve25519";
			break;

		default:
			return rv;
	}

	ASN1_PRINTABLESTRING *str = ASN1_PRINTABLESTRING_new();
	ASN1_STRING_set(str, name.c_str(), name.length());
	rv.resize(i2d_ASN1_PRINTABLESTRING(str, NULL));
	unsigned char *p = &rv[0];
	i2d_ASN1_PRINTABLESTRING(str, &p);
	ASN1_PRINTABLESTRING_free(str);

	return rv;
}

// Convert a ByteString to an OpenSSL EVP_PKEY id
int OSSL::byteString2oid(const ByteString& byteString)
{
	ASN1_OBJECT *oid = NULL;
	ASN1_PRINTABLESTRING *curve_name = NULL;
	const unsigned char *p = byteString.const_byte_str();
	const unsigned char *pp = p;
	long length;
	int tag, pclass;

	ASN1_get_object(&pp, &length, &tag, &pclass, byteString.size());
	if (pclass == V_ASN1_UNIVERSAL && tag == V_ASN1_OBJECT)
	{
		/* The initial release of SoftHSM was expecting just OID value */
		oid = d2i_ASN1_OBJECT(NULL, &p, byteString.size());

		if (oid == NULL)
		{
			return NID_undef;
		}

		return OBJ_obj2nid(oid);
	}
	else if (pclass == V_ASN1_UNIVERSAL && tag == V_ASN1_PRINTABLESTRING)
	{
		/* The final PKCS#11 3.0 expects curve name encoded as PrintableString */
		curve_name = d2i_ASN1_PRINTABLESTRING(NULL, &p, byteString.size());

		if (strcmp((char *)curve_name->data, "edwards25519") == 0)
		{
			return EVP_PKEY_ED25519;
		}

		if (strcmp((char *)curve_name->data, "curve25519") == 0)
		{
			return EVP_PKEY_X25519;
		}
	}

	return NID_undef;
}
#endif
