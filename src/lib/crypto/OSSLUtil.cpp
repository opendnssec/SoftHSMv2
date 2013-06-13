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
#include "OSSLUtil.h"
#include <openssl/asn1.h>

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
	ByteString rv;

	if (pt != NULL && grp != NULL)
	{
		size_t len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
		if (len > 0x7f)
		{
			ERROR_MSG("Oversized EC point");

			return rv;
		}
		rv.resize(len + 2);
		rv[0] = V_ASN1_OCTET_STRING;
		rv[1] = len & 0x7f;
		EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, &rv[2], len, NULL);
	}

	return rv;
}

// Convert a ByteString to an OpenSSL EC POINT in the given EC GROUP
EC_POINT* OSSL::byteString2pt(const ByteString& byteString, const EC_GROUP* grp)
{
	size_t len = byteString.size();
	if (len < 2)
	{
		ERROR_MSG("Undersized EC point");

		return NULL;
	}
	len -= 2;
	if (len > 0x7f)
	{
		ERROR_MSG("Oversized EC point");

		return NULL;
	}
	ByteString repr = byteString;
	if (repr[0] != V_ASN1_OCTET_STRING)
	{
		ERROR_MSG("EC point tag is not OCTET STRING");

		return NULL;
	}
	if (repr[1] != len)
	{
		if (repr[1] < len)
		{
			ERROR_MSG("Underrun EC point");
		}
		else
		{
			ERROR_MSG("Overrun EC point");
		}

		return NULL;
	}

	EC_POINT* pt = EC_POINT_new(grp);
	if (!EC_POINT_oct2point(grp, pt, &repr[2], len, NULL))
	{
		EC_POINT_free(pt);
		return NULL;
	}
	return pt;
}
#endif
