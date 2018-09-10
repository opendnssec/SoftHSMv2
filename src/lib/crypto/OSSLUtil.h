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

#ifndef _SOFTHSM_V2_OSSLUTIL_H
#define _SOFTHSM_V2_OSSLUTIL_H

#include "config.h"
#include "ByteString.h"
#include <openssl/bn.h>
#ifdef WITH_ECC
#include <openssl/ec.h>
#endif
#ifdef WITH_EDDSA
#include <openssl/objects.h>
#endif

namespace OSSL
{
	// Convert an OpenSSL BIGNUM to a ByteString
	ByteString bn2ByteString(const BIGNUM* bn);

	// Convert a ByteString to an OpenSSL BIGNUM
	BIGNUM* byteString2bn(const ByteString& byteString);

#ifdef WITH_ECC
	// Convert an OpenSSL EC GROUP to a ByteString
	ByteString grp2ByteString(const EC_GROUP* grp);

	// Convert a ByteString to an OpenSSL EC GROUP
	EC_GROUP* byteString2grp(const ByteString& byteString);

	// Convert an OpenSSL EC POINT in the given EC GROUP to a ByteString
	ByteString pt2ByteString(const EC_POINT* pt, const EC_GROUP* grp);

	// Convert a ByteString to an OpenSSL EC POINT in the given EC GROUP
	EC_POINT* byteString2pt(const ByteString& byteString, const EC_GROUP* grp);
#endif

#ifdef WITH_EDDSA
	// Convert an OpenSSL NID to a ByteString
	ByteString oid2ByteString(int nid);

	// Convert a ByteString to an OpenSSL NID
	int byteString2oid(const ByteString& byteString);
#endif
}

#endif // !_SOFTHSM_V2_OSSLUTIL_H

