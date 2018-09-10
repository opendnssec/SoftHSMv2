/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 BotanUtil.h

 Botan convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANUTIL_H
#define _SOFTHSM_V2_BOTANUTIL_H

#include "config.h"
#include "ByteString.h"
#include <botan/bigint.h>
#if defined(WITH_ECC) || defined(WITH_GOST)
#include <botan/ec_group.h>
#endif

namespace BotanUtil
{
	// Convert a Botan BigInt to a ByteString
	ByteString bigInt2ByteString(const Botan::BigInt& bigInt);
	ByteString bigInt2ByteStringPrefix(const Botan::BigInt& bigInt, size_t size);

	// Convert a ByteString to a Botan BigInt
	Botan::BigInt byteString2bigInt(const ByteString& byteString);

#if defined(WITH_ECC) || defined(WITH_GOST)
	// Convert a Botan EC group to a ByteString
	ByteString ecGroup2ByteString(const Botan::EC_Group& ecGroup);

	// Convert a ByteString to a Botan EC group
	Botan::EC_Group byteString2ECGroup(const ByteString& byteString);

	// Convert a Botan EC point to a ByteString
	ByteString ecPoint2ByteString(const Botan::PointGFp& ecPoint);

	// Convert a ByteString to a Botan EC point in the given EC group
	Botan::PointGFp byteString2ECPoint(const ByteString& byteString, const Botan::EC_Group& ecGroup);
#endif
#ifdef WITH_EDDSA
	// Convert a Botan OID to a ByteString
	ByteString oid2ByteString(const Botan::OID& oid);

	// Convert a ByteString to a Botan OID
	Botan::OID byteString2Oid(const ByteString& byteString);
#endif
}

#endif // !_SOFTHSM_V2_BOTANUTIL_H

