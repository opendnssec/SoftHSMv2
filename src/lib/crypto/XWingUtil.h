/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 XWingUtil.h

 X-Wing convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_XWINGUTIL_H
#define _SOFTHSM_V2_XWINGUTIL_H

#include "config.h"
#ifdef WITH_X_WING
#include "XWingPrivateKey.h"
#include "XWingPublicKey.h"
#include "ByteString.h"
#include "Token.h"
#include "OSObject.h"

class XWingUtil
{
public:
	XWingUtil() = delete;
	static CK_RV getXWingPrivateKey(XWingPrivateKey* privateKey, Token* token, OSObject* key);
	static CK_RV getXWingPublicKey(XWingPublicKey* publicKey, Token* token, OSObject* key);

	static bool setXWingPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate);
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_XWINGUTIL_H
