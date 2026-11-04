/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 FalconUtil.h

 Falcon convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FALCONUTIL_H
#define _SOFTHSM_V2_FALCONUTIL_H

#include "config.h"
#ifdef WITH_FALCON
#include "FalconPrivateKey.h"
#include "FalconPublicKey.h"
#include "ByteString.h"
#include "Token.h"
#include "OSObject.h"

class FalconUtil
{
public:
	FalconUtil() = delete;
	static CK_RV getFalconPrivateKey(FalconPrivateKey* privateKey, Token* token, OSObject* key);
	static CK_RV getFalconPublicKey(FalconPublicKey* publicKey, Token* token, OSObject* key);

	static bool setFalconPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate);
};

#endif // WITH_FALCON
#endif // !_SOFTHSM_V2_FALCONUTIL_H
