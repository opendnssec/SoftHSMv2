/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 EDDSAUtil.h

 EdDSA convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_EDDSAUTIL_H
#define _SOFTHSM_V2_EDDSAUTIL_H

#include "config.h"
#ifdef WITH_EDDSA
#include "EDDSAMechanismParam.h"
#include "MechanismParam.h"
#include "cryptoki.h"

class EDDSAUtil
{
public:
	EDDSAUtil() = delete;

	// Translate the CKM_EDDSA mechanism parameters, if any, into an EDDSAMechanismParam
	static CK_RV getEddsaParam(CK_MECHANISM_PTR pMechanism, EDDSAMechanismParam& eddsaParam, MechanismParam** mechanismParam);
};

#endif // !WITH_EDDSA
#endif // !_SOFTHSM_V2_EDDSAUTIL_H
