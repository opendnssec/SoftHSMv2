/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 EDDSAMechanismParam.h

 EdDSA mechanism parameters used for signing/verifying operations
 *****************************************************************************/

#ifndef _SOFTHSM_V2_EDDSAMECHANISMPARAM_H
#define _SOFTHSM_V2_EDDSAMECHANISMPARAM_H

#include "config.h"
#ifdef WITH_EDDSA
#include "ByteString.h"
#include "MechanismParam.h"

class EDDSAMechanismParam : public MechanismParam
{
public:

	// EdDSA parameters from ck_eddsa_params
	bool prehash;  // false = no pre-hash (pure), true = with pre-hash (ph)
	ByteString contextData;

	// The type
	static const char* type;

	EDDSAMechanismParam();

	virtual EDDSAMechanismParam* clone() const;

	// Check if the mechanism param is of the given type
	virtual bool isOfType(const char* inType) const;
};

#endif // WITH_EDDSA
#endif // !_SOFTHSM_V2_EDDSAMECHANISMPARAM_H
