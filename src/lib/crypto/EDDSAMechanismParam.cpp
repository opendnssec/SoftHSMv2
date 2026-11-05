/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 EDDSAMechanismParam.cpp

 EdDSA mechanism parameters used for signing/verifying operations
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "ByteString.h"
#include "MechanismParam.h"
#include "EDDSAMechanismParam.h"
#include <string.h>

EDDSAMechanismParam::EDDSAMechanismParam()
{
	prehash = false;
}

// Set the type
/*static*/ const char* EDDSAMechanismParam::type = "EdDSA Signature param";

EDDSAMechanismParam* EDDSAMechanismParam::clone() const
{
	return new EDDSAMechanismParam(*this);
}

// Check if the parameter is of the given type
bool EDDSAMechanismParam::isOfType(const char* inType) const
{
	return !strcmp(type, inType);
}
#endif
