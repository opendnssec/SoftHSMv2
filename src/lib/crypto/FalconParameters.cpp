/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 FalconParameters.cpp

 Falcon parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "FalconParameters.h"
#include <string.h>

// The type
/*static*/ const char* FalconParameters::type = "Falcon parameters";

// Set the parameter set
void FalconParameters::setParameterSet(const unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
unsigned long FalconParameters::getParameterSet() const
{
	return parameterSet;
}

// Are the parameters of the given type?
bool FalconParameters::areOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return strcmp(type, inType) == 0;
}

// Serialisation
ByteString FalconParameters::serialise() const
{
	return ByteString(getParameterSet());
}

bool FalconParameters::deserialise(ByteString& serialised)
{
	if (serialised.size() != 8)
	{
		return false;
	}

	const unsigned long parameter = serialised.long_val();
	if (parameter != FALCON_512_PARAMETER_SET &&
		parameter != FALCON_1024_PARAMETER_SET)
	{
		return false;
	}

	setParameterSet(parameter);
	return true;
}
