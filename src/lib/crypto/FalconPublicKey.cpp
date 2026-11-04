/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 FalconPublicKey.cpp

 Falcon public key class
 *****************************************************************************/

#include "config.h"
#include "FalconParameters.h"
#include "FalconPublicKey.h"
#include <string.h>

// The type
/*static*/ const char* FalconPublicKey::type = "Abstract Falcon public key";

// Check if the key is of the given type
bool FalconPublicKey::isOfType(const char* inType)
{
	return inType != NULL && strcmp(type, inType) == 0;
}

// Get the bit length
unsigned long FalconPublicKey::getBitLength() const
{
	return getValue().bits();
}

// Get the parameter set
unsigned long FalconPublicKey::getParameterSet() const
{
	switch (value.size())
	{
		case FalconParameters::FALCON_512_PUB_LENGTH:
			return FalconParameters::FALCON_512_PARAMETER_SET;
		case FalconParameters::FALCON_1024_PUB_LENGTH:
			return FalconParameters::FALCON_1024_PARAMETER_SET;
	}
	return 0UL;
}

// Get the maximum signature length
unsigned long FalconPublicKey::getOutputLength() const
{
	switch (value.size())
	{
		case FalconParameters::FALCON_512_PUB_LENGTH:
			return FalconParameters::FALCON_512_SIGNATURE_LENGTH;
		case FalconParameters::FALCON_1024_PUB_LENGTH:
			return FalconParameters::FALCON_1024_SIGNATURE_LENGTH;
	}
	return 0UL;
}

void FalconPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& FalconPublicKey::getValue() const
{
	return value;
}

// Serialisation
ByteString FalconPublicKey::serialise() const
{
	return value.serialise();
}

bool FalconPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserialisedValue = ByteString::chainDeserialise(serialised);
	if (deserialisedValue.size() != FalconParameters::FALCON_512_PUB_LENGTH &&
		deserialisedValue.size() != FalconParameters::FALCON_1024_PUB_LENGTH)
	{
		return false;
	}

	setValue(deserialisedValue);
	return true;
}
