/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 FalconPrivateKey.cpp

 Falcon private key class
 *****************************************************************************/

#include "config.h"
#include "FalconParameters.h"
#include "FalconPrivateKey.h"
#include <string.h>

// The type
/*static*/ const char* FalconPrivateKey::type = "Abstract Falcon private key";

// Check if the key is of the given type
bool FalconPrivateKey::isOfType(const char* inType)
{
	return inType != NULL && strcmp(type, inType) == 0;
}

// Get the bit length
unsigned long FalconPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the parameter set
unsigned long FalconPrivateKey::getParameterSet() const
{
	switch (value.size())
	{
		case FalconParameters::FALCON_512_PRIV_LENGTH:
			return FalconParameters::FALCON_512_PARAMETER_SET;
		case FalconParameters::FALCON_1024_PRIV_LENGTH:
			return FalconParameters::FALCON_1024_PARAMETER_SET;
	}
	return 0UL;
}

// Get the maximum signature length
unsigned long FalconPrivateKey::getOutputLength() const
{
	switch (value.size())
	{
		case FalconParameters::FALCON_512_PRIV_LENGTH:
			return FalconParameters::FALCON_512_SIGNATURE_LENGTH;
		case FalconParameters::FALCON_1024_PRIV_LENGTH:
			return FalconParameters::FALCON_1024_SIGNATURE_LENGTH;
	}
	return 0UL;
}

void FalconPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
	publicKeyInfo.wipe();
}

const ByteString& FalconPrivateKey::getValue() const
{
	return value;
}

void FalconPrivateKey::setPublicKeyInfo(const ByteString& inPublicKeyInfo)
{
	publicKeyInfo = inPublicKeyInfo;
}

const ByteString& FalconPrivateKey::getPublicKeyInfo() const
{
	return publicKeyInfo;
}

// Serialisation
ByteString FalconPrivateKey::serialise() const
{
	return value.serialise() + publicKeyInfo.serialise();
}

bool FalconPrivateKey::deserialise(ByteString& serialised)
{
	ByteString deserialisedValue = ByteString::chainDeserialise(serialised);
	if (deserialisedValue.size() != FalconParameters::FALCON_512_PRIV_LENGTH &&
		deserialisedValue.size() != FalconParameters::FALCON_1024_PRIV_LENGTH)
	{
		return false;
	}

	setValue(deserialisedValue);
	setPublicKeyInfo(ByteString::chainDeserialise(serialised));
	return true;
}
