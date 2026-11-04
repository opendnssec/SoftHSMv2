/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingPublicKey.cpp

 X-Wing public key class
 *****************************************************************************/

#include "config.h"
#include "XWingParameters.h"
#include "XWingPublicKey.h"
#include <string.h>

// The type
/*static*/ const char* XWingPublicKey::type = "Abstract X-Wing public key";

// Check if the key is of the given type
bool XWingPublicKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long XWingPublicKey::getBitLength() const
{
	return getValue().bits();
}

// Get the ciphertext length
unsigned long XWingPublicKey::getOutputLength() const
{
	if (value.size() == XWingParameters::X_WING_PUB_LENGTH)
	{
		return XWingParameters::X_WING_CIPHERTEXT_LENGTH;
	}
	return 0UL;
}

void XWingPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& XWingPublicKey::getValue() const
{
	return value;
}

ByteString XWingPublicKey::getMLKEMValue() const
{
	if (value.size() != XWingParameters::X_WING_PUB_LENGTH)
	{
		return ByteString();
	}
	return value.substr(0, XWingParameters::ML_KEM_768_PUB_LENGTH);
}

ByteString XWingPublicKey::getX25519Value() const
{
	if (value.size() != XWingParameters::X_WING_PUB_LENGTH)
	{
		return ByteString();
	}
	return value.substr(XWingParameters::ML_KEM_768_PUB_LENGTH,
	                    XWingParameters::X25519_PUB_LENGTH);
}

// Serialisation
ByteString XWingPublicKey::serialise() const
{
	return value.serialise();
}

bool XWingPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);
	const size_t valueLen = deserializedValue.size();
	if (valueLen != XWingParameters::X_WING_PUB_LENGTH)
	{
		return false;
	}

	setValue(deserializedValue);
	return true;
}
