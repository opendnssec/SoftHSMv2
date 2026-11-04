/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingPrivateKey.cpp

 X-Wing private key class
 *****************************************************************************/

#include "config.h"
#include "XWingParameters.h"
#include "XWingPrivateKey.h"
#include <string.h>

// The type
/*static*/ const char* XWingPrivateKey::type = "Abstract X-Wing private key";

// Check if the key is of the given type
bool XWingPrivateKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long XWingPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the ciphertext length
unsigned long XWingPrivateKey::getOutputLength() const
{
	if (value.size() == XWingParameters::X_WING_PRIV_LENGTH)
	{
		return XWingParameters::X_WING_CIPHERTEXT_LENGTH;
	}
	return 0UL;
}

void XWingPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& XWingPrivateKey::getValue() const
{
	return value;
}

// Serialisation
ByteString XWingPrivateKey::serialise() const
{
	return value.serialise();
}

bool XWingPrivateKey::deserialise(ByteString& serialised)
{
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);
	const size_t valueLen = deserializedValue.size();
	if (valueLen != XWingParameters::X_WING_PRIV_LENGTH)
	{
		return false;
	}

	setValue(deserializedValue);
	return true;
}
