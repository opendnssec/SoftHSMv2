/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 FalconPublicKey.h

 Falcon public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FALCONPUBLICKEY_H
#define _SOFTHSM_V2_FALCONPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"

class FalconPublicKey : public PublicKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the parameter set
	virtual unsigned long getParameterSet() const;

	// Get the maximum signature length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Set the Falcon public key component
	virtual void setValue(const ByteString& value);

	// Get the Falcon public key component
	virtual const ByteString& getValue() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	ByteString value;
};

#endif // !_SOFTHSM_V2_FALCONPUBLICKEY_H
