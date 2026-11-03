/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingPublicKey.h

 X-Wing public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_XWINGPUBLICKEY_H
#define _SOFTHSM_V2_XWINGPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"

class XWingPublicKey : public PublicKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the ciphertext length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Set the X-Wing public key
	virtual void setValue(const ByteString& value);

	// Get the X-Wing public key value
	virtual const ByteString& getValue() const;

	// Get the component public key values
	virtual ByteString getMLKEMValue() const;
	virtual ByteString getX25519Value() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	// Public key value
	ByteString value;
};

#endif // !_SOFTHSM_V2_XWINGPUBLICKEY_H
