/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingParameters.h

 X-Wing parameters
 *****************************************************************************/

#ifndef _SOFTHSM_V2_XWINGPARAMETERS_H
#define _SOFTHSM_V2_XWINGPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"

class XWingParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;
	static const char* X_WING_OID;

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// X-Wing sizes in bytes, as defined by draft-connolly-cfrg-xwing-kem-10
	static const unsigned long X_WING_PRIV_LENGTH = 32;
	static const unsigned long X_WING_PUB_LENGTH = 1216;
	static const unsigned long X_WING_CIPHERTEXT_LENGTH = 1120;
	static const unsigned long X_WING_SHARED_SECRET_LENGTH = 32;
	static const unsigned long X_WING_ENCAPSULATION_SEED_LENGTH = 64;
	static const unsigned long X_WING_KEY_DERIVATION_LENGTH = 96;

	// Component sizes in bytes
	static const unsigned long ML_KEM_768_SEED_LENGTH = 64;
	static const unsigned long ML_KEM_768_PUB_LENGTH = 1184;
	static const unsigned long ML_KEM_768_CIPHERTEXT_LENGTH = 1088;
	static const unsigned long X25519_PRIV_LENGTH = 32;
	static const unsigned long X25519_PUB_LENGTH = 32;
};

#endif // !_SOFTHSM_V2_XWINGPARAMETERS_H
