/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 FalconParameters.h

 Falcon parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FALCONPARAMETERS_H
#define _SOFTHSM_V2_FALCONPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"
#include "ByteString.h"

class FalconParameters : public AsymmetricParameters
{
public:
	FalconParameters() : parameterSet(0) { }

	// The type
	static const char* type;

	// Get the Falcon parameter set
	virtual unsigned long getParameterSet() const;

	// Set the Falcon parameter set
	virtual void setParameterSet(const unsigned long parameterSet);

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// Falcon values for CKA_PARAMETER_SET.
	static const unsigned long FALCON_512_PARAMETER_SET = CKP_FALCON_512;
	static const unsigned long FALCON_1024_PARAMETER_SET = CKP_FALCON_1024;

	// Raw key component and maximum signature sizes exposed by OQS Provider.
	static const unsigned long FALCON_512_PRIV_LENGTH = 1281;
	static const unsigned long FALCON_512_PUB_LENGTH = 897;
	static const unsigned long FALCON_512_SIGNATURE_LENGTH = 752;
	static const unsigned long FALCON_512_SECURITY_BITS = 128;
	static const unsigned long FALCON_1024_PRIV_LENGTH = 2305;
	static const unsigned long FALCON_1024_PUB_LENGTH = 1793;
	static const unsigned long FALCON_1024_SIGNATURE_LENGTH = 1462;
	static const unsigned long FALCON_1024_SECURITY_BITS = 256;

private:
	unsigned long parameterSet;
};

#endif // !_SOFTHSM_V2_FALCONPARAMETERS_H
