/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 AsymmetricParameters.h

 Base class for asymmetric parameter classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ASYMMETRICPARAMETERS_H
#define _SOFTHSM_V2_ASYMMETRICPARAMETERS_H

#include "config.h"
#include "ByteString.h"
#include "Serialisable.h"

class AsymmetricParameters : public Serialisable
{
public:
	// Base constructors
	AsymmetricParameters() { }

	AsymmetricParameters(const AsymmetricParameters& /*in*/) { }

	// Destructor
	virtual ~AsymmetricParameters() { }

	// Check if it is of the given type
	virtual bool areOfType(const char* type) = 0;

	// Serialisation
	virtual ByteString serialise() const = 0;
};

#endif // !_SOFTHSM_V2_ASYMMETRICPARAMETERS_H

