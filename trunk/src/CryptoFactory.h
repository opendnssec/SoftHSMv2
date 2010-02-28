/* $Id$ */

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
 CryptoFactory.h

 This class is a factory for all cryptographic algorithm implementations. It
 is an abstract base class for a factory that produces cryptographic library
 specific implementations of cryptographic algorithms.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CRYPTOFACTORY_H
#define _SOFTHSM_V2_CRYPTOFACTORY_H

#include "config.h"
#include "SymmetricAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "HashAlgorithm.h"
#include "RNG.h"

class CryptoFactory
{
public:
	// Return the one-and-only instance
	static CryptoFactory* i();

	// Create a concrete instance of a symmetric algorithm
	virtual SymmetricAlgorithm* getSymmetricAlgorithm(std::string algorithm) = 0;

	// Create a concrete instance of an asymmetric algorithm
	virtual AsymmetricAlgorithm* getAsymmetricAlgorithm(std::string algorithm) = 0;

	// Create a concrete instance of a hash algorithm
	virtual HashAlgorithm* getHashAlgorithm(std::string algorithm) = 0;

	// Create a concrete instance of an RNG
	virtual RNG* getRNG(std::string name = "default") = 0;

	// Destructor
	virtual ~CryptoFactory() { }

private:
};

#endif // !_SOFTHSM_V2_CRYPTOFACTORY_H

