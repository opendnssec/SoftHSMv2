/* $Id$ */

/*
 * Copyright (c) 2010 SURFnet bv
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 BotanCryptoFactory.h

 This is a Botan based cryptographic algorithm factory
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANCRYPTOFACTORY_H
#define _SOFTHSM_V2_BOTANCRYPTOFACTORY_H

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "config.h"
#include "CryptoFactory.h"
#include "SymmetricAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "HashAlgorithm.h"
#include "RNG.h"
#include "MutexFactory.h"
#include <memory>
#include <map>

class BotanCryptoFactory : public CryptoFactory
{
public:
	// Return the one-and-only instance
	static BotanCryptoFactory* i();

	// Create a concrete instance of a symmetric algorithm
	SymmetricAlgorithm* getSymmetricAlgorithm(std::string algorithm);

	// Create a concrete instance of an asymmetric algorithm
	AsymmetricAlgorithm* getAsymmetricAlgorithm(std::string algorithm);

	// Create a concrete instance of a hash algorithm
	HashAlgorithm* getHashAlgorithm(std::string algorithm);

	// Create a concrete instance of an RNG
	RNG* getRNG(std::string name = "default");

	// Destructor
	~BotanCryptoFactory();

	void recycleRNG(RNG* toRecycle);

private:
	// Constructor
	BotanCryptoFactory();

	// The one-and-only instance
	static std::auto_ptr<BotanCryptoFactory> instance;

	// Thread specific RNG
#ifdef HAVE_PTHREAD_H
	std::map<pthread_t, RNG*> rngs;
#endif
        Mutex* rngsMutex;
};

#endif // !_SOFTHSM_V2_BOTANCRYPTOFACTORY_H

