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
 BotanCryptoFactory.cpp

 This is a Botan based cryptographic algorithm factory
 *****************************************************************************/

#include "config.h"
#include "BotanCryptoFactory.h"
#include "BotanAES.h"
#include "BotanDES.h"
#include "BotanDSA.h"
#include "BotanMD5.h"
#include "BotanRNG.h"
#include "BotanRSA.h"
#include "BotanSHA1.h"
#include "BotanSHA256.h"
#include "BotanSHA512.h"

#include <botan/init.h>

// Initialise the one-and-only instance
std::auto_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(NULL);

// Constructor
BotanCryptoFactory::BotanCryptoFactory()
{
	// Init the Botan crypto library
	Botan::LibraryInitializer::initialize("thread_safe=true");

	// Initialise the one-and-only RNG
	rng = new BotanRNG();
}

// Destructor
BotanCryptoFactory::~BotanCryptoFactory()
{
	// Destroy the one-and-only RNG
	delete rng;

	// Deinitialize the Botan crypto lib
	Botan::LibraryInitializer::deinitialize();
}

// Return the one-and-only instance
BotanCryptoFactory* BotanCryptoFactory::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<BotanCryptoFactory>(new BotanCryptoFactory());
	}

	return instance.get();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* BotanCryptoFactory::getSymmetricAlgorithm(std::string algorithm)
{
        std::string lcAlgo;
        lcAlgo.resize(algorithm.size());
        std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

        if (!lcAlgo.compare("aes"))
        {
                return new BotanAES();
        }
        else if (!lcAlgo.compare("des") || !lcAlgo.compare("3des"))
        {
                return new BotanDES();
        }
        else
        {
                // No algorithm implementation is available
                ERROR_MSG("Unknown algorithm '%s'", lcAlgo.c_str());

                return NULL;
        }

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* BotanCryptoFactory::getAsymmetricAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("rsa"))
	{
		return new BotanRSA();
	}
	else if (!lcAlgo.compare("dsa"))
	{
		return new BotanDSA();
	}
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* BotanCryptoFactory::getHashAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("md5"))
	{
		return new BotanMD5();
	}
	else if (!lcAlgo.compare("sha1"))
	{
		return new BotanSHA1();
	}
	else if (!lcAlgo.compare("sha256"))
	{
		return new BotanSHA256();
	}
	else if (!lcAlgo.compare("sha512"))
	{
		return new BotanSHA512();
	}
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of an RNG
RNG* BotanCryptoFactory::getRNG(std::string name /* = "default" */)
{
	std::string lcAlgo;
	lcAlgo.resize(name.size());
	std::transform(name.begin(), name.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("default"))
	{
		return rng;
	}
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", name.c_str());

		return NULL;
	}
}

void BotanCryptoFactory::recycleRNG(RNG* toRecycle)
{
	// Do nothing; we keep the one-and-only instance
}
