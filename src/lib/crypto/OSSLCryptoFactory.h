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
 OSSLCryptoFactory.h

 This is an OpenSSL based cryptographic algorithm factory
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLCRYPTOFACTORY_H
#define _SOFTHSM_V2_OSSLCRYPTOFACTORY_H

#include "config.h"
#include "CryptoFactory.h"
#include "SymmetricAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "RNG.h"
#include <memory>
#include <openssl/conf.h>
#include <openssl/engine.h>

class OSSLCryptoFactory : public CryptoFactory
{
public:
	// Return the one-and-only instance
	static OSSLCryptoFactory* i();

	// This will destroy the one-and-only instance.
	static void reset();

#ifdef WITH_FIPS
	// Return the FIPS 140-2 selftest status
	virtual bool getFipsSelfTestStatus() const;
#endif

	// Create a concrete instance of a symmetric algorithm
	virtual SymmetricAlgorithm* getSymmetricAlgorithm(SymAlgo::Type algorithm);

	// Create a concrete instance of an asymmetric algorithm
	virtual AsymmetricAlgorithm* getAsymmetricAlgorithm(AsymAlgo::Type algorithm);

	// Create a concrete instance of a hash algorithm
	virtual HashAlgorithm* getHashAlgorithm(HashAlgo::Type algorithm);

	// Create a concrete instance of a MAC algorithm
	virtual MacAlgorithm* getMacAlgorithm(MacAlgo::Type algorithm);

	// Get the global RNG (may be an unique RNG per thread)
	virtual RNG* getRNG(RNGImpl::Type name = RNGImpl::Default);

	// Destructor
	virtual ~OSSLCryptoFactory();

#ifdef WITH_GOST
	// The EVP_MD for GOST R 34.11-94
	const EVP_MD *EVP_GOST_34_11;
#endif

private:
	// Constructor
	OSSLCryptoFactory();

	// The one-and-only instance
#ifdef HAVE_CXX11
	static std::unique_ptr<OSSLCryptoFactory> instance;
#else
	static std::auto_ptr<OSSLCryptoFactory> instance;
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	bool setLockingCallback;
#endif

#ifdef WITH_FIPS
	// The FIPS 140-2 selftest status
	static bool FipsSelfTestStatus;
#endif

	// The one-and-only RNG instance
	RNG* rng;
	// And RDRAND engine to use with it
	ENGINE *rdrand_engine;

#ifdef WITH_GOST
	// The GOST engine
	ENGINE *eg;
#endif
};

#endif // !_SOFTHSM_V2_OSSLCRYPTOFACTORY_H

