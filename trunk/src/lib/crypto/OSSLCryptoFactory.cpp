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
 OSSLCryptoFactory.cpp

 This is an OpenSSL based cryptographic algorithm factory
 *****************************************************************************/

#include "config.h"
#include "OSSLCryptoFactory.h"
#include "OSSLRNG.h"
#include "OSSLAES.h"
#include "OSSLDES.h"
#include "OSSLMD5.h"
#include "OSSLSHA1.h"
#include "OSSLSHA256.h"
#include "OSSLSHA512.h"
#include "OSSLRSA.h"
#include "OSSLDSA.h"

#include <algorithm>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Initialise the one-and-only instance
std::auto_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(NULL); 

// Constructor
OSSLCryptoFactory::OSSLCryptoFactory()
{
	// Initialise OpenSSL
	OpenSSL_add_all_algorithms();

	// Initialise the one-and-only RNG
	rng = new OSSLRNG();
}

// Destructor
OSSLCryptoFactory::~OSSLCryptoFactory()
{
	// Destroy the one-and-only RNG
	delete rng;

	// Clean up OpenSSL
	ERR_remove_state(0);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

// Return the one-and-only instance
OSSLCryptoFactory* OSSLCryptoFactory::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<OSSLCryptoFactory>(new OSSLCryptoFactory());
	}

	return instance.get();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* OSSLCryptoFactory::getSymmetricAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("aes"))
	{
		return new OSSLAES();
	}
	else if (!lcAlgo.compare("des") || !lcAlgo.compare("3des"))
	{
		return new OSSLDES();
	}
	else 
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", lcAlgo.c_str());

		return NULL;
	}
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* OSSLCryptoFactory::getAsymmetricAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("rsa"))
	{
		return new OSSLRSA();
	}
	else if (!lcAlgo.compare("dsa"))
	{
		return new OSSLDSA();
	}
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
	}
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* OSSLCryptoFactory::getHashAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("md5"))
	{
		return new OSSLMD5();
	}
	else if (!lcAlgo.compare("sha1"))
	{
		return new OSSLSHA1();
	}
	else if (!lcAlgo.compare("sha256"))
	{
		return new OSSLSHA256();
	}
	else if (!lcAlgo.compare("sha512"))
	{
		return new OSSLSHA512();
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

// Get the global RNG (may be an unique RNG per thread)
RNG* OSSLCryptoFactory::getRNG(std::string name /* = "default" */)
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

