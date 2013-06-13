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
#include "OSSLSHA224.h"
#include "OSSLSHA256.h"
#include "OSSLSHA384.h"
#include "OSSLSHA512.h"
#include "OSSLHMAC.h"
#include "OSSLRSA.h"
#include "OSSLDSA.h"
#include "OSSLDH.h"
#ifdef WITH_ECC
#include "OSSLECDH.h"
#include "OSSLECDSA.h"
#endif
#ifdef WITH_GOST
#include "OSSLGOSTR3411.h"
#include "OSSLGOST.h"
#endif

#include <algorithm>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef WITH_GOST
#include <openssl/objects.h>
#endif

// Initialise the one-and-only instance
std::auto_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(NULL); 

// Constructor
OSSLCryptoFactory::OSSLCryptoFactory()
{
	// Initialise OpenSSL
	OpenSSL_add_all_algorithms();

	// Initialise the one-and-only RNG
	rng = new OSSLRNG();

#ifdef WITH_GOST
	// Load engines
	ENGINE_load_builtin_engines();

	// Initialise the GOST engine
	eg = ENGINE_by_id("gost");
	if (eg == NULL)
	{
		ERROR_MSG("can't get the GOST engine");
		return;
	}
	if (ENGINE_init(eg) <= 0)
	{
		ENGINE_free(eg);
		eg = NULL;
		ERROR_MSG("can't initialize the GOST engine");
		return;
	}
	// better than digest_gost
	EVP_GOST_34_11 = ENGINE_get_digest(eg, NID_id_GostR3411_94);
	if (EVP_GOST_34_11 == NULL)
	{
		ERROR_MSG("can't get the GOST digest");
		goto err;
	}
	// from the openssl.cnf
	if (ENGINE_register_pkey_asn1_meths(eg) <= 0)
	{
		ERROR_MSG("can't register ASN.1 for the GOST engine");
		goto err;
	}
	if (ENGINE_ctrl_cmd_string(eg,
				   "CRYPT_PARAMS",
				   "id-Gost28147-89-CryptoPro-A-ParamSet",
				   0) <= 0)
	{
		ERROR_MSG("can't set params of the GOST engine");
		goto err;
	}
	return;

err:
	ENGINE_finish(eg);
	ENGINE_free(eg);
	eg = NULL;
	return;
#endif
}

// Destructor
OSSLCryptoFactory::~OSSLCryptoFactory()
{
#ifdef WITH_GOST
	// Finish the GOST engine
	if (eg != NULL)
	{
		ENGINE_finish(eg);
		ENGINE_free(eg);
		eg = NULL;
	}
#endif

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
	else if (!lcAlgo.compare("dh"))
	{
		return new OSSLDH();
	}
#ifdef WITH_ECC
	else if (!lcAlgo.compare("ecdh"))
	{
		return new OSSLECDH();
	}
	else if (!lcAlgo.compare("ecdsa"))
	{
		return new OSSLECDSA();
	}
#endif
#ifdef WITH_GOST
	else if (!lcAlgo.compare("gost"))
	{
		return new OSSLGOST();
	}
#endif
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
	else if (!lcAlgo.compare("sha224"))
	{
		return new OSSLSHA224();
	}
	else if (!lcAlgo.compare("sha256"))
	{
		return new OSSLSHA256();
	}
	else if (!lcAlgo.compare("sha384"))
	{
		return new OSSLSHA384();
	}
	else if (!lcAlgo.compare("sha512"))
	{
		return new OSSLSHA512();
	}
#ifdef WITH_GOST
	else if (!lcAlgo.compare("gost"))
	{
		return new OSSLGOSTR3411();
	}
#endif
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a MAC algorithm
MacAlgorithm* OSSLCryptoFactory::getMacAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("hmac-md5"))
	{
		return new OSSLHMACMD5();
	}
	else if (!lcAlgo.compare("hmac-sha1"))
	{
		return new OSSLHMACSHA1();
	}
	else if (!lcAlgo.compare("hmac-sha224"))
	{
		return new OSSLHMACSHA224();
	}
	else if (!lcAlgo.compare("hmac-sha256"))
	{
		return new OSSLHMACSHA256();
	}
	else if (!lcAlgo.compare("hmac-sha384"))
	{
		return new OSSLHMACSHA384();
	}
	else if (!lcAlgo.compare("hmac-sha512"))
	{
		return new OSSLHMACSHA512();
	}
#ifdef WITH_GOST
	else if (!lcAlgo.compare("hmac-gost"))
	{
		return new OSSLHMACGOSTR3411();
	}
#endif
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

