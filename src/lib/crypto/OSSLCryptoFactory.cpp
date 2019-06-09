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
#include "MutexFactory.h"
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
#include "OSSLCMAC.h"
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
#ifdef WITH_EDDSA
#include "OSSLEDDSA.h"
#endif

#include <algorithm>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifdef WITH_GOST
#include <openssl/objects.h>
#endif

#ifdef WITH_FIPS
// Initialise the FIPS 140-2 selftest status
bool OSSLCryptoFactory::FipsSelfTestStatus = false;
#endif

static unsigned nlocks;
static Mutex** locks;

// Mutex callback
void lock_callback(int mode, int n, const char* file, int line)
{
	if ((unsigned) n >= nlocks)
	{
		ERROR_MSG("out of range [0..%u[ lock %d at %s:%d",
			  nlocks, n, file, line);

		return;
	}

	Mutex* mtx = locks[(unsigned) n];

	if (mode & CRYPTO_LOCK)
	{
		mtx->lock();
	}
	else
	{
		mtx->unlock();
	}
}

// Constructor
OSSLCryptoFactory::OSSLCryptoFactory()
{
	// Multi-thread support
	nlocks = CRYPTO_num_locks();
	locks = new Mutex*[nlocks];
	for (unsigned i = 0; i < nlocks; i++)
	{
		locks[i] = MutexFactory::i()->getMutex();
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	setLockingCallback = false;
	if (CRYPTO_get_locking_callback() == NULL)
	{
		CRYPTO_set_locking_callback(lock_callback);
		setLockingCallback = true;
	}
#endif

#ifdef WITH_FIPS
	// Already in FIPS mode on reenter (avoiding selftests)
	if (!FIPS_mode())
	{
		FipsSelfTestStatus = false;
		if (!FIPS_mode_set(1))
		{
			ERROR_MSG("can't enter into FIPS mode");
			return;
		}
	} else {
		// Undo RAND_cleanup()
		RAND_init_fips();
	}
	FipsSelfTestStatus = true;
#endif

	// Initialise OpenSSL
	OpenSSL_add_all_algorithms();

	// Make sure RDRAND is loaded first
	ENGINE_load_rdrand();
	// Locate the engine
	rdrand_engine = ENGINE_by_id("rdrand");
	// Use RDRAND if available
	if (rdrand_engine != NULL)
	{
		// Initialize RDRAND engine
		if (!ENGINE_init(rdrand_engine))
		{
			WARNING_MSG("ENGINE_init returned %lu\n", ERR_get_error());
		}
		// Set RDRAND engine as the default for RAND_ methods
		else if (!ENGINE_set_default(rdrand_engine, ENGINE_METHOD_RAND))
		{
			WARNING_MSG("ENGINE_set_default returned %lu\n", ERR_get_error());
		}
	}

	// Initialise the one-and-only RNG
	rng = new OSSLRNG();

#ifdef WITH_GOST
	// Load engines
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	ENGINE_load_builtin_engines();
#else
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN |
			    OPENSSL_INIT_ENGINE_RDRAND |
			    OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
			    OPENSSL_INIT_ADD_ALL_CIPHERS |
			    OPENSSL_INIT_ADD_ALL_DIGESTS |
			    OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif

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

	// free RDRAND engine
	if (rdrand_engine != NULL)
	{
		ENGINE_finish(rdrand_engine);
		ENGINE_free(rdrand_engine);
	}

	ENGINE_cleanup();

	// Destroy the one-and-only RNG
	delete rng;

	// Recycle locks
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	if (setLockingCallback)
	{
		CRYPTO_set_locking_callback(NULL);
	}
#endif
	for (unsigned i = 0; i < nlocks; i++)
	{
		MutexFactory::i()->recycleMutex(locks[i]);
	}
	delete[] locks;
}

// Return the one-and-only instance
OSSLCryptoFactory* OSSLCryptoFactory::i()
{
	if (!instance.get())
	{
		instance.reset(new OSSLCryptoFactory());
	}

	return instance.get();
}

// This will destroy the one-and-only instance.
void OSSLCryptoFactory::reset()
{
	instance.reset();
}

#ifdef WITH_FIPS
bool OSSLCryptoFactory::getFipsSelfTestStatus() const
{
	return FipsSelfTestStatus;
}
#endif

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* OSSLCryptoFactory::getSymmetricAlgorithm(SymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case SymAlgo::AES:
			return new OSSLAES();
		case SymAlgo::DES:
		case SymAlgo::DES3:
			return new OSSLDES();
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* OSSLCryptoFactory::getAsymmetricAlgorithm(AsymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case AsymAlgo::RSA:
			return new OSSLRSA();
		case AsymAlgo::DSA:
			return new OSSLDSA();
		case AsymAlgo::DH:
			return new OSSLDH();
#ifdef WITH_ECC
		case AsymAlgo::ECDH:
			return new OSSLECDH();
		case AsymAlgo::ECDSA:
			return new OSSLECDSA();
#endif
#ifdef WITH_GOST
		case AsymAlgo::GOST:
			return new OSSLGOST();
#endif
#ifdef WITH_EDDSA
		case AsymAlgo::EDDSA:
			return new OSSLEDDSA();
#endif
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* OSSLCryptoFactory::getHashAlgorithm(HashAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case HashAlgo::MD5:
			return new OSSLMD5();
		case HashAlgo::SHA1:
			return new OSSLSHA1();
		case HashAlgo::SHA224:
			return new OSSLSHA224();
		case HashAlgo::SHA256:
			return new OSSLSHA256();
		case HashAlgo::SHA384:
			return new OSSLSHA384();
		case HashAlgo::SHA512:
			return new OSSLSHA512();
#ifdef WITH_GOST
		case HashAlgo::GOST:
			return new OSSLGOSTR3411();
#endif
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a MAC algorithm
MacAlgorithm* OSSLCryptoFactory::getMacAlgorithm(MacAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case MacAlgo::HMAC_MD5:
			return new OSSLHMACMD5();
		case MacAlgo::HMAC_SHA1:
			return new OSSLHMACSHA1();
		case MacAlgo::HMAC_SHA224:
			return new OSSLHMACSHA224();
		case MacAlgo::HMAC_SHA256:
			return new OSSLHMACSHA256();
		case MacAlgo::HMAC_SHA384:
			return new OSSLHMACSHA384();
		case MacAlgo::HMAC_SHA512:
			return new OSSLHMACSHA512();
#ifdef WITH_GOST
		case MacAlgo::HMAC_GOST:
			return new OSSLHMACGOSTR3411();
#endif
		case MacAlgo::CMAC_DES:
			return new OSSLCMACDES();
		case MacAlgo::CMAC_AES:
			return new OSSLCMACAES();
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Get the global RNG (may be an unique RNG per thread)
RNG* OSSLCryptoFactory::getRNG(RNGImpl::Type name /* = RNGImpl::Default */)
{
	if (name == RNGImpl::Default)
	{
		return rng;
	}
	else
	{
		// No RNG implementation is available
		ERROR_MSG("Unknown RNG '%i'", name);

		return NULL;
	}
}

