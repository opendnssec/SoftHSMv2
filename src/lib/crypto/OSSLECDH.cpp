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
 OSSLECDH.cpp

 OpenSSL Diffie-Hellman asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECDH.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLECKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif

// Signing functions
bool OSSLECDH::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

bool OSSLECDH::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

bool OSSLECDH::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

// Verification functions
bool OSSLECDH::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			  const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

bool OSSLECDH::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

bool OSSLECDH::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

// Encryption functions
bool OSSLECDH::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		       ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDH does not support encryption");

	return false;
}

// Decryption functions
bool OSSLECDH::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		       ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDH does not support decryption");

	return false;
}

// Key factory
bool OSSLECDH::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDH key generation");

		return false;
	}

	ECParameters* params = (ECParameters*) parameters;

	// Generate the key-pair
	EC_KEY* eckey = EC_KEY_new();

	if (eckey == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL ECDH object");

		return false;
	}

	EC_GROUP* grp = OSSL::byteString2grp(params->getEC());
	EC_KEY_set_group(eckey, grp);
	EC_GROUP_free(grp);

	if (!EC_KEY_generate_key(eckey))
	{
		ERROR_MSG("ECDH key generation failed (0x%08X)", ERR_get_error());

		EC_KEY_free(eckey);

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLECKeyPair* kp = new OSSLECKeyPair();

	((OSSLECPublicKey*) kp->getPublicKey())->setFromOSSL(eckey);
	((OSSLECPrivateKey*) kp->getPrivateKey())->setFromOSSL(eckey);

	*ppKeyPair = kp;

	// Release the key
	EC_KEY_free(eckey);

	return true;
}

bool OSSLECDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get keys
	EC_KEY *pub = ((OSSLECPublicKey *)publicKey)->getOSSLKey();
	EC_KEY *priv = ((OSSLECPrivateKey *)privateKey)->getOSSLKey();
	if (pub == NULL || EC_KEY_get0_public_key(pub) == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL ECDH keys");

		return false;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
	{
		ECDH_set_method(pub, FIPS_ecdh_openssl());
		ECDH_set_method(priv, FIPS_ecdh_openssl());
	}
	else
	{
		ECDH_set_method(pub, ECDH_OpenSSL());
		ECDH_set_method(priv, ECDH_OpenSSL());
	}
#else
	ECDH_set_method(pub, ECDH_OpenSSL());
	ECDH_set_method(priv, ECDH_OpenSSL());
#endif

#else
	EC_KEY_set_method(pub, EC_KEY_OpenSSL());
	EC_KEY_set_method(priv, EC_KEY_OpenSSL());
#endif

	// Derive the secret
	ByteString secret, derivedSecret;
	int size = ((OSSLECPublicKey *)publicKey)->getOrderLength();
	secret.wipe(size);
	derivedSecret.wipe(size);
	int keySize = ECDH_compute_key(&derivedSecret[0], derivedSecret.size(), EC_KEY_get0_public_key(pub), priv, NULL);

	if (keySize <= 0)
	{
		ERROR_MSG("ECDH key derivation failed (0x%08X)", ERR_get_error());

		return false;
	}

	// We compensate that OpenSSL removes leading zeros
	memcpy(&secret[0] + size - keySize, &derivedSecret[0], keySize);

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
		return false;
	if (!(*ppSymmetricKey)->setKeyBits(secret))
	{
		delete *ppSymmetricKey;
		*ppSymmetricKey = NULL;
		return false;
	}

	return true;
}

unsigned long OSSLECDH::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long OSSLECDH::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool OSSLECDH::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLECKeyPair* kp = new OSSLECKeyPair();

	bool rv = true;

	if (!((ECPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((ECPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;

		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLECDH::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLECPublicKey* pub = new OSSLECPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLECDH::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLECPrivateKey* priv = new OSSLECPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLECDH::newPublicKey()
{
	return (PublicKey*) new OSSLECPublicKey();
}

PrivateKey* OSSLECDH::newPrivateKey()
{
	return (PrivateKey*) new OSSLECPrivateKey();
}

AsymmetricParameters* OSSLECDH::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLECDH::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ECParameters* params = new ECParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
