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
 OSSLDH.cpp

 OpenSSL Diffie-Hellman asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDH.h"
#include "CryptoFactory.h"
#include "DHParameters.h"
#include "OSSLComp.h"
#include "OSSLDHKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Signing functions
bool OSSLDH::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
		      const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

bool OSSLDH::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

bool OSSLDH::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

// Verification functions
bool OSSLDH::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

bool OSSLDH::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

bool OSSLDH::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

// Encryption functions
bool OSSLDH::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		     ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DH does not support encryption");

	return false;
}

// Decryption functions
bool OSSLDH::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		     ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DH does not support decryption");

	return false;
}

// Key factory
bool OSSLDH::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(DHParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for DH key generation");

		return false;
	}

	DHParameters* params = (DHParameters*) parameters;

	// Generate the key-pair
	DH* dh = DH_new();
	if (dh == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL DH object");

		return false;
	}

	BIGNUM* bn_p = OSSL::byteString2bn(params->getP());
	BIGNUM* bn_g = OSSL::byteString2bn(params->getG());

	if (!DH_set0_pqg(dh, bn_p, NULL, bn_g))
	{
		ERROR_MSG("DH set pqg failed (0x%08X)", ERR_get_error());

		BN_free(bn_p);
		BN_free(bn_g);
		DH_free(dh);

		return false;
	}

	if (params->getXBitLength() > 0)
	{
		if (!DH_set_length(dh, params->getXBitLength()))
		{
			ERROR_MSG("DH set length failed (0x%08X)", ERR_get_error());

			DH_free(dh);

			return false;
		}
	}

	if (DH_generate_key(dh) != 1)
	{
		ERROR_MSG("DH key generation failed (0x%08X)", ERR_get_error());

		DH_free(dh);

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLDHKeyPair* kp = new OSSLDHKeyPair();

	((OSSLDHPublicKey*) kp->getPublicKey())->setFromOSSL(dh);
	((OSSLDHPrivateKey*) kp->getPrivateKey())->setFromOSSL(dh);

	*ppKeyPair = kp;

	// Release the key
	DH_free(dh);

	return true;
}

bool OSSLDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get keys
	DH *pub = ((OSSLDHPublicKey *)publicKey)->getOSSLKey();
	DH *priv = ((OSSLDHPrivateKey *)privateKey)->getOSSLKey();
	if (pub == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL DH keys");

		return false;
	}
	const BIGNUM* bn_pub_key = NULL;
	DH_get0_key(pub, &bn_pub_key, NULL);
	if (bn_pub_key == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL DH keys");

		return false;
	}

	// Derive the secret
	ByteString secret, derivedSecret;
	int size = DH_size(priv);
	secret.wipe(size);
	derivedSecret.wipe(size);
	int keySize = DH_compute_key(&derivedSecret[0], bn_pub_key, priv);

	if (keySize <= 0)
	{
		ERROR_MSG("DH key derivation failed (0x%08X)", ERR_get_error());

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

unsigned long OSSLDH::getMinKeySize()
{
#ifdef WITH_FIPS
	// OPENSSL_DH_FIPS_MIN_MODULUS_BITS is 1024
	return 1024;
#else
	return 512;
#endif
}

unsigned long OSSLDH::getMaxKeySize()
{
	return OPENSSL_DH_MAX_MODULUS_BITS;
}

bool OSSLDH::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
{
	if ((ppParams == NULL) || (parameters == NULL))
	{
		return false;
	}

	size_t bitLen = (size_t) parameters;

	if (bitLen < getMinKeySize() || bitLen > getMaxKeySize())
	{
		ERROR_MSG("This DH key size is not supported");

		return false;
	}

	DH* dh = DH_new();
	if (dh == NULL)
	{
		ERROR_MSG("Failed to create DH object");

		return false;
	}

	if (!DH_generate_parameters_ex(dh, bitLen, 2, NULL))
	{
		ERROR_MSG("Failed to generate %d bit DH parameters", bitLen);

		DH_free(dh);

		return false;
	}

	// Store the DH parameters
	DHParameters* params = new DHParameters();

	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_g = NULL;

	DH_get0_pqg(dh, &bn_p, NULL, &bn_g);
	ByteString p = OSSL::bn2ByteString(bn_p); params->setP(p);
	ByteString g = OSSL::bn2ByteString(bn_g); params->setG(g);

	*ppParams = params;

	DH_free(dh);

	return true;
}

bool OSSLDH::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLDHKeyPair* kp = new OSSLDHKeyPair();

	bool rv = true;

	if (!((DHPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((DHPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLDH::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDHPublicKey* pub = new OSSLDHPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLDH::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDHPrivateKey* priv = new OSSLDHPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLDH::newPublicKey()
{
	return (PublicKey*) new OSSLDHPublicKey();
}

PrivateKey* OSSLDH::newPrivateKey()
{
	return (PrivateKey*) new OSSLDHPrivateKey();
}

AsymmetricParameters* OSSLDH::newParameters()
{
	return (AsymmetricParameters*) new DHParameters();
}

bool OSSLDH::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	DHParameters* params = new DHParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}

