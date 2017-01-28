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
 OSSLECDSA.cpp

 OpenSSL ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLECKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

// Signing functions
bool OSSLECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::ECDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLECPrivateKey* pk = (OSSLECPrivateKey*) privateKey;
	EC_KEY* eckey = pk->getOSSLKey();

	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		ECDSA_set_method(eckey, FIPS_ecdsa_openssl());
	else
		ECDSA_set_method(eckey, ECDSA_OpenSSL());
#else
	ECDSA_set_method(eckey, ECDSA_OpenSSL());
#endif

#else
	EC_KEY_set_method(eckey, EC_KEY_OpenSSL());
#endif

	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	signature.resize(2 * len);
	memset(&signature[0], 0, 2 * len);
	ECDSA_SIG *sig = ECDSA_do_sign(dataToSign.const_byte_str(), dataToSign.size(), eckey);
	if (sig == NULL)
	{
		ERROR_MSG("ECDSA sign failed (0x%08X)", ERR_get_error());
		return false;
	}
	// Store the 2 values with padding
	const BIGNUM* bn_r = NULL;
	const BIGNUM* bn_s = NULL;
	ECDSA_SIG_get0(sig, &bn_r, &bn_s);
	BN_bn2bin(bn_r, &signature[len - BN_num_bytes(bn_r)]);
	BN_bn2bin(bn_s, &signature[2 * len - BN_num_bytes(bn_s)]);
	ECDSA_SIG_free(sig);
	return true;
}

bool OSSLECDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool OSSLECDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool OSSLECDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::ECDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLECPublicKey* pk = (OSSLECPublicKey*) publicKey;
	EC_KEY* eckey = pk->getOSSLKey();

	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		ECDSA_set_method(eckey, FIPS_ecdsa_openssl());
	else
		ECDSA_set_method(eckey, ECDSA_OpenSSL());
#else
	ECDSA_set_method(eckey, ECDSA_OpenSSL());
#endif

#else
	EC_KEY_set_method(eckey, EC_KEY_OpenSSL());
#endif

	// Perform the verify operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (sig == NULL)
	{
		ERROR_MSG("Could not create an ECDSA_SIG object");
		return false;
	}
	const unsigned char *s = signature.const_byte_str();
	BIGNUM* bn_r = BN_bin2bn(s, len, NULL);
	BIGNUM* bn_s = BN_bin2bn(s + len, len, NULL);
	if (bn_r == NULL || bn_s == NULL ||
	    !ECDSA_SIG_set0(sig, bn_r, bn_s))
	{
		ERROR_MSG("Could not add data to the ECDSA_SIG object");
		ECDSA_SIG_free(sig);
		return false;
	}
	int ret = ECDSA_do_verify(originalData.const_byte_str(), originalData.size(), sig, eckey);
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("ECDSA verify failed (0x%08X)", ERR_get_error());

		ECDSA_SIG_free(sig);
		return false;
	}

	ECDSA_SIG_free(sig);
	return true;
}

bool OSSLECDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool OSSLECDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool OSSLECDSA::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool OSSLECDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLECDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support decryption");

	return false;
}

// Key factory
bool OSSLECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDSA key generation");

		return false;
	}

	ECParameters* params = (ECParameters*) parameters;

	// Generate the key-pair
	EC_KEY* eckey = EC_KEY_new();
	if (eckey == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL ECDSA object");

		return false;
	}

	EC_GROUP* grp = OSSL::byteString2grp(params->getEC());
	EC_KEY_set_group(eckey, grp);
	EC_GROUP_free(grp);

	if (!EC_KEY_generate_key(eckey))
	{
		ERROR_MSG("ECDSA key generation failed (0x%08X)", ERR_get_error());

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

unsigned long OSSLECDSA::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long OSSLECDSA::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool OSSLECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
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

bool OSSLECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
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

bool OSSLECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
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

PublicKey* OSSLECDSA::newPublicKey()
{
	return (PublicKey*) new OSSLECPublicKey();
}

PrivateKey* OSSLECDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLECPrivateKey();
}

AsymmetricParameters* OSSLECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
