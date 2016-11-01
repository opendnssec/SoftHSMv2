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
 OSSLDSA.cpp

 OpenSSL DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDSA.h"
#include "CryptoFactory.h"
#include "DSAParameters.h"
#include "OSSLDSAKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Constructor
OSSLDSA::OSSLDSA()
{
	pCurrentHash = NULL;
}

// Destructor
OSSLDSA::~OSSLDSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}
}

// Signing functions
bool OSSLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		   ByteString& signature, const AsymMech::Type mechanism,
		   const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::DSA)
	{
		// Separate implementation for DSA signing without hash computation

		// Check if the private key is the right type
		if (!privateKey->isOfType(OSSLDSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		OSSLDSAPrivateKey* pk = (OSSLDSAPrivateKey*) privateKey;
		DSA* dsa = pk->getOSSLKey();

		// Perform the signature operation
		unsigned int sigLen = pk->getOutputLength();
		signature.resize(sigLen);
		memset(&signature[0], 0, sigLen);
		int dLen = dataToSign.size();
		DSA_SIG* sig = DSA_do_sign(dataToSign.const_byte_str(), dLen, dsa);
		if (sig == NULL)
			return false;
		// Store the 2 values with padding
		const BIGNUM* bn_r = NULL;
		const BIGNUM* bn_s = NULL;
		DSA_SIG_get0(sig, &bn_r, &bn_s);
		BN_bn2bin(bn_r, &signature[sigLen / 2 - BN_num_bytes(bn_r)]);
		BN_bn2bin(bn_s, &signature[sigLen - BN_num_bytes(bn_s)]);
		DSA_SIG_free(sig);
		return true;
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
	}
}

bool OSSLDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
		       const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::DSA_SHA1:
			hash = HashAlgo::SHA1;
			break;
		case AsymMech::DSA_SHA224:
			hash = HashAlgo::SHA224;
			break;
		case AsymMech::DSA_SHA256:
			hash = HashAlgo::SHA256;
			break;
		case AsymMech::DSA_SHA384:
			hash = HashAlgo::SHA384;
			break;
		case AsymMech::DSA_SHA512:
			hash = HashAlgo::SHA512;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);

	if (pCurrentHash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if (!pCurrentHash->hashInit())
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	OSSLDSAPrivateKey* pk = (OSSLDSAPrivateKey*) currentPrivateKey;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bFirstResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bFirstResult)
	{
		return false;
	}

	DSA* dsa = pk->getOSSLKey();

	// Perform the signature operation
	unsigned int sigLen = pk->getOutputLength();
	signature.resize(sigLen);
	memset(&signature[0], 0, sigLen);
	DSA_SIG* sig = DSA_do_sign(&hash[0], hash.size(), dsa);
	if (sig == NULL)
		return false;
	// Store the 2 values with padding
	const BIGNUM* bn_r = NULL;
	const BIGNUM* bn_s = NULL;
	DSA_SIG_get0(sig, &bn_r, &bn_s);
	BN_bn2bin(bn_r, &signature[sigLen / 2 - BN_num_bytes(bn_r)]);
	BN_bn2bin(bn_s, &signature[sigLen - BN_num_bytes(bn_s)]);
	DSA_SIG_free(sig);
	return true;
}

// Verification functions
bool OSSLDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		     const ByteString& signature, const AsymMech::Type mechanism,
		     const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::DSA)
	{
		// Separate implementation for DSA verification without hash computation

		// Check if the private key is the right type
		if (!publicKey->isOfType(OSSLDSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the verify operation
		OSSLDSAPublicKey* pk = (OSSLDSAPublicKey*) publicKey;
		unsigned int sigLen = pk->getOutputLength();
		if (signature.size() != sigLen)
			return false;
		DSA_SIG* sig = DSA_SIG_new();
		if (sig == NULL)
			return false;
		const unsigned char *s = signature.const_byte_str();
		BIGNUM* bn_r = BN_bin2bn(s, sigLen / 2, NULL);
		BIGNUM* bn_s = BN_bin2bn(s + sigLen / 2, sigLen / 2, NULL);
		if (bn_r == NULL || bn_s == NULL ||
		    !DSA_SIG_set0(sig, bn_r, bn_s))
		{
			DSA_SIG_free(sig);
			return false;
		}
		int dLen = originalData.size();
		int ret = DSA_do_verify(originalData.const_byte_str(), dLen, sig, pk->getOSSLKey());
		if (ret != 1)
		{
			if (ret < 0)
				ERROR_MSG("DSA verify failed (0x%08X)", ERR_get_error());

			DSA_SIG_free(sig);
			return false;
		}

		DSA_SIG_free(sig);
		return true;
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
	}
}

bool OSSLDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::DSA_SHA1:
			hash = HashAlgo::SHA1;
			break;
		case AsymMech::DSA_SHA224:
			hash = HashAlgo::SHA224;
			break;
		case AsymMech::DSA_SHA256:
			hash = HashAlgo::SHA256;
			break;
		case AsymMech::DSA_SHA384:
			hash = HashAlgo::SHA384;
			break;
		case AsymMech::DSA_SHA512:
			hash = HashAlgo::SHA512;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);


	if (pCurrentHash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if (!pCurrentHash->hashInit())
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	OSSLDSAPublicKey* pk = (OSSLDSAPublicKey*) currentPublicKey;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bFirstResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bFirstResult)
	{
		return false;
	}

	// Perform the verify operation
	unsigned int sigLen = pk->getOutputLength();
	if (signature.size() != sigLen)
		return false;
	DSA_SIG* sig = DSA_SIG_new();
	if (sig == NULL)
		return false;
	const unsigned char *s = signature.const_byte_str();
	BIGNUM* bn_r = BN_bin2bn(s, sigLen / 2, NULL);
	BIGNUM* bn_s = BN_bin2bn(s + sigLen / 2, sigLen / 2, NULL);
	if (bn_r == NULL || bn_s == NULL ||
	    !DSA_SIG_set0(sig, bn_r, bn_s))
	{
		DSA_SIG_free(sig);
		return false;
	}
	int ret = DSA_do_verify(&hash[0], hash.size(), sig, pk->getOSSLKey());
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("DSA verify failed (0x%08X)", ERR_get_error());

		DSA_SIG_free(sig);
		return false;
	}

	DSA_SIG_free(sig);
	return true;
}

// Encryption functions
bool OSSLDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		      ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		      ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DSA does not support decryption");

	return false;
}

// Key factory
bool OSSLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(DSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for DSA key generation");

		return false;
	}

	DSAParameters* params = (DSAParameters*) parameters;

	// Generate the key-pair
	DSA* dsa = DSA_new();
	if (dsa == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL DSA object");

		return false;
	}

	// Use the OpenSSL implementation and not any engine
	DSA_set_method(dsa, DSA_get_default_method());

	BIGNUM* bn_p = OSSL::byteString2bn(params->getP());
	BIGNUM* bn_q = OSSL::byteString2bn(params->getQ());
	BIGNUM* bn_g = OSSL::byteString2bn(params->getG());
	DSA_set0_pqg(dsa, bn_p, bn_q, bn_g);

	if (DSA_generate_key(dsa) != 1)
	{
		ERROR_MSG("DSA key generation failed (0x%08X)", ERR_get_error());

		DSA_free(dsa);

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLDSAKeyPair* kp = new OSSLDSAKeyPair();

	((OSSLDSAPublicKey*) kp->getPublicKey())->setFromOSSL(dsa);
	((OSSLDSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(dsa);

	*ppKeyPair = kp;

	// Release the key
	DSA_free(dsa);

	return true;
}

unsigned long OSSLDSA::getMinKeySize()
{
#ifdef WITH_FIPS
	// OPENSSL_DSA_FIPS_MIN_MODULUS_BITS is 1024
	return 1024;
#else
	return 512;
#endif
}

unsigned long OSSLDSA::getMaxKeySize()
{
	return OPENSSL_DSA_MAX_MODULUS_BITS;
}

bool OSSLDSA::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
{
	if ((ppParams == NULL) || (parameters == NULL))
	{
		return false;
	}

	size_t bitLen = (size_t) parameters;

	if (bitLen < getMinKeySize() || bitLen > getMaxKeySize())
	{
		ERROR_MSG("This DSA key size is not supported");

		return false;
	}

	DSA* dsa = DSA_new();

	if (dsa == NULL ||
	    !DSA_generate_parameters_ex(dsa, bitLen, NULL, 0, NULL, NULL, NULL))
	{
		ERROR_MSG("Failed to generate %d bit DSA parameters", bitLen);

		return false;
	}

	// Store the DSA parameters
	DSAParameters* params = new DSAParameters();

	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_q = NULL;
	const BIGNUM* bn_g = NULL;
	DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);

	ByteString p = OSSL::bn2ByteString(bn_p); params->setP(p);
	ByteString q = OSSL::bn2ByteString(bn_q); params->setQ(q);
	ByteString g = OSSL::bn2ByteString(bn_g); params->setG(g);

	*ppParams = params;

	DSA_free(dsa);

	return true;
}

bool OSSLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLDSAKeyPair* kp = new OSSLDSAKeyPair();

	bool rv = true;

	if (!((DSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((DSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDSAPublicKey* pub = new OSSLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDSAPrivateKey* priv = new OSSLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLDSA::newPublicKey()
{
	return (PublicKey*) new OSSLDSAPublicKey();
}

PrivateKey* OSSLDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLDSAPrivateKey();
}

AsymmetricParameters* OSSLDSA::newParameters()
{
	return (AsymmetricParameters*) new DSAParameters();
}

bool OSSLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	DSAParameters* params = new DSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}

