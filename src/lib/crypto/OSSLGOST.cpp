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
 OSSLGOST.cpp

 OpenSSL GOST R 34.10-2001 asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "OSSLGOST.h"
#include "OSSLCryptoFactory.h"
#include "ECParameters.h"
#include "OSSLGOSTKeyPair.h"
#include "OSSLGOSTPrivateKey.h"
#include "OSSLGOSTPublicKey.h"
#include "OSSLComp.h"
#include <algorithm>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

// Destructor
OSSLGOST::~OSSLGOST()
{
	EVP_MD_CTX_free(curCTX);
}

// Signing functions
bool OSSLGOST::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		    ByteString& signature, const AsymMech::Type mechanism,
		    const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::GOST)
	{
		// Separate implementation for GOST signing without hash computation

		// Check if the private key is the right type
		if (!privateKey->isOfType(OSSLGOSTPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// In case of raw GOST, the length of the input data must be 32 bytes
		if (dataToSign.size() != 32)
		{
			ERROR_MSG("Size of data to sign is not 32 bytes");

			return false;
		}

		// Perform the signature operation
		OSSLGOSTPrivateKey* osslKey = (OSSLGOSTPrivateKey*) privateKey;
		EVP_PKEY* pkey = osslKey->getOSSLKey();
		size_t outLen;

		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL private key");

			return false;
		}

		signature.resize(EVP_PKEY_size(pkey));
		outLen = signature.size();

		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey,NULL);
		if (ctx == NULL)
		{
			ERROR_MSG("EVP_PKEY_CTX_new failed");
			return false;
		}

		if (EVP_PKEY_sign_init(ctx) <= 0)
		{
			ERROR_MSG("EVP_PKEY_sign_init failed");
			EVP_PKEY_CTX_free(ctx);
			return false;
		}

		if (EVP_PKEY_sign(ctx, &signature[0], &outLen, dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("An error occurred while performing a signature");
			EVP_PKEY_CTX_free(ctx);
			return false;
		}

		signature.resize(outLen);
		EVP_PKEY_CTX_free(ctx);

		return true;
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
	}
}

bool OSSLGOST::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLGOSTPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if (mechanism != AsymMech::GOST_GOST)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	curCTX = EVP_MD_CTX_new();
	if (curCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_MD_CTX");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	const EVP_MD* md = OSSLCryptoFactory::i()->EVP_GOST_34_11;
	if (!EVP_DigestInit_ex(curCTX, md, NULL))
	{
		ERROR_MSG("EVP_DigestInit_ex failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLGOST::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!EVP_DigestUpdate(curCTX, dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("EVP_DigestUpdate failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLGOST::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	OSSLGOSTPrivateKey* pk = (OSSLGOSTPrivateKey*) currentPrivateKey;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	// Perform the signature operation
	EVP_PKEY* pkey = pk->getOSSLKey();
	unsigned int outLen;

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	signature.resize(EVP_PKEY_size(pkey));
	outLen = signature.size();
	if (!EVP_SignFinal(curCTX, &signature[0], &outLen, pkey))
	{
		ERROR_MSG("EVP_SignFinal failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	signature.resize(outLen);

	EVP_MD_CTX_free(curCTX);
	curCTX = NULL;

	return true;
}

// Verification functions
bool OSSLGOST::verify(PublicKey* publicKey, const ByteString& originalData,
		      const ByteString& signature, const AsymMech::Type mechanism,
		      const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::GOST)
	{
		// Separate implementation for GOST verification without hash computation

		// Check if the private key is the right type
		if (!publicKey->isOfType(OSSLGOSTPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the verification operation
		OSSLGOSTPublicKey* osslKey = (OSSLGOSTPublicKey*) publicKey;
		EVP_PKEY* pkey = osslKey->getOSSLKey();

		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL public key");

			return false;
		}

		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey,NULL);
		if (ctx == NULL)
		{
			ERROR_MSG("EVP_PKEY_CTX_new failed");
			return false;
		}

		if (EVP_PKEY_verify_init(ctx) <= 0)
		{
			ERROR_MSG("EVP_PKEY_verify_init failed");
			EVP_PKEY_CTX_free(ctx);
			return false;
		}

		int ret = EVP_PKEY_verify(ctx, signature.const_byte_str(), signature.size(), originalData.const_byte_str(), originalData.size());
		EVP_PKEY_CTX_free(ctx);
		if (ret != 1)
		{
			if (ret < 0)
				ERROR_MSG("GOST verify failed (0x%08X)", ERR_get_error());

			return false;
		}
		return true;
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
	}
}

bool OSSLGOST::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			  const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLGOSTPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if (mechanism != AsymMech::GOST_GOST)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	curCTX = EVP_MD_CTX_new();
	if (curCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_MD_CTX");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	const EVP_MD* md = OSSLCryptoFactory::i()->EVP_GOST_34_11;
	if (!EVP_DigestInit_ex(curCTX, md, NULL))
	{
		ERROR_MSG("EVP_DigestInit_ex failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLGOST::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!EVP_DigestUpdate(curCTX, originalData.const_byte_str(), originalData.size()))
	{
		ERROR_MSG("EVP_DigestUpdate failed");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLGOST::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	OSSLGOSTPublicKey* pk = (OSSLGOSTPublicKey*) currentPublicKey;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	// Perform the verify operation
	EVP_PKEY *pkey = pk->getOSSLKey();
	int ret;

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	ret = EVP_VerifyFinal(curCTX, signature.const_byte_str(), signature.size(), pkey);
	EVP_MD_CTX_free(curCTX);
	curCTX = NULL;
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("GOST verify failed (0x%08X)", ERR_get_error());

		return false;
	}
	return true;
}

// Encryption functions
bool OSSLGOST::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		       ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("GOST does not support encryption");

	return false;
}

// Decryption functions
bool OSSLGOST::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		       ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("GOST does not support decryption");

	return false;
}

// Key factory
bool OSSLGOST::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for GOST key generation");

		return false;
	}

	ECParameters* params = (ECParameters*) parameters;
	ByteString paramA = "06072a850302022301";
	if (params->getEC() != paramA)
	{
		ERROR_MSG("unsupported parameters");

		return false;
	}

	// Generate the key-pair
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;
	OSSLGOSTKeyPair* kp;

	ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2001, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_PKEY_CTX_new_id failed");

		goto err;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0)
	{
		ERROR_MSG("EVP_PKEY_keygen_init failed");

		goto err;
	}
	if (EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "A") <= 0)
	{
		ERROR_MSG("EVP_PKEY_CTX_ctrl_str failed");

		goto err;
	}
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		ERROR_MSG("EVP_PKEY_keygen failed");

		goto err;
	}
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	// Create an asymmetric key-pair object to return
	kp = new OSSLGOSTKeyPair();

	((OSSLGOSTPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLGOSTPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;

err:
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return false;
}

unsigned long OSSLGOST::getMinKeySize()
{
	return 0;
}

unsigned long OSSLGOST::getMaxKeySize()
{
	return 0;
}

bool OSSLGOST::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLGOSTKeyPair* kp = new OSSLGOSTKeyPair();

	bool rv = true;

	if (!((OSSLGOSTPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((OSSLGOSTPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLGOST::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLGOSTPublicKey* pub = new OSSLGOSTPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLGOST::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLGOSTPrivateKey* priv = new OSSLGOSTPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLGOST::newPublicKey()
{
	return (PublicKey*) new OSSLGOSTPublicKey();
}

PrivateKey* OSSLGOST::newPrivateKey()
{
	return (PrivateKey*) new OSSLGOSTPrivateKey();
}

AsymmetricParameters* OSSLGOST::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLGOST::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
