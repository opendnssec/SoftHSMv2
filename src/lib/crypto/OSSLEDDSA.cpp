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
 OSSLEDDSA.cpp

 OpenSSL EDDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "log.h"
#include "OSSLEDDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLEDKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

// Signing functions
bool OSSLEDDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::EDDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLEDPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLEDPrivateKey* pk = (OSSLEDPrivateKey*) privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	len *= 2;
	signature.resize(len);
	memset(&signature[0], 0, len);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("EDDSA sign init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	if (!EVP_DigestSign(ctx, &signature[0], &len, dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("EDDSA sign failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return true;
}

bool OSSLEDDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("EDDSA does not support multi part signing");

	return false;
}

bool OSSLEDDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("EDDSA does not support multi part signing");

	return false;
}

bool OSSLEDDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("EDDSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLEDDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::EDDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLEDPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLEDPublicKey* pk = (OSSLEDPublicKey*) publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Perform the verify operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	len *= 2;
	if (signature.size() != len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("EDDSA verify init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	int ret = EVP_DigestVerify(ctx, signature.const_byte_str(), len, originalData.const_byte_str(), originalData.size());
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("EDDSA verify failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return true;
}

bool OSSLEDDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("EDDSA does not support multi part verifying");

	return false;
}

bool OSSLEDDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("EDDSA does not support multi part verifying");

	return false;
}

bool OSSLEDDSA::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("EDDSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool OSSLEDDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("EDDSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLEDDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("EDDSA does not support decryption");

	return false;
}

// Key factory
bool OSSLEDDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for EDDSA key generation");

		return false;
	}

	ECParameters* params = (ECParameters*) parameters;
	int nid = OSSL::byteString2oid(params->getEC());

	// Generate the key-pair
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(nid, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL EDDSA context");

		return false;
	}
	int ret = EVP_PKEY_keygen_init(ctx);
	if (ret != 1)
	{
		ERROR_MSG("EDDSA key generation init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	ret = EVP_PKEY_keygen(ctx, &pkey);
	if (ret != 1)
	{
		ERROR_MSG("EDDSA key generation failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// Create an asymmetric key-pair object to return
	OSSLEDKeyPair* kp = new OSSLEDKeyPair();

	((OSSLEDPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLEDPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

bool OSSLEDDSA::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get keys
	EVP_PKEY *pub = ((OSSLEDPublicKey *)publicKey)->getOSSLKey();
	EVP_PKEY *priv = ((OSSLEDPrivateKey *)privateKey)->getOSSLKey();
	if (pub == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL ECDH keys");

		return false;
	}

	// Get and set context
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL ECDH context");

		return false;
	}
	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		ERROR_MSG("Failed to init OpenSSL key derive");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0)
	{
		ERROR_MSG("Failed to set OpenSSL ECDH public key");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Derive the secret
	size_t len;
	if (EVP_PKEY_derive(ctx, NULL, &len) <= 0)
	{
		ERROR_MSG("Failed to get OpenSSL ECDH key length");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	ByteString secret;
	secret.resize(len);
	if (EVP_PKEY_derive(ctx, &secret[0], &len) <= 0)
	{
		ERROR_MSG("Failed to derive OpenSSL ECDH secret");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// Create derived key
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

unsigned long OSSLEDDSA::getMinKeySize()
{
	// Ed25519 is supported
	return 32*8;
}

unsigned long OSSLEDDSA::getMaxKeySize()
{
	// Ed448 will be supported
	return 57*8;
}

bool OSSLEDDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLEDKeyPair* kp = new OSSLEDKeyPair();

	bool rv = true;

	if (!((EDPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((EDPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLEDDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLEDPublicKey* pub = new OSSLEDPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLEDDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLEDPrivateKey* priv = new OSSLEDPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLEDDSA::newPublicKey()
{
	return (PublicKey*) new OSSLEDPublicKey();
}

PrivateKey* OSSLEDDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLEDPrivateKey();
}

AsymmetricParameters* OSSLEDDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLEDDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
