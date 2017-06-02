/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 BotanECDH.cpp

 Botan ECDH asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "BotanECDH.h"
#include "BotanRNG.h"
#include "CryptoFactory.h"
#include "BotanCryptoFactory.h"
#include "ECParameters.h"
#include "BotanECDHKeyPair.h"
#include "BotanUtil.h"
#include <algorithm>
#include <botan/dl_group.h>
#include <botan/ecdh.h>
#include <botan/pubkey.h>
#include <botan/version.h>

// Signing functions
bool BotanECDH::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

bool BotanECDH::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

bool BotanECDH::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

// Verification functions
bool BotanECDH::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

bool BotanECDH::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

bool BotanECDH::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

// Encryption functions
bool BotanECDH::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDH does not support encryption");

	return false;
}

// Decryption functions
bool BotanECDH::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDH does not support decryption");

	return false;
}

// Key factory
bool BotanECDH::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
	Botan::ECDH_PrivateKey* eckp = NULL;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		eckp = new Botan::ECDH_PrivateKey(*rng->getRNG(), BotanUtil::byteString2ECGroup(params->getEC()));
	}
	catch (...)
	{
		ERROR_MSG("ECDH key generation failed");

		return false;
	}

	// Create an asymmetric key-pair object to return
	BotanECDHKeyPair* kp = new BotanECDHKeyPair();

	((BotanECDHPublicKey*) kp->getPublicKey())->setFromBotan(eckp);
	((BotanECDHPrivateKey*) kp->getPrivateKey())->setFromBotan(eckp);

	*ppKeyPair = kp;

	// Release the key
	delete eckp;

	return true;
}

bool BotanECDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get keys
	Botan::ECDH_PublicKey* pub = ((BotanECDHPublicKey*) publicKey)->getBotanKey();
	Botan::ECDH_PrivateKey* priv = ((BotanECDHPrivateKey*) privateKey)->getBotanKey();
	if (pub == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get Botan ECDH keys");

		return false;
	}

	// Derive the secret
	Botan::SymmetricKey sk;
	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,33)
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		Botan::PK_Key_Agreement ka(*priv, *rng->getRNG(), "Raw");
#else
		Botan::PK_Key_Agreement ka(*priv, "Raw");
#endif
		sk = ka.derive_key(0, pub->public_value());
	}
	catch (...)
	{
		ERROR_MSG("Botan ECDH key agreement failed");

		return false;
	}

	ByteString secret;

	// We compensate that Botan removes leading zeros
	int size = ((BotanECDHPublicKey *)publicKey)->getOrderLength();
	int keySize = sk.length();
	secret.wipe(size);
	memcpy(&secret[0] + size - keySize, sk.begin(), keySize);

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
	{
		ERROR_MSG("Can't create ECDH secret");

		return false;
	}
	if (!(*ppSymmetricKey)->setKeyBits(secret))
	{
		delete *ppSymmetricKey;
		*ppSymmetricKey = NULL;
		return false;
	}

	return true;
}

unsigned long BotanECDH::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long BotanECDH::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool BotanECDH::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	BotanECDHKeyPair* kp = new BotanECDHKeyPair();

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

bool BotanECDH::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanECDHPublicKey* pub = new BotanECDHPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool BotanECDH::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanECDHPrivateKey* priv = new BotanECDHPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* BotanECDH::newPublicKey()
{
	return (PublicKey*) new BotanECDHPublicKey();
}

PrivateKey* BotanECDH::newPrivateKey()
{
	return (PrivateKey*) new BotanECDHPrivateKey();
}

AsymmetricParameters* BotanECDH::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool BotanECDH::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
