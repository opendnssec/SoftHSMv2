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
 BotanDH.cpp

 Botan Diffie-Hellman asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanDH.h"
#include "BotanRNG.h"
#include "CryptoFactory.h"
#include "BotanCryptoFactory.h"
#include "DHParameters.h"
#include "BotanDHKeyPair.h"
#include "BotanUtil.h"
#include <algorithm>
#include <botan/dl_group.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/version.h>

// Signing functions
bool BotanDH::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

bool BotanDH::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

bool BotanDH::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

// Verification functions
bool BotanDH::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

bool BotanDH::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

bool BotanDH::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

// Encryption functions
bool BotanDH::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		      ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DH does not support encryption");

	return false;
}

// Decryption functions
bool BotanDH::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		      ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DH does not support decryption");

	return false;
}

// Key factory
bool BotanDH::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
	BotanDH_PrivateKey* dh = NULL;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();

		// PKCS#3: 2^(l-1) <= x < 2^l
		Botan::BigInt x;
		if (params->getXBitLength() > 0)
		{
			x.randomize(*rng->getRNG(), params->getXBitLength());
		}

		dh = new BotanDH_PrivateKey(*rng->getRNG(),
					Botan::DL_Group(BotanUtil::byteString2bigInt(params->getP()),
					BotanUtil::byteString2bigInt(params->getG())),
					x);
	}
	catch (std::exception& e)
	{
		ERROR_MSG("DH key generation failed with %s", e.what());

		return false;
	}

	// Create an asymmetric key-pair object to return
	BotanDHKeyPair* kp = new BotanDHKeyPair();

	((BotanDHPublicKey*) kp->getPublicKey())->setFromBotan(dh);
	((BotanDHPrivateKey*) kp->getPrivateKey())->setFromBotan(dh);

	*ppKeyPair = kp;

	// Release the key
	delete dh;

	return true;
}

bool BotanDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get keys
	Botan::DH_PublicKey* pub = ((BotanDHPublicKey*) publicKey)->getBotanKey();
	BotanDH_PrivateKey* priv = ((BotanDHPrivateKey*) privateKey)->getBotanKey();
	if (pub == NULL || priv == NULL || priv->impl == NULL)
	{
		ERROR_MSG("Failed to get Botan DH keys");

		return false;
	}

	// Derive the secret
	Botan::SymmetricKey sk;
	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,33)
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		Botan::PK_Key_Agreement ka(*priv->impl, *rng->getRNG(), "Raw");
#else
		Botan::PK_Key_Agreement ka(*priv->impl, "Raw");
#endif
		sk = ka.derive_key(0, pub->public_value());
	}
	catch (std::exception& e)
	{
		ERROR_MSG("Botan DH key agreement failed: %s", e.what());

		return false;
	}

	ByteString secret;

	// We compensate that Botan removes leading zeros
	int size = ((BotanDHPublicKey*) publicKey)->getOutputLength();
	int keySize = sk.length();
	secret.wipe(size);
	memcpy(&secret[0] + size - keySize, sk.begin(), keySize);

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
	{
		ERROR_MSG("Can't create DH secret");

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

unsigned long BotanDH::getMinKeySize()
{
	return 512;
}

unsigned long BotanDH::getMaxKeySize()
{
	return 4096;
}

bool BotanDH::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
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

	Botan::DL_Group* group = NULL;
	try
	{
		BotanRNG* brng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		group = new Botan::DL_Group(*brng->getRNG(), Botan::DL_Group::Strong, bitLen);
	}
	catch (std::exception& e)
	{
		ERROR_MSG("Failed to generate %d bit DH parameters: %s", bitLen, e.what());

		return false;
	}

	// Store the DH parameters
	DHParameters* params = new DHParameters();

	ByteString p = BotanUtil::bigInt2ByteString(group->get_p());
	params->setP(p);
	ByteString g = BotanUtil::bigInt2ByteString(group->get_g());
	params->setG(g);

	*ppParams = params;

	delete group;

	return true;
}

bool BotanDH::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	BotanDHKeyPair* kp = new BotanDHKeyPair();

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

bool BotanDH::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanDHPublicKey* pub = new BotanDHPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool BotanDH::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanDHPrivateKey* priv = new BotanDHPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* BotanDH::newPublicKey()
{
	return (PublicKey*) new BotanDHPublicKey();
}

PrivateKey* BotanDH::newPrivateKey()
{
	return (PrivateKey*) new BotanDHPrivateKey();
}

AsymmetricParameters* BotanDH::newParameters()
{
	return (AsymmetricParameters*) new DHParameters();
}

bool BotanDH::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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

