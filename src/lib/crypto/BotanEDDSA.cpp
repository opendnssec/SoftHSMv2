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
 BotanEDDSA.cpp

 Botan EDDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "log.h"
#include "BotanEDDSA.h"
#include "BotanRNG.h"
#include "CryptoFactory.h"
#include "BotanCryptoFactory.h"
#include "ECParameters.h"
#include "BotanEDKeyPair.h"
#include "BotanUtil.h"
#include <algorithm>
#include <botan/curve25519.h>
#include <botan/ed25519.h>
// #include <botan/curve448.h>
// #include <botan/ed448.h>
#include <botan/version.h>
#include <iostream>

const Botan::OID x25519_oid("1.3.101.110");
// const Botan::OID x448_oid("1.3.101.111");
const Botan::OID ed25519_oid("1.3.101.112");
// const Botan::OID ed448_oid("1.3.101.113");

// Constructor
BotanEDDSA::BotanEDDSA()
{
	signer = NULL;
	verifier = NULL;
}

// Destructor
BotanEDDSA::~BotanEDDSA()
{
	delete signer;
	delete verifier;
}

// Signing functions
bool BotanEDDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		      ByteString& signature, const AsymMech::Type mechanism,
		      const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	std::string emsa;

	if (mechanism == AsymMech::EDDSA)
	{
		emsa = "Pure";
	}
        else
        {
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
        }

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanEDPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

        BotanEDPrivateKey* pk = (BotanEDPrivateKey*) privateKey;
        Botan::Ed25519_PrivateKey* botanKey = dynamic_cast<Botan::Ed25519_PrivateKey*>(pk->getBotanKey());

        if (botanKey == NULL)
        {
		ERROR_MSG("Could not get the Botan private key");

		return false;
	}

	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		signer = new Botan::PK_Signer(*botanKey, *rng->getRNG(), emsa);
		// Should we add DISABLE_FAULT_PROTECTION? Makes this operation faster.
	}
	catch (...)
	{
		ERROR_MSG("Could not create the signer token");

		return false;
	}

	// Perform the signature operation
	std::vector<Botan::byte> signResult;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		signResult = signer->sign_message(dataToSign.const_byte_str(), dataToSign.size(), *rng->getRNG());
	}
	catch (...)
	{
		ERROR_MSG("Could not sign the data");

		delete signer;
		signer = NULL;

		return false;
	}

	// Return the result
	signature.resize(signResult.size());
	memcpy(&signature[0], signResult.data(), signResult.size());

	delete signer;
	signer = NULL;

	return true;
}

// Signing functions
bool BotanEDDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			  const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("EDDSA does not support multi part signing");

	return false;
}

bool BotanEDDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("EDDSA does not support multi part signing");

	return false;
}

bool BotanEDDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("EDDSA does not support multi part signing");

	return false;
}

// Verification functions
bool BotanEDDSA::verify(PublicKey* publicKey, const ByteString& originalData,
			const ByteString& signature, const AsymMech::Type mechanism,
			const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	std::string emsa;

	if (mechanism == AsymMech::EDDSA)
	{
		emsa = "Pure";
	}
        else
        {
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanEDPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	BotanEDPublicKey* pk = (BotanEDPublicKey*) publicKey;
	Botan::Ed25519_PublicKey* botanKey = dynamic_cast<Botan::Ed25519_PublicKey*>(pk->getBotanKey());

	if (botanKey == NULL)
	{
		ERROR_MSG("Could not get the Botan public key");

		return false;
	}

	try
	{
		verifier = new Botan::PK_Verifier(*botanKey, emsa);
	}
	catch (...)
	{
		ERROR_MSG("Could not create the verifier token");

		return false;
	}

	// Perform the verify operation
	bool verResult;
	try
	{
		verResult = verifier->verify_message(originalData.const_byte_str(),
							originalData.size(),
							signature.const_byte_str(),
							signature.size());
	}
	catch (...)
	{
		ERROR_MSG("Could not check the signature");

		delete verifier;
		verifier = NULL;

		return false;
	}

	delete verifier;
	verifier = NULL;

	return verResult;
}

// Verification functions
bool BotanEDDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			    const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("EDDSA does not support multi part verifying");

	return false;
}

bool BotanEDDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("EDDSA does not support multi part verifying");

	return false;
}

bool BotanEDDSA::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("EDDSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool BotanEDDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			 ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("EDDSA does not support encryption");

	return false;
}

// Decryption functions
bool BotanEDDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			 ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("EDDSA does not support decryption");

	return false;
}

// Key factory
bool BotanEDDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
	Botan::OID oid = BotanUtil::byteString2Oid(params->getEC());

	// Generate the key-pair
	Botan::Private_Key* eckp = NULL;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		if (oid == x25519_oid)
		{
			eckp = new Botan::Curve25519_PrivateKey(*rng->getRNG());
		}
		else if (oid == ed25519_oid)
		{
			eckp = new Botan::Ed25519_PrivateKey(*rng->getRNG());
		}
		else
		{
			return false;
		}
	}
	catch (...)
	{
		ERROR_MSG("EDDSA key generation failed");

		return false;
	}

	// Create an asymmetric key-pair object to return
	BotanEDKeyPair* kp = new BotanEDKeyPair();

	((BotanEDPublicKey*) kp->getPublicKey())->setFromBotan(eckp);
	((BotanEDPrivateKey*) kp->getPrivateKey())->setFromBotan(eckp);

	*ppKeyPair = kp;

	// Release the key
	delete eckp;

	return true;
}

bool BotanEDDSA::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get keys
	BotanEDPublicKey* pubk = (BotanEDPublicKey*) publicKey;
	Botan::Curve25519_PublicKey* pub = dynamic_cast<Botan::Curve25519_PublicKey*>(pubk->getBotanKey());
	BotanEDPrivateKey* privk = (BotanEDPrivateKey*) privateKey;
	Botan::Curve25519_PrivateKey* priv = dynamic_cast<Botan::Curve25519_PrivateKey*>(privk->getBotanKey());
	if (pub == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get Botan EDDSA keys");

		return false;
	}

	// Derive the secret
	Botan::SymmetricKey sk;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		Botan::PK_Key_Agreement ka(*priv, *rng->getRNG(), "Raw");
		sk = ka.derive_key(0, pub->public_value());
	}
	catch (...)
	{
		ERROR_MSG("Botan EDDSA key agreement failed");

		return false;
	}

	ByteString secret;

	// We compensate that Botan removes leading zeros
	int size = pubk->getOrderLength();
	int keySize = sk.length();
	secret.wipe(size);
	memcpy(&secret[0] + size - keySize, sk.begin(), keySize);

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
	{
		ERROR_MSG("Can't create EDDSA secret");

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

unsigned long BotanEDDSA::getMinKeySize()
{
	// Only Ed25519 is supported
	return 32*8;
}

unsigned long BotanEDDSA::getMaxKeySize()
{
	// Only Ed25519 is supported
	return 32*8;
}

bool BotanEDDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	BotanEDKeyPair* kp = new BotanEDKeyPair();

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

bool BotanEDDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanEDPublicKey* pub = new BotanEDPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool BotanEDDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanEDPrivateKey* priv = new BotanEDPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* BotanEDDSA::newPublicKey()
{
	return (PublicKey*) new BotanEDPublicKey();
}

PrivateKey* BotanEDDSA::newPrivateKey()
{
	return (PrivateKey*) new BotanEDPrivateKey();
}

AsymmetricParameters* BotanEDDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool BotanEDDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
