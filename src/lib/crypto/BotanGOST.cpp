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
 BotanGOST.cpp

 Botan GOST R 34.10-2001 asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "BotanGOST.h"
#include "BotanRNG.h"
#include "CryptoFactory.h"
#include "BotanCryptoFactory.h"
#include "ECParameters.h"
#include "BotanGOSTKeyPair.h"
#include "BotanUtil.h"
#include <algorithm>
#include <botan/ec_group.h>
#include <botan/gost_3410.h>
#include <botan/version.h>
#include <iostream>

// Constructor
BotanGOST::BotanGOST()
{
	signer = NULL;
	verifier = NULL;
}

// Destructor
BotanGOST::~BotanGOST()
{
	delete signer;
	delete verifier;
}

// Signing functions
bool BotanGOST::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanGOSTPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	std::string emsa;

	switch (mechanism)
	{
		case AsymMech::GOST:
			emsa = "Raw";
			break;
		case AsymMech::GOST_GOST:
			emsa = "EMSA1(GOST-34.11)";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

        BotanGOSTPrivateKey* pk = (BotanGOSTPrivateKey*) currentPrivateKey;
        Botan::GOST_3410_PrivateKey* botanKey = pk->getBotanKey();

        if (botanKey == NULL)
        {
		ERROR_MSG("Could not get the Botan private key");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,33)
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		signer = new Botan::PK_Signer(*botanKey, *rng->getRNG(), emsa);
#else
		signer = new Botan::PK_Signer(*botanKey, emsa);
#endif
		// Should we add DISABLE_FAULT_PROTECTION? Makes this operation faster.
	}
	catch (...)
	{
		ERROR_MSG("Could not create the signer token");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool BotanGOST::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	try
	{
		if (dataToSign.size() != 0)
		{
			signer->update(dataToSign.const_byte_str(),
				       dataToSign.size());
		}
	}
	catch (...)
	{
		ERROR_MSG("Could not add data to signer token");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		delete signer;
		signer = NULL;

		return false;
	}

	return true;
}

bool BotanGOST::signFinal(ByteString& signature)
{
	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	// Perform the signature operation
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	std::vector<Botan::byte> signResult;
#else
	Botan::SecureVector<Botan::byte> signResult;
#endif
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		signResult = signer->signature(*rng->getRNG());
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
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	memcpy(&signature[0], signResult.data(), signResult.size());
#else
	memcpy(&signature[0], signResult.begin(), signResult.size());
#endif

	delete signer;
	signer = NULL;

	return true;
}

// Verification functions
bool BotanGOST::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			   const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanGOSTPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	std::string emsa;

	switch (mechanism)
	{
		case AsymMech::GOST:
			emsa = "Raw";
			break;
		case AsymMech::GOST_GOST:
			emsa = "EMSA1(GOST-34.11)";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	BotanGOSTPublicKey* pk = (BotanGOSTPublicKey*) currentPublicKey;
	Botan::GOST_3410_PublicKey* botanKey = pk->getBotanKey();

	if (botanKey == NULL)
	{
		ERROR_MSG("Could not get the Botan public key");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	try
	{
		verifier = new Botan::PK_Verifier(*botanKey, emsa);
	}
	catch (...)
	{
		ERROR_MSG("Could not create the verifier token");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool BotanGOST::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	try
	{
		if (originalData.size() != 0)
		{
			verifier->update(originalData.const_byte_str(),
					 originalData.size());
		}
	}
	catch (...)
	{
		ERROR_MSG("Could not add data to the verifier token");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		delete verifier;
		verifier = NULL;

		return false;
	}

	return true;
}

bool BotanGOST::verifyFinal(const ByteString& signature)
{
	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	// Perform the verify operation
	bool verResult;
	try
	{
		verResult = verifier->check_signature(signature.const_byte_str(), signature.size());
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

// Encryption functions
bool BotanGOST::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("GOST does not support encryption");

	return false;
}

// Decryption functions
bool BotanGOST::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("GOST does not support decryption");

	return false;
}

// Key factory
bool BotanGOST::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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

	// Generate the key-pair
	Botan::GOST_3410_PrivateKey* eckp = NULL;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		eckp = new Botan::GOST_3410_PrivateKey(*rng->getRNG(), BotanUtil::byteString2ECGroup(params->getEC()));
	}
	catch (...)
	{
		ERROR_MSG("GOST key generation failed");

		return false;
	}

	// Create an asymmetric key-pair object to return
	BotanGOSTKeyPair* kp = new BotanGOSTKeyPair();

	((BotanGOSTPublicKey*) kp->getPublicKey())->setFromBotan(eckp);
	((BotanGOSTPrivateKey*) kp->getPrivateKey())->setFromBotan(eckp);

	*ppKeyPair = kp;

	// Release the key
	delete eckp;

	return true;
}

unsigned long BotanGOST::getMinKeySize()
{
	return 0;
}

unsigned long BotanGOST::getMaxKeySize()
{
	return 0;
}

bool BotanGOST::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	BotanGOSTKeyPair* kp = new BotanGOSTKeyPair();

	bool rv = true;

	if (!((BotanGOSTPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((BotanGOSTPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool BotanGOST::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanGOSTPublicKey* pub = new BotanGOSTPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool BotanGOST::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanGOSTPrivateKey* priv = new BotanGOSTPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* BotanGOST::newPublicKey()
{
	return (PublicKey*) new BotanGOSTPublicKey();
}

PrivateKey* BotanGOST::newPrivateKey()
{
	return (PrivateKey*) new BotanGOSTPrivateKey();
}

AsymmetricParameters* BotanGOST::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool BotanGOST::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
