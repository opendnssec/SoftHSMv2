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
 BotanECDSA.cpp

 Botan ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "BotanECDSA.h"
#include "BotanRNG.h"
#include "CryptoFactory.h"
#include "BotanCryptoFactory.h"
#include "ECParameters.h"
#include "BotanECDSAKeyPair.h"
#include "BotanUtil.h"
#include <algorithm>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/version.h>
#include <iostream>

// Constructor
BotanECDSA::BotanECDSA()
{
	signer = NULL;
	verifier = NULL;
}

// Destructor
BotanECDSA::~BotanECDSA()
{
	delete signer;
	delete verifier;
}

// Signing functions
bool BotanECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		      ByteString& signature, const AsymMech::Type mechanism,
		      const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	std::string emsa;

	if (mechanism == AsymMech::ECDSA)
	{
		emsa = "Raw";
	}
        else
        {
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
        }

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanECDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

        BotanECDSAPrivateKey* pk = (BotanECDSAPrivateKey*) privateKey;
        Botan::ECDSA_PrivateKey* botanKey = pk->getBotanKey();

        if (botanKey == NULL)
        {
		ERROR_MSG("Could not get the Botan private key");

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
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	memcpy(&signature[0], signResult.data(), signResult.size());
#else
	memcpy(&signature[0], signResult.begin(), signResult.size());
#endif

	delete signer;
	signer = NULL;

	return true;
}

// Signing functions
bool BotanECDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			  const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool BotanECDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool BotanECDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

// Verification functions
bool BotanECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
			const ByteString& signature, const AsymMech::Type mechanism,
			const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	std::string emsa;

	if (mechanism == AsymMech::ECDSA)
	{
		emsa = "Raw";
	}
        else
        {
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanECDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	BotanECDSAPublicKey* pk = (BotanECDSAPublicKey*) publicKey;
	Botan::ECDSA_PublicKey* botanKey = pk->getBotanKey();

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
bool BotanECDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			    const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool BotanECDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool BotanECDSA::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool BotanECDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			 ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support encryption");

	return false;
}

// Decryption functions
bool BotanECDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			 ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support decryption");

	return false;
}

// Key factory
bool BotanECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
	Botan::ECDSA_PrivateKey* eckp = NULL;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		eckp = new Botan::ECDSA_PrivateKey(*rng->getRNG(), BotanUtil::byteString2ECGroup(params->getEC()));
	}
	catch (...)
	{
		ERROR_MSG("ECDSA key generation failed");

		return false;
	}

	// Create an asymmetric key-pair object to return
	BotanECDSAKeyPair* kp = new BotanECDSAKeyPair();

	((BotanECDSAPublicKey*) kp->getPublicKey())->setFromBotan(eckp);
	((BotanECDSAPrivateKey*) kp->getPrivateKey())->setFromBotan(eckp);

	*ppKeyPair = kp;

	// Release the key
	delete eckp;

	return true;
}

unsigned long BotanECDSA::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long BotanECDSA::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool BotanECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	BotanECDSAKeyPair* kp = new BotanECDSAKeyPair();

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

bool BotanECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanECDSAPublicKey* pub = new BotanECDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool BotanECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanECDSAPrivateKey* priv = new BotanECDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* BotanECDSA::newPublicKey()
{
	return (PublicKey*) new BotanECDSAPublicKey();
}

PrivateKey* BotanECDSA::newPrivateKey()
{
	return (PrivateKey*) new BotanECDSAPrivateKey();
}

AsymmetricParameters* BotanECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool BotanECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
