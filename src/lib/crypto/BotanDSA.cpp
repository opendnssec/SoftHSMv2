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
 BotanDSA.cpp

 Botan DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanDSA.h"
#include "BotanRNG.h"
#include "CryptoFactory.h"
#include "BotanCryptoFactory.h"
#include "DSAParameters.h"
#include "BotanDSAKeyPair.h"
#include "BotanUtil.h"
#include <algorithm>
#include <botan/dl_group.h>
#include <botan/dsa.h>
#include <botan/version.h>
#include <iostream>

// Constructor
BotanDSA::BotanDSA()
{
	signer = NULL;
	verifier = NULL;
}

// Destructor
BotanDSA::~BotanDSA()
{
	delete signer;
	delete verifier;
}

// Signing functions
bool BotanDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		    ByteString& signature, const AsymMech::Type mechanism,
		    const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	std::string emsa;

	if (mechanism == AsymMech::DSA)
	{
		emsa = "Raw";
	}
	else
        {
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
        }

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

        BotanDSAPrivateKey* pk = (BotanDSAPrivateKey*) privateKey;
        Botan::DSA_PrivateKey* botanKey = pk->getBotanKey();

        if (!botanKey)
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

bool BotanDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	std::string emsa;

	switch (mechanism)
	{
		case AsymMech::DSA_SHA1:
			emsa = "EMSA1(SHA-160)";
			break;
		case AsymMech::DSA_SHA224:
			emsa = "EMSA1(SHA-224)";
			break;
		case AsymMech::DSA_SHA256:
			emsa = "EMSA1(SHA-256)";
			break;
		case AsymMech::DSA_SHA384:
			emsa = "EMSA1(SHA-384)";
			break;
		case AsymMech::DSA_SHA512:
			emsa = "EMSA1(SHA-512)";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
        }

        BotanDSAPrivateKey* pk = (BotanDSAPrivateKey*) currentPrivateKey;
        Botan::DSA_PrivateKey* botanKey = pk->getBotanKey();

        if (!botanKey)
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

bool BotanDSA::signUpdate(const ByteString& dataToSign)
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

bool BotanDSA::signFinal(ByteString& signature)
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
bool BotanDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		      const ByteString& signature, const AsymMech::Type mechanism,
		      const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	std::string emsa;

	if (mechanism == AsymMech::DSA)
	{
		emsa = "Raw";
	}
        else
        {
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	BotanDSAPublicKey* pk = (BotanDSAPublicKey*) publicKey;
	Botan::DSA_PublicKey* botanKey = pk->getBotanKey();

	if (!botanKey)
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

bool BotanDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			  const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	std::string emsa;

	switch (mechanism)
	{
		case AsymMech::DSA_SHA1:
			emsa = "EMSA1(SHA-160)";
			break;
		case AsymMech::DSA_SHA224:
			emsa = "EMSA1(SHA-224)";
			break;
		case AsymMech::DSA_SHA256:
			emsa = "EMSA1(SHA-256)";
			break;
		case AsymMech::DSA_SHA384:
			emsa = "EMSA1(SHA-384)";
			break;
		case AsymMech::DSA_SHA512:
			emsa = "EMSA1(SHA-512)";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
        }

	BotanDSAPublicKey* pk = (BotanDSAPublicKey*) currentPublicKey;
	Botan::DSA_PublicKey* botanKey = pk->getBotanKey();

	if (!botanKey)
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

bool BotanDSA::verifyUpdate(const ByteString& originalData)
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

bool BotanDSA::verifyFinal(const ByteString& signature)
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
bool BotanDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		       ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DSA does not support encryption");

	return false;
}

// Decryption functions
bool BotanDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		       ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DSA does not support decryption");

	return false;
}

// Key factory
bool BotanDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
	Botan::DSA_PrivateKey* dsa = NULL;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		dsa = new Botan::DSA_PrivateKey(*rng->getRNG(),
					Botan::DL_Group(BotanUtil::byteString2bigInt(params->getP()),
					BotanUtil::byteString2bigInt(params->getQ()),
					BotanUtil::byteString2bigInt(params->getG())));
	}
	catch (...)
	{
		ERROR_MSG("DSA key generation failed");

		return false;
	}

	// Create an asymmetric key-pair object to return
	BotanDSAKeyPair* kp = new BotanDSAKeyPair();

	((BotanDSAPublicKey*) kp->getPublicKey())->setFromBotan(dsa);
	((BotanDSAPrivateKey*) kp->getPrivateKey())->setFromBotan(dsa);

	*ppKeyPair = kp;

	// Release the key
	delete dsa;

	return true;
}

unsigned long BotanDSA::getMinKeySize()
{
	return 512;
}

unsigned long BotanDSA::getMaxKeySize()
{
	// Taken from OpenSSL
	return 10000;
}

bool BotanDSA::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
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

	Botan::DL_Group* group = NULL;
	// Taken from OpenSSL
	size_t qLen = bitLen >= 2048 ? 256 : 160;
	try
	{
		BotanRNG* brng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		group = new Botan::DL_Group(*brng->getRNG(), Botan::DL_Group::Prime_Subgroup, bitLen, qLen);
	}
	catch (std::exception& e)
	{
		ERROR_MSG("Failed to generate %d bit DSA parameters: %s", bitLen, e.what());

		return false;
	}

	// Store the DSA parameters
	DSAParameters* params = new DSAParameters();

	ByteString p = BotanUtil::bigInt2ByteString(group->get_p());
	params->setP(p);
	ByteString q = BotanUtil::bigInt2ByteString(group->get_q());
	params->setQ(q);
	ByteString g = BotanUtil::bigInt2ByteString(group->get_g());
	params->setG(g);

	*ppParams = params;

	delete group;

	return true;
}

bool BotanDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	BotanDSAKeyPair* kp = new BotanDSAKeyPair();

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

bool BotanDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanDSAPublicKey* pub = new BotanDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool BotanDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanDSAPrivateKey* priv = new BotanDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* BotanDSA::newPublicKey()
{
	return (PublicKey*) new BotanDSAPublicKey();
}

PrivateKey* BotanDSA::newPrivateKey()
{
	return (PrivateKey*) new BotanDSAPrivateKey();
}

AsymmetricParameters* BotanDSA::newParameters()
{
	return (AsymmetricParameters*) new DSAParameters();
}

bool BotanDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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

