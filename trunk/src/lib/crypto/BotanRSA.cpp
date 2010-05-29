/* $Id$ */

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
 BotanRSA.cpp

 Botan RSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanRSA.h"
#include "BotanRNG.h"
#include "CryptoFactory.h"
#include "BotanCryptoFactory.h"
#include "RSAParameters.h"
#include "BotanRSAKeyPair.h"
#include <algorithm>
#include <botan/rsa.h>

// Constructor
BotanRSA::BotanRSA()
{
	signer = NULL;
	verifier = NULL;
}

// Destructor
BotanRSA::~BotanRSA()
{
	delete signer;
	delete verifier;
}

// Signing functions
bool BotanRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const 
std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);
	std::string emsa = "";

	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		emsa = "EMSA3(Raw)";
	}
	else if (!lowerMechanism.compare("rsa"))
	{
		emsa = "Raw";
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism);
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	BotanRSAPrivateKey* pk = (BotanRSAPrivateKey*) privateKey;
	Botan::RSA_PrivateKey* botanKey = pk->getBotanKey();

	if (!botanKey)
	{
		ERROR_MSG("Could not get the Botan private key");

		return false;
	}

	try
	{
		signer = new Botan::PK_Signer(*botanKey, emsa);
		// Should we add DISABLE_FAULT_PROTECTION? Makes this operation faster.
	}
	catch (...)
	{
		ERROR_MSG("Could not create the signer token");

		return false;
	}

	// Perform the signature operation
	Botan::SecureVector<Botan::byte> signResult;
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
	memcpy(&signature[0], signResult.begin(), signResult.size());

	delete signer;
	signer = NULL;

	return true;
}
	
bool BotanRSA::signInit(PrivateKey* privateKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);
	std::string emsa;

	if (!lowerMechanism.compare("rsa-md5-pkcs"))
	{
		emsa = "EMSA3(MD5)";
	}
	else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
	{
		emsa = "EMSA3(SHA-160)";
	}
	else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
	{
		emsa = "EMSA3(SHA-256)";
	}
	else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
	{
		emsa = "EMSA3(SHA-512)";
	}
	else if (!lowerMechanism.compare("rsa-ssl"))
	{
		emsa = "EMSA3(Parallel(MD5,SHA-160))";
	}
	else
	{
		ERROR_MSG("Invalid mechanism supplied (%s)", mechanism.c_str());

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	BotanRSAPrivateKey* pk = (BotanRSAPrivateKey*) currentPrivateKey;
	Botan::RSA_PrivateKey* botanKey = pk->getBotanKey();

	if (!botanKey)
	{
		ERROR_MSG("Could not get the Botan private key");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	try
	{
		signer = new Botan::PK_Signer(*botanKey, emsa);
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

bool BotanRSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	try
	{
		signer->update(dataToSign.const_byte_str(), dataToSign.size());
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

bool BotanRSA::signFinal(ByteString& signature)
{
	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	// Perform the signature operation
	Botan::SecureVector<Botan::byte> signResult;
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
	memcpy(&signature[0], signResult.begin(), signResult.size());

	delete signer;
	signer = NULL;

	return true;
}

// Verification functions
bool BotanRSA::verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);
	std::string emsa = "";

	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		emsa = "EMSA3(Raw)";
	}
	else if (!lowerMechanism.compare("rsa"))
	{
		emsa = "Raw";
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism);
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	BotanRSAPublicKey* pk = (BotanRSAPublicKey*) publicKey;
	Botan::RSA_PublicKey* botanKey = pk->getBotanKey();

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

bool BotanRSA::verifyInit(PublicKey* publicKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);
	std::string emsa;

	if (!lowerMechanism.compare("rsa-md5-pkcs"))
	{
		emsa = "EMSA3(MD5)";
	}
	else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
	{
		emsa = "EMSA3(SHA-160)";
	}
	else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
	{
		emsa = "EMSA3(SHA-256)";
	}
	else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
	{
		emsa = "EMSA3(SHA-512)";
	}
	else if (!lowerMechanism.compare("rsa-ssl"))
	{
		emsa = "EMSA3(Parallel(MD5,SHA-160))";
	}
	else
	{
		ERROR_MSG("Invalid mechanism supplied (%s)", mechanism.c_str());

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	BotanRSAPublicKey* pk = (BotanRSAPublicKey*) currentPublicKey;
	Botan::RSA_PublicKey* botanKey = pk->getBotanKey();

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

bool BotanRSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	try
	{
		verifier->update(originalData.const_byte_str(), originalData.size());
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

bool BotanRSA::verifyFinal(const ByteString& signature)
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
bool BotanRSA::encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const std::string padding)
{
	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	std::string lowerPadding;
	lowerPadding.resize(padding.size());
	std::transform(padding.begin(), padding.end(), lowerPadding.begin(), tolower);
	std::string eme;

	if (!lowerPadding.compare("rsa-pkcs"))
	{
		eme = "PKCS1v15";
	}
	else if (!lowerPadding.compare("rsa-pkcs-oaep"))
	{
		eme = "EME1(SHA-160)";
	}
	else if (!lowerPadding.compare("rsa-raw"))
	{
		eme = "Raw";
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%s)", padding.c_str());

		return false;
	}

	BotanRSAPublicKey* pk = (BotanRSAPublicKey*) publicKey;
	Botan::RSA_PublicKey* botanKey = pk->getBotanKey();

	if (!botanKey)
	{
		ERROR_MSG("Could not get the Botan public key");

		return false;
	}

	Botan::PK_Encryptor_EME* encryptor = NULL;
	try
	{
		encryptor = new Botan::PK_Encryptor_EME(*botanKey, eme);
	}
	catch (...)
	{
		ERROR_MSG("Could not create the encryptor token");

		return false;
	}

	// Perform the encryption operation
	Botan::SecureVector<Botan::byte> encResult;
	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		encResult = encryptor->encrypt(data.const_byte_str(), data.size(), *rng->getRNG());
	}
	catch (...)
	{
		ERROR_MSG("Could not encrypt the data");

		delete encryptor;

		return false;
	}

	// Return the result
	encryptedData.resize(encResult.size());
	memcpy(&encryptedData[0], encResult.begin(), encResult.size());

	delete encryptor;

	return true;
}

// Decryption functions
bool BotanRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const std::string padding)
{
	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	std::string lowerPadding;
	lowerPadding.resize(padding.size());
	std::transform(padding.begin(), padding.end(), lowerPadding.begin(), tolower);
	std::string eme;

	if (!lowerPadding.compare("rsa-pkcs"))
	{
		eme = "PKCS1v15";
	}
	else if (!lowerPadding.compare("rsa-pkcs-oaep"))
	{
		eme = "EME1(SHA-160)";
	}
	else if (!lowerPadding.compare("rsa-raw"))
	{
		eme = "Raw";
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%s)", padding.c_str());

		return false;
	}

	BotanRSAPrivateKey* pk = (BotanRSAPrivateKey*) privateKey;
	Botan::RSA_PrivateKey* botanKey = pk->getBotanKey();

	if (!botanKey)
	{
		ERROR_MSG("Could not get the Botan private key");

		return false;
	}

	Botan::PK_Decryptor_EME* decryptor = NULL;
	try
	{
		decryptor = new Botan::PK_Decryptor_EME(*botanKey, eme);
	}
	catch (...)
	{
		ERROR_MSG("Could not create the decryptor token");

		return false;
	}

	// Perform the decryption operation
	Botan::SecureVector<Botan::byte> decResult;
	try
	{
		decResult = decryptor->decrypt(encryptedData.const_byte_str(), encryptedData.size());
	}
	catch (...)
	{
		ERROR_MSG("Could not decrypt the data");

		delete decryptor;

		return false;
	}

	// Return the result
	if (!eme.compare("Raw"))
	{
		// We compensate that Botan removes leading zeros
		int modSize = pk->getN().size();
		int decSize = decResult.size();
		data.resize(modSize);
		memcpy(&data[0] + modSize - decSize, decResult.begin(), decSize);
	}
	else
	{
		data.resize(decResult.size());
		memcpy(&data[0], decResult.begin(), decResult.size());
	}

	delete decryptor;

	return true;
}

// Key factory
bool BotanRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng /* = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(RSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for RSA key generation");

		return false;
	}

	RSAParameters* params = (RSAParameters*) parameters;

	if (params->getBitLength() < 1024)
	{
		WARNING_MSG("Using an RSA key size < 1024 bits is not recommended");
	}

	// Retrieve the desired public exponent
	unsigned long e = params->getE().long_val();

	// Check the public exponent
	if ((e == 0) || (e % 2 != 1))
	{
		ERROR_MSG("Invalid RSA public exponent %d", e);

		return false;
	}

	// Create an asymmetric key-pair object to return
	BotanRSAKeyPair* kp = new BotanRSAKeyPair();

	// Generate the key-pair
	Botan::RSA_PrivateKey* rsa = NULL;
	try {
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		rsa = new Botan::RSA_PrivateKey(*rng->getRNG(),
					(Botan::u32bit)params->getBitLength(),
					(Botan::u32bit)e);
	}
	catch(...) {
		ERROR_MSG("RSA key generation failed");

		delete kp;

		return false;
	}

	((BotanRSAPublicKey*) kp->getPublicKey())->setFromBotan(rsa);
	((BotanRSAPrivateKey*) kp->getPrivateKey())->setFromBotan(rsa);

	*ppKeyPair = kp;

	// Release the key
	delete rsa;

	return true;
}

bool BotanRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	BotanRSAKeyPair* kp = new BotanRSAKeyPair();

	bool rv = true;

	if (!((RSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((RSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool BotanRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanRSAPublicKey* pub = new BotanRSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool BotanRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	BotanRSAPrivateKey* priv = new BotanRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* BotanRSA::newPublicKey()
{
	return (PublicKey*) new BotanRSAPublicKey();
}

PrivateKey* BotanRSA::newPrivateKey()
{
	return (PrivateKey*) new BotanRSAPrivateKey();
}
	
AsymmetricParameters* BotanRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

