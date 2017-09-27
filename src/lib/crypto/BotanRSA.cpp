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
#include <botan/version.h>
#include <sstream>

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
bool BotanRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		    ByteString& signature, const AsymMech::Type mechanism,
		    const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	std::string emsa = "";

	switch (mechanism)
	{
		case AsymMech::RSA:
			emsa = "Raw";
			break;
		case AsymMech::RSA_PKCS:
			emsa = "EMSA3(Raw)";
			break;
#ifdef WITH_RAW_PSS
		case AsymMech::RSA_PKCS_PSS:
			emsa = getCipherRawPss(privateKey->getBitLength(), dataToSign.size(), param, paramLen);
			if (emsa == "")
			{
				return false;
			}
			break;
#endif
		default:
			// Call default implementation
			return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
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
	catch (std::exception& e)
	{
		ERROR_MSG("Could not sign the data: %s", e.what());

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

bool BotanRSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
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

	std::string emsa;
	std::ostringstream request;
	size_t sLen;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			emsa = "EMSA3(MD5)";
			break;
		case AsymMech::RSA_SHA1_PKCS:
			emsa = "EMSA3(SHA-160)";
			break;
		case AsymMech::RSA_SHA224_PKCS:
			emsa = "EMSA3(SHA-224)";
			break;
		case AsymMech::RSA_SHA256_PKCS:
			emsa = "EMSA3(SHA-256)";
			break;
		case AsymMech::RSA_SHA384_PKCS:
			emsa = "EMSA3(SHA-384)";
			break;
		case AsymMech::RSA_SHA512_PKCS:
			emsa = "EMSA3(SHA-512)";
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-20))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-160,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-224,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-256,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-384,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-512,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SSL:
			emsa = "EMSA3(Parallel(MD5,SHA-160))";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

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

bool BotanRSA::signUpdate(const ByteString& dataToSign)
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

bool BotanRSA::signFinal(ByteString& signature)
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
bool BotanRSA::verify(PublicKey* publicKey, const ByteString& originalData,
		      const ByteString& signature, const AsymMech::Type mechanism,
		      const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	std::string emsa = "";

	switch (mechanism)
	{
		case AsymMech::RSA:
			emsa = "Raw";
			break;
		case AsymMech::RSA_PKCS:
			emsa = "EMSA3(Raw)";
			break;
#ifdef WITH_RAW_PSS
		case AsymMech::RSA_PKCS_PSS:
			emsa = getCipherRawPss(publicKey->getBitLength(), originalData.size(), param, paramLen);
			if (emsa == "")
			{
				return false;
			}
			break;
#endif
		default:
			// Call the generic function
			return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
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

bool BotanRSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			  const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
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

	std::string emsa;
	std::ostringstream request;
	size_t sLen;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			emsa = "EMSA3(MD5)";
			break;
		case AsymMech::RSA_SHA1_PKCS:
			emsa = "EMSA3(SHA-160)";
			break;
		case AsymMech::RSA_SHA224_PKCS:
			emsa = "EMSA3(SHA-224)";
			break;
		case AsymMech::RSA_SHA256_PKCS:
			emsa = "EMSA3(SHA-256)";
			break;
		case AsymMech::RSA_SHA384_PKCS:
			emsa = "EMSA3(SHA-384)";
			break;
		case AsymMech::RSA_SHA512_PKCS:
			emsa = "EMSA3(SHA-512)";
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-20))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-160,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-224,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-256,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-384,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			request << "EMSA4(SHA-512,MGF1," << sLen << ")";
			emsa = request.str();
			break;
		case AsymMech::RSA_SSL:
			emsa = "EMSA3(Parallel(MD5,SHA-160))";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

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
bool BotanRSA::encrypt(PublicKey* publicKey, const ByteString& data,
		       ByteString& encryptedData, const AsymMech::Type padding)
{
	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	std::string eme;

	switch (padding)
	{
		case AsymMech::RSA_PKCS:
			eme = "PKCS1v15";
			break;
		case AsymMech::RSA_PKCS_OAEP:
			eme = "EME1(SHA-160)";
			break;
		case AsymMech::RSA:
			eme = "Raw";
			break;
		default:
			ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);

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
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,33)
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		encryptor = new Botan::PK_Encryptor_EME(*botanKey, *rng->getRNG(), eme);
#else
		encryptor = new Botan::PK_Encryptor_EME(*botanKey, eme);
#endif
	}
	catch (...)
	{
		ERROR_MSG("Could not create the encryptor token");

		return false;
	}

	// Perform the encryption operation
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	std::vector<Botan::byte> encResult;
#else
	Botan::SecureVector<Botan::byte> encResult;
#endif
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
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	memcpy(&encryptedData[0], encResult.data(), encResult.size());
#else
	memcpy(&encryptedData[0], encResult.begin(), encResult.size());
#endif

	delete encryptor;

	return true;
}

// Decryption functions
bool BotanRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
		       ByteString& data, const AsymMech::Type padding)
{
	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	std::string eme;

	switch (padding)
	{
		case AsymMech::RSA_PKCS:
			eme = "PKCS1v15";
			break;
		case AsymMech::RSA_PKCS_OAEP:
			eme = "EME1(SHA-160)";
			break;
		case AsymMech::RSA:
			eme = "Raw";
			break;
		default:
			ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);

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
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,33)
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		decryptor = new Botan::PK_Decryptor_EME(*botanKey, *rng->getRNG(), eme);
#else
		decryptor = new Botan::PK_Decryptor_EME(*botanKey, eme);
#endif
	}
	catch (...)
	{
		ERROR_MSG("Could not create the decryptor token");

		return false;
	}

	// Perform the decryption operation
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	Botan::secure_vector<Botan::byte> decResult;
#else
	Botan::SecureVector<Botan::byte> decResult;
#endif
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
	if (padding == AsymMech::RSA)
	{
		// We compensate that Botan removes leading zeros
		int modSize = pk->getN().size();
		int decSize = decResult.size();
		data.resize(modSize);
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
		memcpy(&data[0] + modSize - decSize, decResult.data(), decSize);
#else
		memcpy(&data[0] + modSize - decSize, decResult.begin(), decSize);
#endif
	}
	else
	{
		data.resize(decResult.size());
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
		memcpy(&data[0], decResult.data(), decResult.size());
#else
		memcpy(&data[0], decResult.begin(), decResult.size());
#endif
	}

	delete decryptor;

	return true;
}

// Key factory
bool BotanRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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

	if (params->getBitLength() < getMinKeySize() || params->getBitLength() > getMaxKeySize())
	{
		ERROR_MSG("This RSA key size (%lu) is not supported", params->getBitLength());

		return false;
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
		rsa = new Botan::RSA_PrivateKey(*rng->getRNG(),	params->getBitLength(),	e);
	}
	catch (std::exception& ex) {
		ERROR_MSG("RSA key generation failed: %s", ex.what());

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

unsigned long BotanRSA::getMinKeySize()
{
	return 1024;
}

unsigned long BotanRSA::getMaxKeySize()
{
	return 4096;
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

bool BotanRSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	RSAParameters* params = new RSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}

#ifdef WITH_RAW_PSS
std::string BotanRSA::getCipherRawPss(size_t bitLength, size_t dataSize, const void* param, const size_t paramLen)
{
	if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS))
	{
		ERROR_MSG("Invalid parameters");
		return "";
	}

	std::string hashStr = "";
	size_t allowedLen = 0;
	switch (((RSA_PKCS_PSS_PARAMS*) param)->hashAlg)
	{
		case HashAlgo::SHA1:
			hashStr = "SHA-160";
			allowedLen = 20;
			break;
		case HashAlgo::SHA224:
			hashStr = "SHA-224";
			allowedLen = 28;
			break;
		case HashAlgo::SHA256:
			hashStr = "SHA-256";
			allowedLen = 32;
			break;
		case HashAlgo::SHA384:
			hashStr = "SHA-384";
			allowedLen = 48;
			break;
		case HashAlgo::SHA512:
			hashStr = "SHA-512";
			allowedLen = 64;
			break;
		default:
			ERROR_MSG("Invalid hash parameter");
			return "";
	}

	if (dataSize != allowedLen)
	{
		ERROR_MSG("Data to sign does not match expected (%d) for RSA PSS", (int)allowedLen);
		return "";
	}

	size_t sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
	if (sLen > ((bitLength+6)/8-2-20))
	{
		ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
			  (unsigned long)sLen, bitLength);
		return "";
	}

	std::ostringstream request;
	request << "PSSR_Raw(" << hashStr << ",MGF1," << sLen << ")";
	return request.str();
}
#endif
