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
 OSSLRSA.cpp

 OpenSSL RSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLRSA.h"
#include "OSSLUtil.h"
#include "CryptoFactory.h"
#include "RSAParameters.h"
#include "OSSLRSAKeyPair.h"
#include <algorithm>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Constructor
OSSLRSA::OSSLRSA()
{
	pCurrentHash = NULL;
	pSecondHash = NULL;
	sLen = 0;
}

// Destructor
OSSLRSA::~OSSLRSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
	}
}

// Signing functions
bool OSSLRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		   ByteString& signature, const AsymMech::Type mechanism,
		   const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		// Separate implementation for RSA PKCS #1 signing without hash computation

		// Check if the private key is the right type
		if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// In case of PKCS #1 signing the length of the input data may not exceed 40% of the
		// modulus size
		OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;

		size_t allowedLen = osslKey->getN().size() - 11;

		if (dataToSign.size() > allowedLen)
		{
			ERROR_MSG("Data to sign exceeds maximum for PKCS #1 signature");

			return false;
		}

		// Perform the signature operation
		signature.resize(osslKey->getN().size());

		RSA* rsa = osslKey->getOSSLKey();

		if (!RSA_blinding_on(rsa, NULL))
		{
			ERROR_MSG("Failed to turn on blinding for OpenSSL RSA key");

			return false;
		}

		int sigLen = RSA_private_encrypt(dataToSign.size(), (unsigned char*) dataToSign.const_byte_str(), &signature[0], rsa, RSA_PKCS1_PADDING);

		RSA_blinding_off(rsa);

		if (sigLen == -1)
		{
			ERROR_MSG("An error occurred while performing a PKCS #1 signature");

			return false;
		}

		signature.resize(sigLen);

		return true;
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		const RSA_PKCS_PSS_PARAMS *pssParam = (RSA_PKCS_PSS_PARAMS*)param;

		// Separate implementation for RSA PKCS #1 signing without hash computation

		// Check if the private key is the right type
		if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		if (pssParam == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS))
		{
			ERROR_MSG("Invalid parameters supplied");

			return false;
		}

		size_t allowedLen;
		const EVP_MD* hash = NULL;

		switch (pssParam->hashAlg)
		{
		case HashAlgo::SHA1:
			hash = EVP_sha1();
			allowedLen = 20;
			break;
		case HashAlgo::SHA224:
			hash = EVP_sha224();
			allowedLen = 28;
			break;
		case HashAlgo::SHA256:
			hash = EVP_sha256();
			allowedLen = 32;
			break;
		case HashAlgo::SHA384:
			hash = EVP_sha384();
			allowedLen = 48;
			break;
		case HashAlgo::SHA512:
			hash = EVP_sha512();
			allowedLen = 64;
			break;
		default:
			return false;
		}

		OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;

		RSA* rsa = osslKey->getOSSLKey();

		if (dataToSign.size() != allowedLen)
		{
			ERROR_MSG("Data to sign does not match expected (%d) for RSA PSS", (int)allowedLen);

			return false;
		}

		size_t sLen = pssParam->sLen;
		if (sLen > ((privateKey->getBitLength()+6)/8-2-allowedLen))
		{
			ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
				  (unsigned long)sLen, privateKey->getBitLength());
			return false;
		}

		ByteString em;
		em.resize(osslKey->getN().size());

		int status = RSA_padding_add_PKCS1_PSS_mgf1(rsa, &em[0], (unsigned char*) dataToSign.const_byte_str(), hash, hash, pssParam->sLen);
		if (!status)
		{
			ERROR_MSG("Error in RSA PSS padding generation");

			return false;
		}


		if (!RSA_blinding_on(rsa, NULL))
		{
			ERROR_MSG("Failed to turn on blinding for OpenSSL RSA key");

			return false;
		}

		// Perform the signature operation
		signature.resize(osslKey->getN().size());

		int sigLen = RSA_private_encrypt(osslKey->getN().size(), &em[0], &signature[0], rsa, RSA_NO_PADDING);

		RSA_blinding_off(rsa);

		if (sigLen == -1)
		{
			ERROR_MSG("An error occurred while performing the RSA-PSS signature");

			return false;
		}

		signature.resize(sigLen);

		return true;
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Separate implementation for raw RSA signing

		// Check if the private key is the right type
		if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// In case of raw RSA, the length of the input data must match the length of the modulus
		OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;

		if (dataToSign.size() != osslKey->getN().size())
		{
			ERROR_MSG("Size of data to sign does not match the modulus size");

			return false;
		}

		// Perform the signature operation
		signature.resize(osslKey->getN().size());

		RSA* rsa = osslKey->getOSSLKey();

		if (!RSA_blinding_on(rsa, NULL))
		{
			ERROR_MSG("Failed to turn on blinding for OpenSSL RSA key");

			return false;
		}

		int sigLen = RSA_private_encrypt(dataToSign.size(), (unsigned char*) dataToSign.const_byte_str(), &signature[0], rsa, RSA_NO_PADDING);

		RSA_blinding_off(rsa);

		if (sigLen == -1)
		{
			ERROR_MSG("An error occurred while performing a raw RSA signature");

			return false;
		}

		signature.resize(sigLen);

		return true;
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
	}
}

bool OSSLRSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
		       const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
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
			hash1 = HashAlgo::SHA1;
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
			hash1 = HashAlgo::SHA224;
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
			hash1 = HashAlgo::SHA256;
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
			hash1 = HashAlgo::SHA384;
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
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);

		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;

			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
		}
	}

	return true;
}

bool OSSLRSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		delete pSecondHash;
		pSecondHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLRSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	OSSLRSAPrivateKey* pk = (OSSLRSAPrivateKey*) currentPrivateKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;

		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	// Resize the data block for the signature to the modulus size of the key
	signature.resize(pk->getN().size());

	// Determine the signature NID type
	int type = 0;
	bool isPSS = false;
	const EVP_MD* hash = NULL;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			type = NID_md5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			type = NID_sha1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			type = NID_sha224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			type = NID_sha256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			type = NID_sha384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			type = NID_sha512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha1();
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha224();
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha256();
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha384();
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha512();
			break;
		case AsymMech::RSA_SSL:
			type = NID_md5_sha1;
			break;
		default:
			break;
	}

	// Perform the signature operation
	unsigned int sigLen = signature.size();

	RSA* rsa = pk->getOSSLKey();

	if (!RSA_blinding_on(rsa, NULL))
	{
		ERROR_MSG("Failed to turn blinding on for OpenSSL RSA key");

		return false;
	}

	bool rv;
	int result;

	if (isPSS)
	{
		ByteString em;
		em.resize(pk->getN().size());

		result = (RSA_padding_add_PKCS1_PSS(pk->getOSSLKey(), &em[0], &digest[0],
						hash, sLen) == 1);
		if (!result)
		{
			ERROR_MSG("RSA PSS padding failed (0x%08X)", ERR_get_error());
			rv = false;
		}
		else
		{
			result = RSA_private_encrypt(em.size(), &em[0], &signature[0],
							 pk->getOSSLKey(), RSA_NO_PADDING);
			if (result >= 0)
			{
				sigLen = result;
				rv = true;
			}
			else
			{
				ERROR_MSG("RSA private encrypt failed (0x%08X)", ERR_get_error());
				rv = false;
			}
		}
	}
	else
	{
		result = RSA_sign(type, &digest[0], digest.size(), &signature[0],
			       &sigLen, pk->getOSSLKey());
		if (result > 0)
		{
			rv = true;
		}
		else
		{
			ERROR_MSG("RSA sign failed (0x%08X)", ERR_get_error());
			rv = false;
		}
	}

	RSA_blinding_off(rsa);

	signature.resize(sigLen);

	return rv;
}

// Verification functions
bool OSSLRSA::verify(PublicKey* publicKey, const ByteString& originalData,
		     const ByteString& signature, const AsymMech::Type mechanism,
		     const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		// Specific implementation for PKCS #1 only verification; originalData is assumed to contain
		// a digestInfo structure and verification is performed by comparing originalData to the data
		// recovered from the signature

		// Check if the public key is the right type
		if (!publicKey->isOfType(OSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the RSA public key operation
		OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;

		ByteString recoveredData;

		recoveredData.resize(osslKey->getN().size());

		RSA* rsa = osslKey->getOSSLKey();

		int retLen = RSA_public_decrypt(signature.size(), (unsigned char*) signature.const_byte_str(), &recoveredData[0], rsa, RSA_PKCS1_PADDING);

		if (retLen == -1)
		{
			ERROR_MSG("Public key operation failed");

			return false;
		}

		recoveredData.resize(retLen);

		return (originalData == recoveredData);
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		const RSA_PKCS_PSS_PARAMS *pssParam = (RSA_PKCS_PSS_PARAMS*)param;

		if (pssParam == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS))
		{
			ERROR_MSG("Invalid parameters supplied");

			return false;
		}

		// Check if the public key is the right type
		if (!publicKey->isOfType(OSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the RSA public key operation
		OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;

		ByteString recoveredData;

		recoveredData.resize(osslKey->getN().size());

		RSA* rsa = osslKey->getOSSLKey();

		int retLen = RSA_public_decrypt(signature.size(), (unsigned char*) signature.const_byte_str(), &recoveredData[0], rsa, RSA_NO_PADDING);

		if (retLen == -1)
		{
			ERROR_MSG("Public key operation failed");

			return false;
		}

		recoveredData.resize(retLen);

		size_t allowedLen;
		const EVP_MD* hash = NULL;

		switch (pssParam->hashAlg)
		{
		case HashAlgo::SHA1:
			hash = EVP_sha1();
			allowedLen = 20;
			break;
		case HashAlgo::SHA224:
			hash = EVP_sha224();
			allowedLen = 28;
			break;
		case HashAlgo::SHA256:
			hash = EVP_sha256();
			allowedLen = 32;
			break;
		case HashAlgo::SHA384:
			hash = EVP_sha384();
			allowedLen = 48;
			break;
		case HashAlgo::SHA512:
			hash = EVP_sha512();
			allowedLen = 64;
			break;
		default:
			return false;
		}

		if (originalData.size() != allowedLen) {
			return false;
		}

		size_t sLen = pssParam->sLen;
		if (sLen > ((osslKey->getBitLength()+6)/8-2-allowedLen))
		{
			ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
				  (unsigned long)sLen, osslKey->getBitLength());
			return false;
		}

		int status = RSA_verify_PKCS1_PSS_mgf1(rsa, (unsigned char*)originalData.const_byte_str(), hash, hash, (unsigned char*) recoveredData.const_byte_str(), pssParam->sLen);

		return (status == 1);
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Specific implementation for raw RSA verifiction; originalData is assumed to contain the
		// full input data used to compute the signature and verification is performed by comparing
		// originalData to the data recovered from the signature

		// Check if the public key is the right type
		if (!publicKey->isOfType(OSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the RSA public key operation
		OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;

		ByteString recoveredData;

		recoveredData.resize(osslKey->getN().size());

		RSA* rsa = osslKey->getOSSLKey();

		int retLen = RSA_public_decrypt(signature.size(), (unsigned char*) signature.const_byte_str(), &recoveredData[0], rsa, RSA_NO_PADDING);

		if (retLen == -1)
		{
			ERROR_MSG("Public key operation failed");

			return false;
		}

		recoveredData.resize(retLen);

		return (originalData == recoveredData);
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
	}
}

bool OSSLRSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
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
			hash1 = HashAlgo::SHA1;
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
			hash1 = HashAlgo::SHA224;
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
			hash1 = HashAlgo::SHA256;
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
			hash1 = HashAlgo::SHA384;
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
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);

		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;

			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
		}
	}

	return true;
}

bool OSSLRSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		delete pSecondHash;
		pSecondHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLRSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	OSSLRSAPublicKey* pk = (OSSLRSAPublicKey*) currentPublicKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;

		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	// Determine the signature NID type
	int type = 0;
	bool isPSS = false;
	const EVP_MD* hash = NULL;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			type = NID_md5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			type = NID_sha1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			type = NID_sha224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			type = NID_sha256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			type = NID_sha384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			type = NID_sha512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha1();
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha224();
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha256();
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha384();
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			isPSS = true;
			hash = EVP_sha512();
			break;
		case AsymMech::RSA_SSL:
			type = NID_md5_sha1;
			break;
		default:
			break;
	}

	// Perform the verify operation
	bool rv;

	if (isPSS)
	{
		ByteString plain;
		plain.resize(pk->getN().size());
		int result = RSA_public_decrypt(signature.size(),
						(unsigned char*) signature.const_byte_str(),
						&plain[0],
						pk->getOSSLKey(),
						RSA_NO_PADDING);
		if (result < 0)
		{
			rv = false;
			ERROR_MSG("RSA public decrypt failed (0x%08X)", ERR_get_error());
		}
		else
		{
			plain.resize(result);
			result = RSA_verify_PKCS1_PSS(pk->getOSSLKey(), &digest[0],
						      hash, &plain[0], sLen);
			if (result == 1)
			{
				rv = true;
			}
			else
			{
				rv = false;
				ERROR_MSG("RSA PSS verify failed (0x%08X)", ERR_get_error());
			}
		}
	}
	else
	{
		rv = (RSA_verify(type, &digest[0], digest.size(), (unsigned char*) signature.const_byte_str(), signature.size(), pk->getOSSLKey()) == 1);

		if (!rv) ERROR_MSG("RSA verify failed (0x%08X)", ERR_get_error());
	}

	return rv;
}

// Encryption functions
bool OSSLRSA::encrypt(PublicKey* publicKey, const ByteString& data,
		      ByteString& encryptedData, const AsymMech::Type padding)
{
	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	// Retrieve the OpenSSL key object
	RSA* rsa = ((OSSLRSAPublicKey*) publicKey)->getOSSLKey();

	// Check the data and padding algorithm
	int osslPadding = 0;

	if (padding == AsymMech::RSA_PKCS)
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 11
		if (data.size() > (size_t) (RSA_size(rsa) - 11))
		{
			ERROR_MSG("Too much data supplied for RSA PKCS #1 encryption");

			return false;
		}

		osslPadding = RSA_PKCS1_PADDING;
	}
	else if (padding == AsymMech::RSA_PKCS_OAEP)
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 41
		if (data.size() > (size_t) (RSA_size(rsa) - 41))
		{
			ERROR_MSG("Too much data supplied for RSA OAEP encryption");

			return false;
		}

		osslPadding = RSA_PKCS1_OAEP_PADDING;
	}
	else if (padding == AsymMech::RSA)
	{
		// The size of the input data should be exactly equal to the modulus length
		if (data.size() != (size_t) RSA_size(rsa))
		{
			ERROR_MSG("Incorrect amount of input data supplied for raw RSA encryption");

			return false;
		}

		osslPadding = RSA_NO_PADDING;
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);

		return false;
	}

	// Perform the RSA operation
	encryptedData.resize(RSA_size(rsa));

	if (RSA_public_encrypt(data.size(), (unsigned char*) data.const_byte_str(), &encryptedData[0], rsa, osslPadding) == -1)
	{
		ERROR_MSG("RSA public key encryption failed (0x%08X)", ERR_get_error());

		return false;
	}

	return true;
}

// Decryption functions
bool OSSLRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
		      ByteString& data, const AsymMech::Type padding)
{
	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	// Retrieve the OpenSSL key object
	RSA* rsa = ((OSSLRSAPrivateKey*) privateKey)->getOSSLKey();

	// Check the input size
	if (encryptedData.size() != (size_t) RSA_size(rsa))
	{
		ERROR_MSG("Invalid amount of input data supplied for RSA decryption");

		return false;
	}

	// Determine the OpenSSL padding algorithm
	int osslPadding = 0;

	switch (padding)
	{
		case AsymMech::RSA_PKCS:
			osslPadding = RSA_PKCS1_PADDING;
			break;
		case AsymMech::RSA_PKCS_OAEP:
			osslPadding = RSA_PKCS1_OAEP_PADDING;
			break;
		case AsymMech::RSA:
			osslPadding = RSA_NO_PADDING;
			break;
		default:
			ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);
			return false;
	}

	// Perform the RSA operation
	data.resize(RSA_size(rsa));

	int decSize = RSA_private_decrypt(encryptedData.size(), (unsigned char*) encryptedData.const_byte_str(), &data[0], rsa, osslPadding);

	if (decSize == -1)
	{
		ERROR_MSG("RSA private key decryption failed (0x%08X)", ERR_get_error());

		return false;
	}

	data.resize(decSize);

	return true;
}

// Key factory
bool OSSLRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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

	// Generate the key-pair
	RSA* rsa = RSA_new();
	if (rsa == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL RSA object");

		return false;
	}

	BIGNUM* bn_e = OSSL::byteString2bn(params->getE());

	// Check if the key was successfully generated
	if (!RSA_generate_key_ex(rsa, params->getBitLength(), bn_e, NULL))
	{
		ERROR_MSG("RSA key generation failed (0x%08X)", ERR_get_error());
		BN_free(bn_e);
		RSA_free(rsa);

		return false;
	}
	BN_free(bn_e);

	// Create an asymmetric key-pair object to return
	OSSLRSAKeyPair* kp = new OSSLRSAKeyPair();

	((OSSLRSAPublicKey*) kp->getPublicKey())->setFromOSSL(rsa);
	((OSSLRSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(rsa);

	*ppKeyPair = kp;

	// Release the key
	RSA_free(rsa);

	return true;
}

unsigned long OSSLRSA::getMinKeySize()
{
#ifdef WITH_FIPS
	// OPENSSL_RSA_FIPS_MIN_MODULUS_BITS is 1024
	return 1024;
#else
	return 512;
#endif
}

unsigned long OSSLRSA::getMaxKeySize()
{
	return OPENSSL_RSA_MAX_MODULUS_BITS;
}

bool OSSLRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLRSAKeyPair* kp = new OSSLRSAKeyPair();

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

bool OSSLRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLRSAPublicKey* pub = new OSSLRSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLRSAPrivateKey* priv = new OSSLRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLRSA::newPublicKey()
{
	return (PublicKey*) new OSSLRSAPublicKey();
}

PrivateKey* OSSLRSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLRSAPrivateKey();
}

AsymmetricParameters* OSSLRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

bool OSSLRSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
