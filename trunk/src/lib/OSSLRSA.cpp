/* $Id$ */

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
#include "CryptoFactory.h"
#include "RSAParameters.h"
#include "OSSLRSAKeyPair.h"
#include <algorithm>
#include <openssl/rsa.h>
#include <openssl/err.h>

// Constructor
OSSLRSA::OSSLRSA()
{
	pCurrentHash = NULL;
	pSecondHash = NULL;
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
bool OSSLRSA::signInit(PrivateKey* privateKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism))
	{
		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("rsa-md5-pkcs"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("md5");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha256");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha512");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-ssl"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("md5");
		pSecondHash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		if (!pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
			
			delete pSecondHash;
			pSecondHash = NULL;
		}
	}

	if (pCurrentHash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
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
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	

	return true;
}

// Verification functions
bool OSSLRSA::verifyInit(PublicKey* publicKey, const std::string mechanism)
{
	return true;
}

bool OSSLRSA::verifyUpdate(const ByteString& originalData)
{
	return true;
}

bool OSSLRSA::verifyFinal(const ByteString& signature)
{
	return true;
}

// Encryption functions
bool OSSLRSA::encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const std::string padding)
{
	return true;
}

// Decryption functions
bool OSSLRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const std::string padding)
{
	return true;
}

// Key factory
bool OSSLRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, size_t keySize, void* parameters /* = NULL */, RNG* rng /* = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (keySize < 512) ||
	    (keySize > 16384) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (keySize < 1024)
	{
		WARNING_MSG("Using an RSA key size < 1024 bits is not recommended");
	}

	RSAParameters* params = (RSAParameters*) parameters;

	try
	{
		if (params->magic != RSA_PARAMETER_MAGIC)
		{
			return false;
		}
	}
	catch (...)
	{
		return false;
	}

	// Retrieve the desired public exponent
	unsigned long e = params->e.long_val();

	// Check the public exponent
	if ((e == 0) || (e % 2 != 1))
	{
		ERROR_MSG("Invalid RSA public exponent %d", e);

		return false;
	}

	// Generate the key-pair
	RSA* rsa = RSA_generate_key(keySize, e, NULL, NULL);

	// Check if the key was successfully generated
	if (rsa == NULL)
	{
		ERROR_MSG("RSA key generation failed: %s in %s in %s",
			  ERR_reason_error_string(ERR_get_error()),
			  ERR_func_error_string(ERR_get_error()),
			  ERR_lib_error_string(ERR_get_error()));

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLRSAKeyPair* kp = new OSSLRSAKeyPair();

	((OSSLRSAPublicKey*) kp->getPublicKey())->setFromOSSL(rsa);
	((OSSLRSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(rsa);

	*ppKeyPair = kp;

	// Release the key
	RSA_free(rsa);

	return true;
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


