/* $Id$ */

/*
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
 OSSLDSA.cpp

 OpenSSL DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDSA.h"
#include "CryptoFactory.h"
#include "DSAParameters.h"
#include "OSSLDSAKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Constructor
OSSLDSA::OSSLDSA()
{
	pCurrentHash = NULL;
}

// Destructor
OSSLDSA::~OSSLDSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}
}
	
// Signing functions
bool OSSLDSA::signInit(PrivateKey* privateKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa-sha1"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
#ifdef DSA_SHA256_SUPPORT
	else if (!lowerMechanism.compare("dsa-sha256"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha256");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
#endif // DSA_SHA256_SUPPORT
#ifdef DSA_SHA512_SUPPORT
	else if (!lowerMechanism.compare("dsa-sha512"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha512");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
#endif // DSA_SHA512_SUPPORT

	if (pCurrentHash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::signUpdate(const ByteString& dataToSign)
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

	return true;
}

bool OSSLDSA::signFinal(ByteString& signature)
{	
	// Save necessary state before calling super class signFinal
	OSSLDSAPrivateKey* pk = (OSSLDSAPrivateKey*) currentPrivateKey;

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bFirstResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bFirstResult)
	{
		return false;
	}
	
	DSA* dsa = pk->getOSSLKey();

	// Resize the data block for the signature to the modulus size of the key
	signature.resize(DSA_size(dsa));

	// Perform the signature operation
	unsigned int sigLen = signature.size();

	bool rv = (DSA_sign(0, &hash[0], hash.size(), &signature[0], &sigLen, dsa) == 1);

	signature.resize(sigLen);

	return rv;
}

// Verification functions
bool OSSLDSA::verifyInit(PublicKey* publicKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa-sha1"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
#ifdef DSA_SHA256_SUPPORT
	else if (!lowerMechanism.compare("dsa-sha256"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha256");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
#endif // DSA_SHA256_SUPPORT
#ifdef DSA_SHA512_SUPPORT
	else if (!lowerMechanism.compare("dsa-sha512"))
	{
		pCurrentHash = CryptoFactory::i()->getHashAlgorithm("sha512");

		if (!pCurrentHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}
	}
#endif // DSA_SHA512_SUPPORT
	
	if (pCurrentHash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::verifyUpdate(const ByteString& originalData)
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

	return true;
}

bool OSSLDSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	OSSLDSAPublicKey* pk = (OSSLDSAPublicKey*) currentPublicKey;

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bFirstResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bFirstResult)
	{
		return false;
	}

	// Perform the verify operation
	bool rv = (DSA_verify(0, &hash[0], hash.size(), (unsigned char*) signature.const_byte_str(), signature.size(), pk->getOSSLKey()) == 1);

	if (!rv) ERROR_MSG("DSA verify failed (0x%08X)", ERR_get_error());

	return rv;
}

// Encryption functions
bool OSSLDSA::encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const std::string padding)
{
	ERROR_MSG("DSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLDSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const std::string padding)
{
	ERROR_MSG("DSA does not support decryption");

	return false;
}

// Key factory
bool OSSLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng /* = NULL */)
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
	DSA* dsa = DSA_new();

	if (dsa == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL DSA object");

		return false;
	}

	dsa->p = OSSL::byteString2bn(params->getP());
	dsa->q = OSSL::byteString2bn(params->getQ());
	dsa->g = OSSL::byteString2bn(params->getG());

	if (DSA_generate_key(dsa) != 1)
	{
		ERROR_MSG("DSA key generation failed (0x%08X)", ERR_get_error());

		DSA_free(dsa);

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLDSAKeyPair* kp = new OSSLDSAKeyPair();

	((OSSLDSAPublicKey*) kp->getPublicKey())->setFromOSSL(dsa);
	((OSSLDSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(dsa);

	*ppKeyPair = kp;

	// Release the key
	DSA_free(dsa);

	return true;
}

bool OSSLDSA::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* rng /* = NULL*/)
{
	if ((ppParams == NULL) || (parameters == NULL))
	{
		return false;
	}

	size_t bitLen = (size_t) parameters;

	DSA* dsa = DSA_generate_parameters(bitLen, NULL, 0, NULL, NULL, NULL, NULL);

	if (dsa == NULL)
	{
		ERROR_MSG("Failed to generate %d bit DSA parameters", bitLen);

		return false;
	}

	// Store the DSA parameters
	DSAParameters* params = new DSAParameters();

	ByteString p = OSSL::bn2ByteString(dsa->p); params->setP(p);
	ByteString q = OSSL::bn2ByteString(dsa->q); params->setQ(q);
	ByteString g = OSSL::bn2ByteString(dsa->g); params->setG(g);

	*ppParams = params;

	DSA_free(dsa);

	return true;
}

bool OSSLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLDSAKeyPair* kp = new OSSLDSAKeyPair();

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

bool OSSLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDSAPublicKey* pub = new OSSLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDSAPrivateKey* priv = new OSSLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLDSA::newPublicKey()
{
	return (PublicKey*) new OSSLDSAPublicKey();
}

PrivateKey* OSSLDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLDSAPrivateKey();
}
	
AsymmetricParameters* OSSLDSA::newParameters()
{
	return (AsymmetricParameters*) new DSAParameters();
}

bool OSSLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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

