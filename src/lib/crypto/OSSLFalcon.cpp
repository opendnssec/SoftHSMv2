/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalcon.cpp

 OpenSSL Falcon asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_FALCON
#include "FalconParameters.h"
#include "log.h"
#include "OSSLFalcon.h"
#include "OSSLFalconKeyPair.h"
#include "OSSLFalconPrivateKey.h"
#include "OSSLFalconPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/err.h>
#include <openssl/evp.h>

bool OSSLFalcon::sign(PrivateKey* privateKey, const ByteString& dataToSign,
	ByteString& signature, const AsymMech::Type mechanism,
	const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::FALCON)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (mechanismParam != NULL)
	{
		ERROR_MSG("Falcon signing does not accept mechanism parameters");
		return false;
	}
	if (privateKey == NULL)
	{
		ERROR_MSG("No private key supplied");
		return false;
	}
	if (!privateKey->isOfType(OSSLFalconPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLFalconPrivateKey* falconKey =
		static_cast<OSSLFalconPrivateKey*>(privateKey);
	EVP_PKEY* pkey = falconKey->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL Falcon private key");
		return false;
	}

	EVP_MD_CTX* context = EVP_MD_CTX_new();
	if (context == NULL)
	{
		ERROR_MSG("Falcon signing context allocation failed");
		return false;
	}
	if (EVP_DigestSignInit(context, NULL, NULL, NULL, pkey) <= 0)
	{
		ERROR_MSG("Falcon signing initialization failed (0x%08lX)",
			ERR_get_error());
		EVP_MD_CTX_free(context);
		return false;
	}

	size_t signatureLength = 0;
	if (EVP_DigestSign(context, NULL, &signatureLength,
		dataToSign.const_byte_str(), dataToSign.size()) <= 0 ||
		signatureLength == 0 ||
		signatureLength > falconKey->getOutputLength())
	{
		ERROR_MSG("Falcon signature size query failed (0x%08lX)",
			ERR_get_error());
		EVP_MD_CTX_free(context);
		return false;
	}

	signature.resize(signatureLength);
	if (EVP_DigestSign(context, signature.byte_str(), &signatureLength,
		dataToSign.const_byte_str(), dataToSign.size()) <= 0)
	{
		ERROR_MSG("Falcon signing failed (0x%08lX)", ERR_get_error());
		signature.resize(0);
		EVP_MD_CTX_free(context);
		return false;
	}
	signature.resize(signatureLength);
	EVP_MD_CTX_free(context);
	return true;
}

bool OSSLFalcon::signInit(PrivateKey* /*privateKey*/,
	const AsymMech::Type /*mechanism*/, const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("Falcon does not support multi part signing");
	return false;
}

bool OSSLFalcon::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("Falcon does not support multi part signing");
	return false;
}

bool OSSLFalcon::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("Falcon does not support multi part signing");
	return false;
}

bool OSSLFalcon::verify(PublicKey* publicKey, const ByteString& originalData,
	const ByteString& signature, const AsymMech::Type mechanism,
	const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::FALCON)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (mechanismParam != NULL)
	{
		ERROR_MSG("Falcon verification does not accept mechanism parameters");
		return false;
	}
	if (publicKey == NULL)
	{
		ERROR_MSG("No public key supplied");
		return false;
	}
	if (!publicKey->isOfType(OSSLFalconPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLFalconPublicKey* falconKey =
		static_cast<OSSLFalconPublicKey*>(publicKey);
	if (signature.size() == 0 ||
		signature.size() > falconKey->getOutputLength())
	{
		ERROR_MSG("Invalid Falcon signature length");
		return false;
	}

	EVP_PKEY* pkey = falconKey->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL Falcon public key");
		return false;
	}

	EVP_MD_CTX* context = EVP_MD_CTX_new();
	if (context == NULL)
	{
		ERROR_MSG("Falcon verification context allocation failed");
		return false;
	}
	if (EVP_DigestVerifyInit(context, NULL, NULL, NULL, pkey) <= 0)
	{
		ERROR_MSG("Falcon verification initialization failed (0x%08lX)",
			ERR_get_error());
		EVP_MD_CTX_free(context);
		return false;
	}

	const int result = EVP_DigestVerify(context, signature.const_byte_str(),
		signature.size(), originalData.const_byte_str(), originalData.size());
	if (result < 0)
	{
		ERROR_MSG("Falcon verification failed (0x%08lX)", ERR_get_error());
	}
	EVP_MD_CTX_free(context);
	return result == 1;
}

bool OSSLFalcon::verifyInit(PublicKey* /*publicKey*/,
	const AsymMech::Type /*mechanism*/, const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("Falcon does not support multi part verifying");
	return false;
}

bool OSSLFalcon::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("Falcon does not support multi part verifying");
	return false;
}

bool OSSLFalcon::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("Falcon does not support multi part verifying");
	return false;
}

bool OSSLFalcon::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
	ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
	const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("Falcon does not support encryption");
	return false;
}

bool OSSLFalcon::decrypt(PrivateKey* /*privateKey*/,
	const ByteString& /*encryptedData*/, ByteString& /*data*/,
	const AsymMech::Type /*padding*/, const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("Falcon does not support decryption");
	return false;
}

unsigned long OSSLFalcon::getMinKeySize()
{
	return FalconParameters::FALCON_512_PUB_LENGTH;
}

unsigned long OSSLFalcon::getMaxKeySize()
{
	return FalconParameters::FALCON_1024_PUB_LENGTH;
}

bool OSSLFalcon::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
	AsymmetricParameters* inParameters, RNG* /*rng*/)
{
	if (ppKeyPair == NULL || inParameters == NULL) return false;
	if (!inParameters->areOfType(FalconParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for Falcon key generation");
		return false;
	}

	FalconParameters* parameters = static_cast<FalconParameters*>(inParameters);
	const unsigned long parameterSet = parameters->getParameterSet();
	const char* name = OSSL::falconParameterSet2Name(parameterSet);
	if (name == NULL)
	{
		ERROR_MSG("Unknown Falcon parameter set (%lu)", parameterSet);
		return false;
	}

	EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	EVP_PKEY* generatedKey = NULL;
	if (context == NULL)
	{
		ERROR_MSG("Falcon key generation context failed (0x%08lX)", ERR_get_error());
		return false;
	}
	if (EVP_PKEY_keygen_init(context) <= 0 ||
		EVP_PKEY_generate(context, &generatedKey) <= 0)
	{
		ERROR_MSG("Falcon key generation failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_free(generatedKey);
		EVP_PKEY_CTX_free(context);
		return false;
	}

	OSSLFalconKeyPair* keyPair = new OSSLFalconKeyPair();
	OSSLFalconPrivateKey* privateKey =
		static_cast<OSSLFalconPrivateKey*>(keyPair->getPrivateKey());
	OSSLFalconPublicKey* publicKey =
		static_cast<OSSLFalconPublicKey*>(keyPair->getPublicKey());
	publicKey->setFromOSSL(generatedKey);
	if (!privateKey->setFromOSSL(generatedKey) ||
		publicKey->getValue().size() == 0)
	{
		delete keyPair;
		EVP_PKEY_free(generatedKey);
		EVP_PKEY_CTX_free(context);
		return false;
	}

	*ppKeyPair = keyPair;
	EVP_PKEY_free(generatedKey);
	EVP_PKEY_CTX_free(context);
	return true;
}

bool OSSLFalcon::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair,
	ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString publicData = ByteString::chainDeserialise(serialisedData);
	ByteString privateData = ByteString::chainDeserialise(serialisedData);
	OSSLFalconKeyPair* keyPair = new OSSLFalconKeyPair();
	OSSLFalconPublicKey* publicKey =
		static_cast<OSSLFalconPublicKey*>(keyPair->getPublicKey());
	OSSLFalconPrivateKey* privateKey =
		static_cast<OSSLFalconPrivateKey*>(keyPair->getPrivateKey());

	if (!publicKey->deserialise(publicData) ||
		!privateKey->deserialise(privateData))
	{
		delete keyPair;
		return false;
	}
	*ppKeyPair = keyPair;
	return true;
}

bool OSSLFalcon::reconstructPublicKey(PublicKey** ppPublicKey,
	ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;

	OSSLFalconPublicKey* publicKey = new OSSLFalconPublicKey();
	if (!publicKey->deserialise(serialisedData))
	{
		delete publicKey;
		return false;
	}
	*ppPublicKey = publicKey;
	return true;
}

bool OSSLFalcon::reconstructPrivateKey(PrivateKey** ppPrivateKey,
	ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;

	OSSLFalconPrivateKey* privateKey = new OSSLFalconPrivateKey();
	if (!privateKey->deserialise(serialisedData))
	{
		delete privateKey;
		return false;
	}
	*ppPrivateKey = privateKey;
	return true;
}

bool OSSLFalcon::reconstructParameters(AsymmetricParameters** ppParams,
	ByteString& serialisedData)
{
	if (ppParams == NULL || serialisedData.size() == 0) return false;

	FalconParameters* parameters = new FalconParameters();
	if (!parameters->deserialise(serialisedData))
	{
		delete parameters;
		return false;
	}
	*ppParams = parameters;
	return true;
}

PublicKey* OSSLFalcon::newPublicKey()
{
	return new OSSLFalconPublicKey();
}

PrivateKey* OSSLFalcon::newPrivateKey()
{
	return new OSSLFalconPrivateKey();
}

AsymmetricParameters* OSSLFalcon::newParameters()
{
	return new FalconParameters();
}

#endif
