/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWing.cpp

 OpenSSL X-Wing asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "AESKey.h"
#include "CryptoFactory.h"
#include "log.h"
#include "OSSLXWing.h"
#include "OSSLXWingKeyPair.h"
#include "OSSLXWingPrivateKey.h"
#include "XWingParameters.h"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

namespace
{
const unsigned char X_WING_LABEL[] = {
	0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c
};
}

bool OSSLXWing::encapsulateMLKEM(EVP_PKEY* mlkemPkey,
	ByteString& cipherText, ByteString& sharedSecret, const ByteString& seed)
{
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
			const_cast<unsigned char*>(seed.const_byte_str()), seed.size()),
		OSSL_PARAM_construct_end()
	};
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, mlkemPkey, NULL);
	size_t cipherTextLen = 0;
	size_t sharedSecretLen = 0;
	bool rv = ctx != NULL &&
		EVP_PKEY_encapsulate_init(ctx, seed.size() == 0 ? NULL : params) > 0 &&
		EVP_PKEY_encapsulate(ctx, NULL, &cipherTextLen, NULL,
		                     &sharedSecretLen) > 0 &&
		cipherTextLen == XWingParameters::ML_KEM_768_CIPHERTEXT_LENGTH &&
		sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;

	if (rv)
	{
		cipherText.resize(cipherTextLen);
		sharedSecret.resize(sharedSecretLen);
		rv = EVP_PKEY_encapsulate(ctx, cipherText.byte_str(), &cipherTextLen,
		                          sharedSecret.byte_str(), &sharedSecretLen) > 0 &&
			cipherTextLen == XWingParameters::ML_KEM_768_CIPHERTEXT_LENGTH &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;
	}

	EVP_PKEY_CTX_free(ctx);
	if (!rv)
	{
		ERROR_MSG("Could not encapsulate the X-Wing ML-KEM-768 component "
		          "(0x%08lX)", ERR_get_error());
		cipherText.wipe();
		sharedSecret.wipe();
	}
	return rv;
}

bool OSSLXWing::encapsulateX25519(EVP_PKEY* x25519Pkey,
	ByteString& cipherText, ByteString& sharedSecret, const ByteString& seed)
{
	ByteString ephemeralPrivateKey = seed;
	EVP_PKEY* ephemeralPkey = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	size_t cipherTextLen = XWingParameters::X25519_PUB_LENGTH;
	size_t sharedSecretLen = 0;
	static const unsigned char zero[
		XWingParameters::X_WING_SHARED_SECRET_LENGTH] = { 0 };

	bool rv = seed.size() == XWingParameters::X25519_PRIV_LENGTH;
	if (seed.size() == 0)
	{
		RNG* rng = CryptoFactory::i()->getRNG();
		rv = rng != NULL &&
			rng->generateRandom(ephemeralPrivateKey,
			                    XWingParameters::X25519_PRIV_LENGTH);
	}
	if (rv)
	{
		ephemeralPkey = EVP_PKEY_new_raw_private_key_ex(
			NULL, "X25519", NULL, ephemeralPrivateKey.const_byte_str(),
			ephemeralPrivateKey.size());
		rv = ephemeralPkey != NULL;
	}
	if (rv)
	{
		cipherText.resize(cipherTextLen);
		rv = EVP_PKEY_get_raw_public_key(ephemeralPkey, cipherText.byte_str(),
		                                 &cipherTextLen) > 0 &&
			cipherTextLen == XWingParameters::X25519_PUB_LENGTH;
	}
	if (rv)
	{
		ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ephemeralPkey, NULL);
		rv = ctx != NULL && EVP_PKEY_derive_init(ctx) > 0 &&
			EVP_PKEY_derive_set_peer(ctx, x25519Pkey) > 0 &&
			EVP_PKEY_derive(ctx, NULL, &sharedSecretLen) > 0 &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;
	}
	if (rv)
	{
		sharedSecret.resize(sharedSecretLen);
		rv = EVP_PKEY_derive(ctx, sharedSecret.byte_str(),
		                     &sharedSecretLen) > 0 &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH &&
			CRYPTO_memcmp(sharedSecret.const_byte_str(), zero,
			              sizeof(zero)) != 0;
	}

	ephemeralPrivateKey.wipe();
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(ephemeralPkey);
	if (!rv)
	{
		ERROR_MSG("Could not encapsulate the X-Wing X25519 component "
		          "(0x%08lX)", ERR_get_error());
		cipherText.wipe();
		sharedSecret.wipe();
	}
	return rv;
}

bool OSSLXWing::encapsulateComponents(EVP_PKEY* mlkemPkey,
	EVP_PKEY* x25519Pkey, ByteString& mlkemCipherText,
	ByteString& mlkemSharedSecret, ByteString& x25519CipherText,
	ByteString& x25519SharedSecret, const ByteString& seed)
{
	mlkemCipherText.wipe();
	mlkemSharedSecret.wipe();
	x25519CipherText.wipe();
	x25519SharedSecret.wipe();
	if (mlkemPkey == NULL || x25519Pkey == NULL) return false;

	const size_t seedLen = XWingParameters::X_WING_ENCAPSULATION_SEED_LENGTH / 2;
	if (encapsulateX25519(x25519Pkey, x25519CipherText,
	                    x25519SharedSecret, seed.substr(seedLen)) &&
		encapsulateMLKEM(mlkemPkey, mlkemCipherText,
		                 mlkemSharedSecret, seed.substr(0, seedLen)))
	{
		return true;
	}

	mlkemCipherText.wipe();
	mlkemSharedSecret.wipe();
	x25519CipherText.wipe();
	x25519SharedSecret.wipe();
	return false;
}

bool OSSLXWing::decapsulateMLKEM(EVP_PKEY* mlkemPkey,
	const ByteString& cipherText, ByteString& sharedSecret)
{
	sharedSecret.wipe();
	if (mlkemPkey == NULL ||
		cipherText.size() !=
			XWingParameters::ML_KEM_768_CIPHERTEXT_LENGTH)
	{
		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, mlkemPkey, NULL);
	size_t sharedSecretLen = 0;
	bool rv = ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) > 0 &&
		EVP_PKEY_decapsulate(ctx, NULL, &sharedSecretLen,
		                     cipherText.const_byte_str(),
		                     cipherText.size()) > 0 &&
		sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;

	if (rv)
	{
		sharedSecret.resize(sharedSecretLen);
		rv = EVP_PKEY_decapsulate(ctx, sharedSecret.byte_str(),
		                          &sharedSecretLen,
		                          cipherText.const_byte_str(),
		                          cipherText.size()) > 0 &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;
	}

	EVP_PKEY_CTX_free(ctx);
	if (!rv)
	{
		ERROR_MSG("Could not decapsulate the X-Wing ML-KEM-768 component "
		          "(0x%08lX)", ERR_get_error());
		sharedSecret.wipe();
	}
	return rv;
}

bool OSSLXWing::decapsulateX25519(EVP_PKEY* x25519Pkey,
	const ByteString& cipherText, ByteString& sharedSecret)
{
	sharedSecret.wipe();
	if (x25519Pkey == NULL ||
		cipherText.size() != XWingParameters::X25519_PUB_LENGTH)
	{
		return false;
	}

	EVP_PKEY* peerPkey = EVP_PKEY_new_raw_public_key_ex(
		NULL, "X25519", NULL, cipherText.const_byte_str(), cipherText.size());
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, x25519Pkey, NULL);
	size_t sharedSecretLen = 0;
	static const unsigned char zero[
		XWingParameters::X_WING_SHARED_SECRET_LENGTH] = { 0 };
	bool rv = peerPkey != NULL && ctx != NULL &&
		EVP_PKEY_derive_init(ctx) > 0 &&
		EVP_PKEY_derive_set_peer(ctx, peerPkey) > 0 &&
		EVP_PKEY_derive(ctx, NULL, &sharedSecretLen) > 0 &&
		sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;

	if (rv)
	{
		sharedSecret.resize(sharedSecretLen);
		rv = EVP_PKEY_derive(ctx, sharedSecret.byte_str(),
		                     &sharedSecretLen) > 0 &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH &&
			CRYPTO_memcmp(sharedSecret.const_byte_str(), zero,
			              sizeof(zero)) != 0;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerPkey);
	if (!rv)
	{
		ERROR_MSG("Could not decapsulate the X-Wing X25519 component "
		          "(0x%08lX)", ERR_get_error());
		sharedSecret.wipe();
	}
	return rv;
}

bool OSSLXWing::combineSharedSecrets(const ByteString& mlkemSharedSecret,
	const ByteString& x25519SharedSecret,
	const ByteString& x25519CipherText,
	const ByteString& x25519PublicKey, ByteString& sharedSecret)
{
	sharedSecret.wipe();
	EVP_MD* sha3 = EVP_MD_fetch(NULL, "SHA3-256", NULL);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	unsigned int sharedSecretLen = 0;
	sharedSecret.resize(XWingParameters::X_WING_SHARED_SECRET_LENGTH);
	const bool rv = sha3 != NULL && ctx != NULL &&
		EVP_DigestInit_ex(ctx, sha3, NULL) > 0 &&
		EVP_DigestUpdate(ctx, mlkemSharedSecret.const_byte_str(),
		                 mlkemSharedSecret.size()) > 0 &&
		EVP_DigestUpdate(ctx, x25519SharedSecret.const_byte_str(),
		                 x25519SharedSecret.size()) > 0 &&
		EVP_DigestUpdate(ctx, x25519CipherText.const_byte_str(),
		                 x25519CipherText.size()) > 0 &&
		EVP_DigestUpdate(ctx, x25519PublicKey.const_byte_str(),
		                 x25519PublicKey.size()) > 0 &&
		EVP_DigestUpdate(ctx, X_WING_LABEL, sizeof(X_WING_LABEL)) > 0 &&
		EVP_DigestFinal_ex(ctx, sharedSecret.byte_str(),
		                   &sharedSecretLen) > 0 &&
		sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(sha3);

	if (!rv)
	{
		ERROR_MSG("Could not combine the X-Wing shared secrets "
		          "(0x%08lX)", ERR_get_error());
		sharedSecret.wipe();
	}
	return rv;
}

bool OSSLXWing::encapsulate(PublicKey* publicKey, ByteString& cipherText,
	SymmetricKey** secretKey, CK_KEY_TYPE keyType,
	const AsymMech::Type mechanism)
{
	return encapsulate(publicKey, cipherText, secretKey, keyType,
	                   mechanism, ByteString());
}

bool OSSLXWing::encapsulate(PublicKey* publicKey, ByteString& cipherText,
	SymmetricKey** secretKey, CK_KEY_TYPE keyType,
	const AsymMech::Type /*mechanism*/, const ByteString& seed)
{
	cipherText.wipe();
	if (secretKey == NULL)
	{
		ERROR_MSG("Invalid X-Wing secret key output");
		return false;
	}
	*secretKey = NULL;
	if (seed.size() != 0 &&
		seed.size() != XWingParameters::X_WING_ENCAPSULATION_SEED_LENGTH)
	{
		ERROR_MSG("Invalid X-Wing encapsulation seed length");
		return false;
	}
	if (publicKey == NULL ||
		!publicKey->isOfType(OSSLXWingPublicKey::type))
	{
		ERROR_MSG("Invalid X-Wing public key input");
		return false;
	}

	OSSLXWingPublicKey* xwingPublicKey =
		static_cast<OSSLXWingPublicKey*>(publicKey);
	EVP_PKEY* mlkemPkey = xwingPublicKey->getOSSLMLKEMKey();
	EVP_PKEY* x25519Pkey = xwingPublicKey->getOSSLX25519Key();
	if (mlkemPkey == NULL || x25519Pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL X-Wing public key components");
		return false;
	}

	ByteString mlkemCipherText;
	ByteString mlkemSharedSecret;
	ByteString x25519CipherText;
	ByteString x25519SharedSecret;
	ByteString sharedSecret;
	const ByteString x25519PublicKey = xwingPublicKey->getX25519Value();
	bool rv = encapsulateComponents(mlkemPkey, x25519Pkey,
	                                mlkemCipherText, mlkemSharedSecret,
	                                x25519CipherText, x25519SharedSecret,
	                                seed) &&
		combineSharedSecrets(mlkemSharedSecret, x25519SharedSecret,
		                     x25519CipherText, x25519PublicKey,
		                     sharedSecret);

	if (rv)
		cipherText = mlkemCipherText + x25519CipherText;

	SymmetricKey* outputKey = NULL;
	if (rv)
	{
		const size_t bitLength =
			XWingParameters::X_WING_SHARED_SECRET_LENGTH * 8;
		if (keyType == CKK_AES)
			outputKey = new AESKey(bitLength);
		else
			outputKey = new SymmetricKey(bitLength);
		rv = outputKey->setKeyBits(sharedSecret);
	}

	mlkemCipherText.wipe();
	mlkemSharedSecret.wipe();
	x25519CipherText.wipe();
	x25519SharedSecret.wipe();
	sharedSecret.wipe();
	if (!rv)
	{
		delete outputKey;
		cipherText.wipe();
		return false;
	}

	*secretKey = outputKey;
	return true;
}

bool OSSLXWing::decapsulate(PrivateKey* privateKey,
	const ByteString& cipherText, SymmetricKey** secretKey,
	CK_KEY_TYPE keyType, const AsymMech::Type /*mechanism*/)
{
	if (secretKey == NULL)
	{
		ERROR_MSG("Invalid X-Wing secret key output");
		return false;
	}
	*secretKey = NULL;
	if (privateKey == NULL ||
		!privateKey->isOfType(OSSLXWingPrivateKey::type))
	{
		ERROR_MSG("Invalid X-Wing private key input");
		return false;
	}
	if (cipherText.size() != XWingParameters::X_WING_CIPHERTEXT_LENGTH)
	{
		ERROR_MSG("Invalid X-Wing ciphertext length");
		return false;
	}

	OSSLXWingPrivateKey* xwingPrivateKey =
		static_cast<OSSLXWingPrivateKey*>(privateKey);
	EVP_PKEY* mlkemPkey = xwingPrivateKey->getOSSLMLKEMKey();
	EVP_PKEY* x25519Pkey = xwingPrivateKey->getOSSLX25519Key();
	if (mlkemPkey == NULL || x25519Pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL X-Wing private key components");
		return false;
	}

	ByteString x25519PublicKey;
	x25519PublicKey.resize(XWingParameters::X25519_PUB_LENGTH);
	size_t publicKeyLength = x25519PublicKey.size();
	if (EVP_PKEY_get_raw_public_key(x25519Pkey, x25519PublicKey.byte_str(),
		&publicKeyLength) <= 0 || publicKeyLength != x25519PublicKey.size())
	{
		ERROR_MSG("Could not get the X25519 public key for X-Wing decapsulation");
		return false;
	}
	const ByteString mlkemCipherText = cipherText.substr(
		0, XWingParameters::ML_KEM_768_CIPHERTEXT_LENGTH);
	const ByteString x25519CipherText = cipherText.substr(
		XWingParameters::ML_KEM_768_CIPHERTEXT_LENGTH,
		XWingParameters::X25519_PUB_LENGTH);
	ByteString mlkemSharedSecret;
	ByteString x25519SharedSecret;
	ByteString sharedSecret;
	bool rv = decapsulateMLKEM(mlkemPkey, mlkemCipherText,
	                          mlkemSharedSecret) &&
		decapsulateX25519(x25519Pkey, x25519CipherText,
		                   x25519SharedSecret) &&
		combineSharedSecrets(mlkemSharedSecret, x25519SharedSecret,
		                     x25519CipherText, x25519PublicKey,
		                     sharedSecret);

	SymmetricKey* outputKey = NULL;
	if (rv)
	{
		const size_t bitLength =
			XWingParameters::X_WING_SHARED_SECRET_LENGTH * 8;
		if (keyType == CKK_AES)
			outputKey = new AESKey(bitLength);
		else
			outputKey = new SymmetricKey(bitLength);
		rv = outputKey->setKeyBits(sharedSecret);
	}

	mlkemSharedSecret.wipe();
	x25519SharedSecret.wipe();
	sharedSecret.wipe();
	if (!rv)
	{
		delete outputKey;
		return false;
	}

	*secretKey = outputKey;
	return true;
}

bool OSSLXWing::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
	ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
	const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("X-Wing does not support encryption");
	return false;
}

bool OSSLXWing::decrypt(PrivateKey* /*privateKey*/,
	const ByteString& /*encryptedData*/, ByteString& /*data*/,
	const AsymMech::Type /*padding*/, const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("X-Wing does not support decryption");
	return false;
}

bool OSSLXWing::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
	AsymmetricParameters* parameters, RNG* rng)
{
	if (ppKeyPair == NULL || parameters == NULL ||
		!parameters->areOfType(XWingParameters::type))
	{
		return false;
	}
	if (rng == NULL) rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return false;

	ByteString seed;
	if (!rng->generateRandom(seed, XWingParameters::X_WING_PRIV_LENGTH))
		return false;

	OSSLXWingKeyPair* kp = new OSSLXWingKeyPair();
	OSSLXWingPrivateKey* privateKey =
		static_cast<OSSLXWingPrivateKey*>(kp->getPrivateKey());
	privateKey->setValue(seed);
	OSSLXWingPublicKey* publicKey =
		static_cast<OSSLXWingPublicKey*>(kp->getPublicKey());
	publicKey->setFromOSSL(privateKey->getOSSLMLKEMKey(),
		privateKey->getOSSLX25519Key());
	seed.wipe();
	if (publicKey->getValue().size() == 0)
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;
	return true;
}

unsigned long OSSLXWing::getMinKeySize()
{
	return XWingParameters::X_WING_PRIV_LENGTH;
}

unsigned long OSSLXWing::getMaxKeySize()
{
	return XWingParameters::X_WING_PRIV_LENGTH;
}

bool OSSLXWing::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair,
	ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);
	OSSLXWingKeyPair* kp = new OSSLXWingKeyPair();
	if (!static_cast<XWingPublicKey*>(kp->getPublicKey())->deserialise(dPub) ||
		!static_cast<XWingPrivateKey*>(kp->getPrivateKey())->deserialise(dPriv))
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;
	return true;
}

bool OSSLXWing::reconstructPublicKey(PublicKey** ppPublicKey,
	ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLXWingPublicKey* publicKey = new OSSLXWingPublicKey();
	if (!publicKey->deserialise(serialisedData))
	{
		delete publicKey;
		return false;
	}
	*ppPublicKey = publicKey;
	return true;
}

bool OSSLXWing::reconstructPrivateKey(PrivateKey** ppPrivateKey,
	ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLXWingPrivateKey* privateKey = new OSSLXWingPrivateKey();
	if (!privateKey->deserialise(serialisedData))
	{
		delete privateKey;
		return false;
	}
	*ppPrivateKey = privateKey;
	return true;
}

bool OSSLXWing::reconstructParameters(AsymmetricParameters** ppParams,
	ByteString& serialisedData)
{
	if (ppParams == NULL) return false;
	XWingParameters* parameters = new XWingParameters();
	if (!parameters->deserialise(serialisedData))
	{
		delete parameters;
		return false;
	}
	*ppParams = parameters;
	return true;
}

PublicKey* OSSLXWing::newPublicKey()
{
	return new OSSLXWingPublicKey();
}

PrivateKey* OSSLXWing::newPrivateKey()
{
	return new OSSLXWingPrivateKey();
}

AsymmetricParameters* OSSLXWing::newParameters()
{
	return new XWingParameters();
}

#endif
