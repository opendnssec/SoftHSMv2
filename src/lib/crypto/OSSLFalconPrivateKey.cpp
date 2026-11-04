/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalconPrivateKey.cpp

 OpenSSL Falcon private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_FALCON
#include "FalconParameters.h"
#include "log.h"
#include "OSSLFalconPrivateKey.h"
#include "OSSLFalconPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <cstring>
#include <utility>

OSSLFalconPrivateKey::OSSLFalconPrivateKey() : pkey(NULL)
{
}

OSSLFalconPrivateKey::OSSLFalconPrivateKey(const EVP_PKEY* inFalconKey) : pkey(NULL)
{
	setFromOSSL(inFalconKey);
}

OSSLFalconPrivateKey::~OSSLFalconPrivateKey()
{
	EVP_PKEY_free(pkey);
}

OSSLFalconPrivateKey::OSSLFalconPrivateKey(OSSLFalconPrivateKey&& other) noexcept
	: FalconPrivateKey(std::move(other)), pkey(other.pkey)
{
	other.pkey = NULL;
}

OSSLFalconPrivateKey& OSSLFalconPrivateKey::operator=(OSSLFalconPrivateKey&& other) noexcept
{
	if (this != &other)
	{
		FalconPrivateKey::operator=(std::move(other));
		EVP_PKEY_free(pkey);
		pkey = other.pkey;
		other.pkey = NULL;
	}
	return *this;
}

/*static*/ const char* OSSLFalconPrivateKey::type = "OpenSSL Falcon private key";

bool OSSLFalconPrivateKey::setFromOSSL(const EVP_PKEY* inFalconKey)
{
	if (inFalconKey == NULL) return false;

	size_t expectedPrivateLength = 0;
	size_t expectedPublicLength = 0;
	if (EVP_PKEY_is_a(inFalconKey, "falcon512"))
	{
		expectedPrivateLength = FalconParameters::FALCON_512_PRIV_LENGTH;
		expectedPublicLength = FalconParameters::FALCON_512_PUB_LENGTH;
	}
	else if (EVP_PKEY_is_a(inFalconKey, "falcon1024"))
	{
		expectedPrivateLength = FalconParameters::FALCON_1024_PRIV_LENGTH;
		expectedPublicLength = FalconParameters::FALCON_1024_PUB_LENGTH;
	}
	else
	{
		return false;
	}

	unsigned char privateKey[FalconParameters::FALCON_1024_PRIV_LENGTH];
	size_t privateKeyLength = 0;
	size_t publicKeyLength = 0;
	const bool privateOK = EVP_PKEY_get_octet_string_param(inFalconKey,
		OSSL_PKEY_PARAM_PRIV_KEY, privateKey, sizeof(privateKey),
		&privateKeyLength) > 0 && privateKeyLength == expectedPrivateLength;
	const bool publicOK = EVP_PKEY_get_octet_string_param(inFalconKey,
		OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
		&publicKeyLength) > 0 && publicKeyLength == expectedPublicLength;

	if (!privateOK)
	{
		ERROR_MSG("Could not get Falcon private key");
		OPENSSL_cleanse(privateKey, sizeof(privateKey));
		return false;
	}

	ByteString privateValue(privateKey, privateKeyLength);
	OPENSSL_cleanse(privateKey, sizeof(privateKey));
	ByteString info;
	if (publicOK)
	{
		const int length = i2d_PUBKEY(inFalconKey, NULL);
		if (length <= 0) return false;
		info.resize(length);
		unsigned char* output = info.byte_str();
		if (i2d_PUBKEY(inFalconKey, &output) != length) return false;
	}
	setValue(privateValue);
	setPublicKeyInfo(info);
	privateValue.wipe();
	return true;
}

bool OSSLFalconPrivateKey::isOfType(const char* inType)
{
	return inType != NULL &&
		(strcmp(type, inType) == 0 || FalconPrivateKey::isOfType(inType));
}

void OSSLFalconPrivateKey::invalidateOSSLKey()
{
	EVP_PKEY_free(pkey);
	pkey = NULL;
}

void OSSLFalconPrivateKey::setValue(const ByteString& inValue)
{
	FalconPrivateKey::setValue(inValue);
	invalidateOSSLKey();
}

void OSSLFalconPrivateKey::setPublicKeyInfo(const ByteString& inPublicKeyInfo)
{
	FalconPrivateKey::setPublicKeyInfo(inPublicKeyInfo);
	invalidateOSSLKey();
}

ByteString OSSLFalconPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;

	PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(key);
	if (p8 == NULL) return der;
	const int length = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
	if (length <= 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		return der;
	}

	der.resize(length);
	unsigned char* out = der.byte_str();
	const int written = i2d_PKCS8_PRIV_KEY_INFO(p8, &out);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (written != length) der.wipe();
	return der;
}

bool OSSLFalconPrivateKey::PKCS8Decode(const ByteString& ber)
{
	if (ber.size() == 0) return false;
	const unsigned char* in = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &in, ber.size());
	if (p8 == NULL) return false;

	EVP_PKEY* localPkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (localPkey == NULL) return false;
	const bool result = setFromOSSL(localPkey);
	EVP_PKEY_free(localPkey);
	return result;
}

EVP_PKEY* OSSLFalconPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();
	return pkey;
}

void OSSLFalconPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;
	const unsigned long parameterSet = getParameterSet();
	const char* name = OSSL::falconParameterSet2Name(parameterSet);
	if (name == NULL)
	{
		ERROR_MSG("Invalid Falcon private key length: %zu", getValue().size());
		return;
	}

	ByteString localValue = getValue();
	ByteString publicValue;
	if (getPublicKeyInfo().size() != 0)
	{
		const unsigned char* input = getPublicKeyInfo().const_byte_str();
		EVP_PKEY* publicPkey = d2i_PUBKEY(NULL, &input, getPublicKeyInfo().size());
		OSSLFalconPublicKey publicKey;
		publicKey.setFromOSSL(publicPkey);
		if (publicKey.getParameterSet() == parameterSet)
			publicValue = publicKey.getValue();
		EVP_PKEY_free(publicPkey);
	}

	OSSL_PARAM params[3];
	OSSL_PARAM* param = params;
	*param++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
		localValue.byte_str(), localValue.size());
	int selection = EVP_PKEY_PRIVATE_KEY;
	if (publicValue.size() != 0)
	{
		*param++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
			publicValue.byte_str(), publicValue.size());
		selection = EVP_PKEY_KEYPAIR;
	}
	*param = OSSL_PARAM_construct_end();

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
		EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0)
	{
		ERROR_MSG("Could not create Falcon private EVP_PKEY");
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	localValue.wipe();
}

#endif
