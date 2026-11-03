/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPublicKey.cpp

 OpenSSL X-Wing public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "log.h"
#include "OSSLXWingPublicKey.h"
#include "XWingParameters.h"
#include <openssl/core_names.h>
#include <string.h>
#include <utility>

namespace
{
bool importMLKEMPublicKey(const ByteString& value, EVP_PKEY** pkey)
{
	EVP_PKEY_CTX* ctx =
		EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
		                                  const_cast<unsigned char*>(
		                                      value.const_byte_str()),
		                                  value.size()),
		OSSL_PARAM_construct_end()
	};
	const bool rv = ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0 &&
		EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;
	EVP_PKEY_CTX_free(ctx);
	return rv;
}

bool importPublicKeyComponents(const ByteString& mlkemValue,
	const ByteString& x25519Value, EVP_PKEY** mlkemPkey,
	EVP_PKEY** x25519Pkey)
{
	if (mlkemPkey == NULL || x25519Pkey == NULL ||
		mlkemValue.size() != XWingParameters::ML_KEM_768_PUB_LENGTH ||
		x25519Value.size() != XWingParameters::X25519_PUB_LENGTH)
	{
		return false;
	}

	*mlkemPkey = NULL;
	*x25519Pkey = NULL;
	bool rv = importMLKEMPublicKey(mlkemValue, mlkemPkey);
	if (rv)
	{
		*x25519Pkey = EVP_PKEY_new_raw_public_key_ex(
			NULL, "X25519", NULL, x25519Value.const_byte_str(),
			x25519Value.size());
		rv = *x25519Pkey != NULL;
	}
	if (!rv)
	{
		ERROR_MSG("Could not import X-Wing public key components");
		EVP_PKEY_free(*mlkemPkey);
		EVP_PKEY_free(*x25519Pkey);
		*mlkemPkey = NULL;
		*x25519Pkey = NULL;
	}
	return rv;
}
}

OSSLXWingPublicKey::OSSLXWingPublicKey() : mlkemPkey(NULL), x25519Pkey(NULL)
{
}

OSSLXWingPublicKey::~OSSLXWingPublicKey()
{
	resetOSSLKeys();
}

OSSLXWingPublicKey::OSSLXWingPublicKey(OSSLXWingPublicKey&& other) noexcept
	: XWingPublicKey(std::move(other)), mlkemPkey(other.mlkemPkey),
	  x25519Pkey(other.x25519Pkey)
{
	other.mlkemPkey = NULL;
	other.x25519Pkey = NULL;
}

OSSLXWingPublicKey& OSSLXWingPublicKey::operator=(OSSLXWingPublicKey&& other) noexcept
{
	if (this != &other)
	{
		XWingPublicKey::operator=(std::move(other));
		resetOSSLKeys();
		mlkemPkey = other.mlkemPkey;
		x25519Pkey = other.x25519Pkey;
		other.mlkemPkey = NULL;
		other.x25519Pkey = NULL;
	}
	return *this;
}

/*static*/ const char* OSSLXWingPublicKey::type = "OpenSSL X-Wing Public Key";

bool OSSLXWingPublicKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType) || XWingPublicKey::isOfType(inType);
}

void OSSLXWingPublicKey::resetOSSLKeys()
{
	EVP_PKEY_free(mlkemPkey);
	EVP_PKEY_free(x25519Pkey);
	mlkemPkey = NULL;
	x25519Pkey = NULL;
}

void OSSLXWingPublicKey::setValue(const ByteString& inValue)
{
	XWingPublicKey::setValue(inValue);
	resetOSSLKeys();
}

void OSSLXWingPublicKey::setFromOSSL(const EVP_PKEY* mlkemKey,
	const EVP_PKEY* x25519Key)
{
	unsigned char mlkemPub[XWingParameters::ML_KEM_768_PUB_LENGTH];
	unsigned char x25519Pub[XWingParameters::X25519_PUB_LENGTH];
	size_t mlkemPubLen = sizeof(mlkemPub);
	size_t x25519PubLen = sizeof(x25519Pub);
	if (mlkemKey == NULL || x25519Key == NULL ||
		EVP_PKEY_get_octet_string_param(mlkemKey, OSSL_PKEY_PARAM_PUB_KEY,
			mlkemPub, sizeof(mlkemPub), &mlkemPubLen) <= 0 ||
		mlkemPubLen != sizeof(mlkemPub) ||
		EVP_PKEY_get_raw_public_key(x25519Key, x25519Pub, &x25519PubLen) <= 0 ||
		x25519PubLen != sizeof(x25519Pub))
	{
		ERROR_MSG("Could not get X-Wing public key components");
		return;
	}
	setValue(ByteString(mlkemPub, mlkemPubLen) +
		ByteString(x25519Pub, x25519PubLen));
}

void OSSLXWingPublicKey::createOSSLKeys()
{
	if (mlkemPkey != NULL && x25519Pkey != NULL) return;
	resetOSSLKeys();
	importPublicKeyComponents(getMLKEMValue(), getX25519Value(),
	                          &mlkemPkey, &x25519Pkey);
}

EVP_PKEY* OSSLXWingPublicKey::getOSSLMLKEMKey()
{
	if (mlkemPkey == NULL) createOSSLKeys();
	return mlkemPkey;
}

EVP_PKEY* OSSLXWingPublicKey::getOSSLX25519Key()
{
	if (x25519Pkey == NULL) createOSSLKeys();
	return x25519Pkey;
}

#endif
