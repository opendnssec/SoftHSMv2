/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPrivateKey.cpp

 OpenSSL X-Wing private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "log.h"
#include "OSSLXWingPrivateKey.h"
#include "XWingParameters.h"
#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <string.h>
#include <utility>

namespace
{
bool shake256(const ByteString& input, unsigned char* output,
	size_t outputLen)
{
	EVP_MD* shake = EVP_MD_fetch(NULL, "SHAKE256", NULL);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	const bool rv = shake != NULL && ctx != NULL &&
		EVP_DigestInit_ex(ctx, shake, NULL) > 0 &&
		EVP_DigestUpdate(ctx, input.const_byte_str(), input.size()) > 0 &&
		EVP_DigestFinalXOF(ctx, output, outputLen) > 0;
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(shake);
	return rv;
}

bool generateMLKEMKeyPair(const unsigned char* seed, EVP_PKEY** pkey)
{
	EVP_PKEY_CTX* ctx =
		EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
		                                  const_cast<unsigned char*>(seed),
		                                  XWingParameters::ML_KEM_768_SEED_LENGTH),
		OSSL_PARAM_construct_end()
	};
	const bool rv = ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0 &&
		EVP_PKEY_CTX_set_params(ctx, params) > 0 &&
		EVP_PKEY_generate(ctx, pkey) > 0;
	EVP_PKEY_CTX_free(ctx);
	return rv;
}

bool expandDecapsulationKey(const ByteString& seed, EVP_PKEY** mlkemPkey,
	EVP_PKEY** x25519Pkey)
{
	if (mlkemPkey == NULL || x25519Pkey == NULL ||
		seed.size() != XWingParameters::X_WING_PRIV_LENGTH)
	{
		return false;
	}

	*mlkemPkey = NULL;
	*x25519Pkey = NULL;
	unsigned char keyDerivationMaterial[
		XWingParameters::X_WING_KEY_DERIVATION_LENGTH];

	// draft-connolly-cfrg-xwing-kem-10 expands sk into d || z || sk_X.
	// OpenSSL accepts d || z as the 64-byte ML-KEM key-generation seed.
	bool rv = shake256(seed, keyDerivationMaterial,
	                   sizeof(keyDerivationMaterial)) &&
		generateMLKEMKeyPair(keyDerivationMaterial, mlkemPkey);
	if (rv)
	{
		*x25519Pkey = EVP_PKEY_new_raw_private_key_ex(
			NULL, "X25519", NULL,
			keyDerivationMaterial +
				XWingParameters::ML_KEM_768_SEED_LENGTH,
			XWingParameters::X25519_PRIV_LENGTH);
		rv = *x25519Pkey != NULL;
	}

	if (!rv)
	{
		ERROR_MSG("Could not expand X-Wing decapsulation key");
		EVP_PKEY_free(*mlkemPkey);
		EVP_PKEY_free(*x25519Pkey);
		*mlkemPkey = NULL;
		*x25519Pkey = NULL;
	}

	OPENSSL_cleanse(keyDerivationMaterial, sizeof(keyDerivationMaterial));
	return rv;
}
}

OSSLXWingPrivateKey::OSSLXWingPrivateKey() : mlkemPkey(NULL), x25519Pkey(NULL)
{
}

OSSLXWingPrivateKey::~OSSLXWingPrivateKey()
{
	resetOSSLKeys();
}

OSSLXWingPrivateKey::OSSLXWingPrivateKey(OSSLXWingPrivateKey&& other) noexcept
	: XWingPrivateKey(std::move(other)), mlkemPkey(other.mlkemPkey),
	  x25519Pkey(other.x25519Pkey)
{
	other.mlkemPkey = NULL;
	other.x25519Pkey = NULL;
}

OSSLXWingPrivateKey& OSSLXWingPrivateKey::operator=(OSSLXWingPrivateKey&& other) noexcept
{
	if (this != &other)
	{
		XWingPrivateKey::operator=(std::move(other));
		resetOSSLKeys();
		mlkemPkey = other.mlkemPkey;
		x25519Pkey = other.x25519Pkey;
		other.mlkemPkey = NULL;
		other.x25519Pkey = NULL;
	}
	return *this;
}

/*static*/ const char* OSSLXWingPrivateKey::type = "OpenSSL X-Wing Private Key";

bool OSSLXWingPrivateKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType) || XWingPrivateKey::isOfType(inType);
}

void OSSLXWingPrivateKey::resetOSSLKeys()
{
	EVP_PKEY_free(mlkemPkey);
	EVP_PKEY_free(x25519Pkey);
	mlkemPkey = NULL;
	x25519Pkey = NULL;
}

void OSSLXWingPrivateKey::setValue(const ByteString& inValue)
{
	XWingPrivateKey::setValue(inValue);
	resetOSSLKeys();
}

void OSSLXWingPrivateKey::createOSSLKeys()
{
	if (mlkemPkey != NULL && x25519Pkey != NULL) return;
	resetOSSLKeys();
	expandDecapsulationKey(getValue(), &mlkemPkey, &x25519Pkey);
}

EVP_PKEY* OSSLXWingPrivateKey::getOSSLMLKEMKey()
{
	if (mlkemPkey == NULL) createOSSLKeys();
	return mlkemPkey;
}

EVP_PKEY* OSSLXWingPrivateKey::getOSSLX25519Key()
{
	if (x25519Pkey == NULL) createOSSLKeys();
	return x25519Pkey;
}

ByteString OSSLXWingPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (getValue().size() != XWingParameters::X_WING_PRIV_LENGTH) return der;

	PKCS8_PRIV_KEY_INFO* p8 = PKCS8_PRIV_KEY_INFO_new();
	ASN1_OBJECT* oid = OBJ_txt2obj(XWingParameters::X_WING_OID, 1);
	unsigned char* privateKey = static_cast<unsigned char*>(
		OPENSSL_memdup(getValue().const_byte_str(), getValue().size()));
	if (p8 == NULL || oid == NULL || privateKey == NULL ||
		PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, privateKey,
		                 XWingParameters::X_WING_PRIV_LENGTH) <= 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		ASN1_OBJECT_free(oid);
		OPENSSL_clear_free(privateKey, getValue().size());
		return der;
	}

	const int length = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
	if (length > 0)
	{
		der.resize(length);
		unsigned char* output = der.byte_str();
		if (i2d_PKCS8_PRIV_KEY_INFO(p8, &output) != length) der.wipe();
	}
	PKCS8_PRIV_KEY_INFO_free(p8);
	return der;
}

bool OSSLXWingPrivateKey::PKCS8Decode(const ByteString& ber)
{
	if (ber.size() == 0) return false;
	const unsigned char* input = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &input, ber.size());
	if (p8 == NULL) return false;

	const ASN1_OBJECT* algorithm = NULL;
	const unsigned char* privateKey = NULL;
	const X509_ALGOR* algorithmIdentifier = NULL;
	int privateKeyLength = 0;
	int parameterType = V_ASN1_UNDEF;
	const void* parameterValue = NULL;
	const bool extracted = PKCS8_pkey_get0(&algorithm, &privateKey,
		&privateKeyLength, &algorithmIdentifier, p8) > 0;
	if (algorithmIdentifier != NULL)
		X509_ALGOR_get0(NULL, &parameterType, &parameterValue,
		                algorithmIdentifier);
	ASN1_OBJECT* expectedAlgorithm = OBJ_txt2obj(XWingParameters::X_WING_OID, 1);
	const bool valid = extracted && expectedAlgorithm != NULL &&
		OBJ_cmp(algorithm, expectedAlgorithm) == 0 &&
		parameterType == V_ASN1_UNDEF &&
		privateKeyLength ==
			static_cast<int>(XWingParameters::X_WING_PRIV_LENGTH);

	if (valid) setValue(ByteString(privateKey, privateKeyLength));
	ASN1_OBJECT_free(expectedAlgorithm);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return valid;
}

#endif
