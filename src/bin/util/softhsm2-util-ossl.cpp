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
 softhsm2-util-ossl.cpp

 Code specific for OpenSSL
 *****************************************************************************/

#include <config.h>
#define UTIL_OSSL
#include "softhsm2-util.h"
#include "softhsm2-util-ossl.h"
#include "OSSLComp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

// Init OpenSSL
void crypto_init()
{
	// We do not need to do this one
	// OpenSSL_add_all_algorithms();
#ifdef WITH_FIPS
	// The PKCS#11 library might be using a FIPS capable OpenSSL
	if (FIPS_mode())
		return;
	if (!FIPS_mode_set(1))
	{
		fprintf(stderr, "ERROR: can't enter into FIPS mode.\n");
		exit(0);
	}
#endif
}

// Final OpenSSL
void crypto_final()
{
	// EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

int crypto_import_aes_key
(
	CK_SESSION_HANDLE hSession,
	char* filePath,
	char* label,
	char* objID,
	size_t objIDLen
)
{
	const size_t cMaxAesKeySize = 1024 + 1; // including null-character
	char aesKeyValue[cMaxAesKeySize];
	FILE* fp = fopen(filePath, "rb");
	if (fp == NULL)
	{
		fprintf(stderr, "ERROR: Could not open the secret key file.\n");
		return 1;
	}
	if (fgets(aesKeyValue, cMaxAesKeySize, fp) == NULL)
	{
		fprintf(stderr, "ERROR: Could not read the secret key file.\n");
		fclose(fp);
		return 1;
	}
	fclose(fp);

	CK_BBOOL ckTrue = CK_TRUE;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS,            &keyClass,    sizeof(keyClass) },
		{ CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
		{ CKA_LABEL,            label,        strlen(label) },
		{ CKA_ID,               objID,        objIDLen },
		{ CKA_TOKEN,            &ckTrue,      sizeof(ckTrue) },
		{ CKA_ENCRYPT,          &ckTrue,      sizeof(ckTrue) },
		{ CKA_DECRYPT,          &ckTrue,      sizeof(ckTrue) },
		{ CKA_SENSITIVE,        &ckTrue,      sizeof(ckTrue) },
        	{ CKA_VALUE,		&aesKeyValue, strlen(aesKeyValue) }
	};

	CK_OBJECT_HANDLE hKey;
	CK_RV rv = p11->C_CreateObject(hSession, keyTemplate, 9, &hKey);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the secret key in the token. "
				"Maybe the algorithm is not supported.\n");
		return 1;
	}

	return 0;
}

// Import a key pair from given path
int crypto_import_key_pair
(
	CK_SESSION_HANDLE hSession,
	char* filePath,
	char* filePIN,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey
)
{
	EVP_PKEY* pkey = crypto_read_file(filePath, filePIN);
	if (pkey == NULL)
	{
		return 1;
	}

	RSA* rsa = NULL;
	DSA* dsa = NULL;
#ifdef WITH_ECC
	EC_KEY* ecdsa = NULL;
#endif
#ifdef WITH_EDDSA
	EVP_PKEY* eddsa = NULL;
#endif

	switch (EVP_PKEY_type(EVP_PKEY_id(pkey)))
	{
		case EVP_PKEY_RSA:
			rsa = EVP_PKEY_get1_RSA(pkey);
			break;
		case EVP_PKEY_DSA:
			dsa = EVP_PKEY_get1_DSA(pkey);
			break;
#ifdef WITH_ECC
		case EVP_PKEY_EC:
			ecdsa = EVP_PKEY_get1_EC_KEY(pkey);
			break;
#endif
#ifdef WITH_EDDSA
		case NID_X25519:
		case NID_ED25519:
		case NID_X448:
		case NID_ED448:
			EVP_PKEY_up_ref(pkey);
			eddsa = pkey;
			break;
#endif
		default:
			fprintf(stderr, "ERROR: Cannot handle this algorithm.\n");
			EVP_PKEY_free(pkey);
			return 1;
			break;
	}
	EVP_PKEY_free(pkey);

	int result = 0;

	if (rsa)
	{
		result = crypto_save_rsa(hSession, label, objID, objIDLen, noPublicKey, rsa);
		RSA_free(rsa);
	}
	else if (dsa)
	{
		result = crypto_save_dsa(hSession, label, objID, objIDLen, noPublicKey, dsa);
		DSA_free(dsa);
	}
#ifdef WITH_ECC
	else if (ecdsa)
	{
		result = crypto_save_ecdsa(hSession, label, objID, objIDLen, noPublicKey, ecdsa);
		EC_KEY_free(ecdsa);
	}
#endif
#ifdef WITH_EDDSA
	else if (eddsa)
	{
		result = crypto_save_eddsa(hSession, label, objID, objIDLen, noPublicKey, eddsa);
		EVP_PKEY_free(eddsa);
	}
#endif
	else
	{
		fprintf(stderr, "ERROR: Could not get the key material.\n");
		result = 1;
	}

	return result;
}

// Read the key from file
EVP_PKEY* crypto_read_file(char* filePath, char* filePIN)
{
	BIO* in = NULL;
	PKCS8_PRIV_KEY_INFO* p8inf = NULL;
	EVP_PKEY* pkey = NULL;
	X509_SIG* p8 = NULL;

	if (!(in = BIO_new_file(filePath, "rb")))
	{
		fprintf(stderr, "ERROR: Could open the PKCS#8 file: %s\n", filePath);
		return NULL;
	}

	// The PKCS#8 file is encrypted
	if (filePIN)
	{
		p8 = PEM_read_bio_PKCS8(in, NULL, NULL, NULL);
		BIO_free(in);

		if (!p8)
		{
			fprintf(stderr, "ERROR: Could not read the PKCS#8 file. "
					"Maybe the file is not encrypted.\n");
			return NULL;
		}

		p8inf = PKCS8_decrypt(p8, filePIN, strlen(filePIN));
		X509_SIG_free(p8);

		if (!p8inf)
		{
			fprintf(stderr, "ERROR: Could not decrypt the PKCS#8 file. "
					"Maybe wrong PIN to file (--file-pin <PIN>)\n");
			return NULL;
		}
	}
	else
	{
		p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(in, NULL, NULL, NULL);
		BIO_free(in);

		if (!p8inf)
		{
			fprintf(stderr, "ERROR: Could not read the PKCS#8 file. "
					"Maybe it is encypted (--file-pin <PIN>)\n");
			return NULL;
		}
	}

	// Convert the PKCS#8 to OpenSSL
	pkey = EVP_PKCS82PKEY(p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (!pkey)
	{
		fprintf(stderr, "ERROR: Could not convert the key.\n");
		return NULL;
	}

	return pkey;
}

// Save the key data in PKCS#11
int crypto_save_rsa
(
	CK_SESSION_HANDLE hSession,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey,
	RSA* rsa
)
{
	rsa_key_material_t* keyMat = crypto_malloc_rsa(rsa);
	if (!keyMat)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE, ckToken = CK_TRUE;
	if (noPublicKey)
	{
		ckToken = CK_FALSE;
	}
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,            &pubClass,    sizeof(pubClass) },
		{ CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
		{ CKA_LABEL,            label,        strlen(label) },
		{ CKA_ID,               objID,        objIDLen },
		{ CKA_TOKEN,            &ckToken,     sizeof(ckToken) },
		{ CKA_VERIFY,           &ckTrue,      sizeof(ckTrue) },
		{ CKA_ENCRYPT,          &ckTrue,      sizeof(ckTrue) },
		{ CKA_WRAP,             &ckTrue,      sizeof(ckTrue) },
		{ CKA_PUBLIC_EXPONENT,  keyMat->bigE, keyMat->sizeE },
		{ CKA_MODULUS,          keyMat->bigN, keyMat->sizeN }
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,            &privClass,      sizeof(privClass) },
		{ CKA_KEY_TYPE,         &keyType,        sizeof(keyType) },
		{ CKA_LABEL,            label,           strlen(label) },
		{ CKA_ID,               objID,           objIDLen },
		{ CKA_SIGN,             &ckTrue,         sizeof(ckTrue) },
		{ CKA_DECRYPT,          &ckTrue,         sizeof(ckTrue) },
		{ CKA_UNWRAP,           &ckTrue,         sizeof(ckTrue) },
		{ CKA_SENSITIVE,        &ckTrue,         sizeof(ckTrue) },
		{ CKA_TOKEN,            &ckTrue,         sizeof(ckTrue) },
		{ CKA_PRIVATE,          &ckTrue,         sizeof(ckTrue) },
		{ CKA_EXTRACTABLE,      &ckFalse,        sizeof(ckFalse) },
		{ CKA_PUBLIC_EXPONENT,  keyMat->bigE,    keyMat->sizeE },
		{ CKA_MODULUS,          keyMat->bigN,    keyMat->sizeN },
		{ CKA_PRIVATE_EXPONENT, keyMat->bigD,    keyMat->sizeD },
		{ CKA_PRIME_1,          keyMat->bigP,    keyMat->sizeP },
		{ CKA_PRIME_2,          keyMat->bigQ,    keyMat->sizeQ },
		{ CKA_EXPONENT_1,       keyMat->bigDMP1, keyMat->sizeDMP1 },
		{ CKA_EXPONENT_2,       keyMat->bigDMQ1, keyMat->sizeDMQ1 },
		{ CKA_COEFFICIENT,      keyMat->bigIQMP, keyMat->sizeIQMP }
	};

	CK_OBJECT_HANDLE hKey1, hKey2;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate, 19, &hKey1);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
				"Maybe the algorithm is not supported.\n");
		crypto_free_rsa(keyMat);
		return 1;
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 10, &hKey2);
	crypto_free_rsa(keyMat);

	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hKey1);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The key pair has been imported.\n");

	return 0;
}

// Convert the OpenSSL key to binary
rsa_key_material_t* crypto_malloc_rsa(RSA* rsa)
{
	if (rsa == NULL)
	{
		return NULL;
	}

	rsa_key_material_t* keyMat = (rsa_key_material_t*)malloc(sizeof(rsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	const BIGNUM* bn_e = NULL;
	const BIGNUM* bn_n = NULL;
	const BIGNUM* bn_d = NULL;
	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_q = NULL;
	const BIGNUM* bn_dmp1 = NULL;
	const BIGNUM* bn_dmq1 = NULL;
	const BIGNUM* bn_iqmp = NULL;
	RSA_get0_factors(rsa, &bn_p, &bn_q);
	RSA_get0_crt_params(rsa, &bn_dmp1, &bn_dmq1, &bn_iqmp);
	RSA_get0_key(rsa, &bn_n, &bn_e, &bn_d);

	keyMat->sizeE = BN_num_bytes(bn_e);
	keyMat->sizeN = BN_num_bytes(bn_n);
	keyMat->sizeD = BN_num_bytes(bn_d);
	keyMat->sizeP = BN_num_bytes(bn_p);
	keyMat->sizeQ = BN_num_bytes(bn_q);
	keyMat->sizeDMP1 = BN_num_bytes(bn_dmp1);
	keyMat->sizeDMQ1 = BN_num_bytes(bn_dmq1);
	keyMat->sizeIQMP = BN_num_bytes(bn_iqmp);

	keyMat->bigE = (CK_VOID_PTR)malloc(keyMat->sizeE);
	keyMat->bigN = (CK_VOID_PTR)malloc(keyMat->sizeN);
	keyMat->bigD = (CK_VOID_PTR)malloc(keyMat->sizeD);
	keyMat->bigP = (CK_VOID_PTR)malloc(keyMat->sizeP);
	keyMat->bigQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);
	keyMat->bigDMP1 = (CK_VOID_PTR)malloc(keyMat->sizeDMP1);
	keyMat->bigDMQ1 = (CK_VOID_PTR)malloc(keyMat->sizeDMQ1);
	keyMat->bigIQMP = (CK_VOID_PTR)malloc(keyMat->sizeIQMP);

	if
	(
		!keyMat->bigE ||
		!keyMat->bigN ||
		!keyMat->bigD ||
		!keyMat->bigP ||
		!keyMat->bigQ ||
		!keyMat->bigDMP1 ||
		!keyMat->bigDMQ1 ||
		!keyMat->bigIQMP
	)
	{
		crypto_free_rsa(keyMat);
		return NULL;
	}

	BN_bn2bin(bn_e, (unsigned char*)keyMat->bigE);
	BN_bn2bin(bn_n, (unsigned char*)keyMat->bigN);
	BN_bn2bin(bn_d, (unsigned char*)keyMat->bigD);
	BN_bn2bin(bn_p, (unsigned char*)keyMat->bigP);
	BN_bn2bin(bn_q, (unsigned char*)keyMat->bigQ);
	BN_bn2bin(bn_dmp1, (unsigned char*)keyMat->bigDMP1);
	BN_bn2bin(bn_dmq1, (unsigned char*)keyMat->bigDMQ1);
	BN_bn2bin(bn_iqmp, (unsigned char*)keyMat->bigIQMP);

	return keyMat;
}

// Free the memory of the key
void crypto_free_rsa(rsa_key_material_t* keyMat)
{
	if (keyMat == NULL) return;
	if (keyMat->bigE) free(keyMat->bigE);
	if (keyMat->bigN) free(keyMat->bigN);
	if (keyMat->bigD) free(keyMat->bigD);
	if (keyMat->bigP) free(keyMat->bigP);
	if (keyMat->bigQ) free(keyMat->bigQ);
	if (keyMat->bigDMP1) free(keyMat->bigDMP1);
	if (keyMat->bigDMQ1) free(keyMat->bigDMQ1);
	if (keyMat->bigIQMP) free(keyMat->bigIQMP);
	free(keyMat);
}

// Save the key data in PKCS#11
int crypto_save_dsa
(
	CK_SESSION_HANDLE hSession,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey,
	DSA* dsa
)
{
	dsa_key_material_t* keyMat = crypto_malloc_dsa(dsa);
	if (keyMat == NULL)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_DSA;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE, ckToken = CK_TRUE;
	if (noPublicKey)
	{
		ckToken = CK_FALSE;
	}
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,            &pubClass,    sizeof(pubClass) },
		{ CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
		{ CKA_LABEL,            label,        strlen(label) },
		{ CKA_ID,               objID,        objIDLen },
		{ CKA_TOKEN,            &ckToken,     sizeof(ckToken) },
		{ CKA_VERIFY,           &ckTrue,      sizeof(ckTrue) },
		{ CKA_ENCRYPT,          &ckFalse,     sizeof(ckFalse) },
		{ CKA_WRAP,             &ckFalse,     sizeof(ckFalse) },
		{ CKA_PRIME,            keyMat->bigP, keyMat->sizeP },
		{ CKA_SUBPRIME,         keyMat->bigQ, keyMat->sizeQ },
		{ CKA_BASE,             keyMat->bigG, keyMat->sizeG },
		{ CKA_VALUE,            keyMat->bigY, keyMat->sizeY }
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,            &privClass,   sizeof(privClass) },
		{ CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
		{ CKA_LABEL,            label,        strlen(label) },
		{ CKA_ID,               objID,        objIDLen },
		{ CKA_SIGN,             &ckTrue,      sizeof(ckTrue) },
		{ CKA_DECRYPT,          &ckFalse,     sizeof(ckFalse) },
		{ CKA_UNWRAP,           &ckFalse,     sizeof(ckFalse) },
		{ CKA_SENSITIVE,        &ckTrue,      sizeof(ckTrue) },
		{ CKA_TOKEN,            &ckTrue,      sizeof(ckTrue) },
		{ CKA_PRIVATE,          &ckTrue,      sizeof(ckTrue) },
		{ CKA_EXTRACTABLE,      &ckFalse,     sizeof(ckFalse) },
		{ CKA_PRIME,            keyMat->bigP, keyMat->sizeP },
		{ CKA_SUBPRIME,         keyMat->bigQ, keyMat->sizeQ },
		{ CKA_BASE,             keyMat->bigG, keyMat->sizeG },
		{ CKA_VALUE,            keyMat->bigX, keyMat->sizeX }
	};

	CK_OBJECT_HANDLE hKey1, hKey2;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate, 15, &hKey1);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
				"Maybe the algorithm is not supported.\n");
		crypto_free_dsa(keyMat);
		return 1;
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 12, &hKey2);
	crypto_free_dsa(keyMat);

	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hKey1);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The key pair has been imported.\n");

	return 0;
}

// Convert the OpenSSL key to binary
dsa_key_material_t* crypto_malloc_dsa(DSA* dsa)
{
	if (dsa == NULL)
	{
		return NULL;
	}

	dsa_key_material_t* keyMat = (dsa_key_material_t*)malloc(sizeof(dsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_q = NULL;
	const BIGNUM* bn_g = NULL;
	const BIGNUM* bn_priv_key = NULL;
	const BIGNUM* bn_pub_key = NULL;
	DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);
	DSA_get0_key(dsa, &bn_pub_key, &bn_priv_key);

	keyMat->sizeP = BN_num_bytes(bn_p);
	keyMat->sizeQ = BN_num_bytes(bn_q);
	keyMat->sizeG = BN_num_bytes(bn_g);
	keyMat->sizeX = BN_num_bytes(bn_priv_key);
	keyMat->sizeY = BN_num_bytes(bn_pub_key);

	keyMat->bigP = (CK_VOID_PTR)malloc(keyMat->sizeP);
	keyMat->bigQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);
	keyMat->bigG = (CK_VOID_PTR)malloc(keyMat->sizeG);
	keyMat->bigX = (CK_VOID_PTR)malloc(keyMat->sizeX);
	keyMat->bigY = (CK_VOID_PTR)malloc(keyMat->sizeY);

	if (!keyMat->bigP || !keyMat->bigQ || !keyMat->bigG || !keyMat->bigX || !keyMat->bigY)
	{
		crypto_free_dsa(keyMat);
		return NULL;
	}

	BN_bn2bin(bn_p, (unsigned char*)keyMat->bigP);
	BN_bn2bin(bn_q, (unsigned char*)keyMat->bigQ);
	BN_bn2bin(bn_g, (unsigned char*)keyMat->bigG);
	BN_bn2bin(bn_priv_key, (unsigned char*)keyMat->bigX);
	BN_bn2bin(bn_pub_key, (unsigned char*)keyMat->bigY);

	return keyMat;
}

// Free the memory of the key
void crypto_free_dsa(dsa_key_material_t* keyMat)
{
	if (keyMat == NULL) return;
	if (keyMat->bigP) free(keyMat->bigP);
	if (keyMat->bigQ) free(keyMat->bigQ);
	if (keyMat->bigG) free(keyMat->bigG);
	if (keyMat->bigX) free(keyMat->bigX);
	if (keyMat->bigY) free(keyMat->bigY);
	free(keyMat);
}

#ifdef WITH_ECC

// Save the key data in PKCS#11
int crypto_save_ecdsa
(
	CK_SESSION_HANDLE hSession,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey,
	EC_KEY* ecdsa
)
{
	ecdsa_key_material_t* keyMat = crypto_malloc_ecdsa(ecdsa);
	if (keyMat == NULL)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_EC;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE, ckToken = CK_TRUE;
	if (noPublicKey)
	{
		ckToken = CK_FALSE;
	}
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,          &pubClass,         sizeof(pubClass) },
		{ CKA_KEY_TYPE,       &keyType,          sizeof(keyType) },
		{ CKA_LABEL,          label,             strlen(label) },
		{ CKA_ID,             objID,             objIDLen },
		{ CKA_TOKEN,          &ckToken,          sizeof(ckToken) },
		{ CKA_VERIFY,         &ckTrue,           sizeof(ckTrue) },
		{ CKA_ENCRYPT,        &ckFalse,          sizeof(ckFalse) },
		{ CKA_WRAP,           &ckFalse,          sizeof(ckFalse) },
		{ CKA_EC_PARAMS,      keyMat->derParams, keyMat->sizeParams },
		{ CKA_EC_POINT,       keyMat->derQ,      keyMat->sizeQ },
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,          &privClass,        sizeof(privClass) },
		{ CKA_KEY_TYPE,       &keyType,          sizeof(keyType) },
		{ CKA_LABEL,          label,             strlen(label) },
		{ CKA_ID,             objID,             objIDLen },
		{ CKA_SIGN,           &ckTrue,           sizeof(ckTrue) },
		{ CKA_DECRYPT,        &ckFalse,          sizeof(ckFalse) },
		{ CKA_UNWRAP,         &ckFalse,          sizeof(ckFalse) },
		{ CKA_SENSITIVE,      &ckTrue,           sizeof(ckTrue) },
		{ CKA_TOKEN,          &ckTrue,           sizeof(ckTrue) },
		{ CKA_PRIVATE,        &ckTrue,           sizeof(ckTrue) },
		{ CKA_EXTRACTABLE,    &ckFalse,          sizeof(ckFalse) },
		{ CKA_EC_PARAMS,      keyMat->derParams, keyMat->sizeParams },
		{ CKA_VALUE,          keyMat->bigD,      keyMat->sizeD }
	};

	CK_OBJECT_HANDLE hKey1, hKey2;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate, 13, &hKey1);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
				"Maybe the algorithm is not supported.\n");
		crypto_free_ecdsa(keyMat);
		return 1;
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 10, &hKey2);
	crypto_free_ecdsa(keyMat);

	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hKey1);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The key pair has been imported.\n");

	return 0;
}

// Convert the OpenSSL key to binary
ecdsa_key_material_t* crypto_malloc_ecdsa(EC_KEY* ec_key)
{
	int result;

	if (ec_key == NULL)
	{
		return NULL;
	}

	ecdsa_key_material_t* keyMat = (ecdsa_key_material_t*)malloc(sizeof(ecdsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	const BIGNUM *d = EC_KEY_get0_private_key(ec_key);
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	const EC_POINT *point = EC_KEY_get0_public_key(ec_key);

	keyMat->sizeParams = i2d_ECPKParameters(group, NULL);
	keyMat->sizeD = BN_num_bytes(d);

	keyMat->derParams = (CK_VOID_PTR)malloc(keyMat->sizeParams);
	keyMat->bigD = (CK_VOID_PTR)malloc(keyMat->sizeD);
	keyMat->derQ = NULL;

	if (!keyMat->derParams || !keyMat->bigD)
	{
		crypto_free_ecdsa(keyMat);
		return NULL;
	}

	/*
	 * i2d functions increment the pointer, so we have to use a
	 * sacrificial pointer
	 */
	unsigned char *derParams = (unsigned char*) keyMat->derParams;
	result = i2d_ECPKParameters(group, &derParams);
	if (result == 0)
	{
		crypto_free_ecdsa(keyMat);
		return NULL;
	}
	BN_bn2bin(d, (unsigned char*)keyMat->bigD);

	size_t point_length = EC_POINT_point2oct(group,
					      point,
					      POINT_CONVERSION_UNCOMPRESSED,
					      NULL,
					      0,
					      NULL);

	// Definite, short
	if (point_length <= 0x7f)
	{
		keyMat->sizeQ = 2 + point_length;
		keyMat->derQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);
		if (!keyMat->derQ)
		{
			crypto_free_ecdsa(keyMat);
			return NULL;
		}

		unsigned char *derQ = (unsigned char *)keyMat->derQ;
		derQ[0] = V_ASN1_OCTET_STRING;
		derQ[1] = point_length & 0x7f;
		result = EC_POINT_point2oct(group,
					    point,
					    POINT_CONVERSION_UNCOMPRESSED,
					    &derQ[2],
					    point_length,
					    NULL);
		if (result == 0)
		{
			crypto_free_ecdsa(keyMat);
			return NULL;
		}
	}
	// Definite, long
	else
	{
		// Count significate bytes
		size_t bytes = sizeof(size_t);
		for(; bytes > 0; bytes--)
		{
			size_t value = point_length >> ((bytes - 1) * 8);
			if (value & 0xFF) break;
		}

		keyMat->sizeQ = 2 + bytes + point_length;
		keyMat->derQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);
		if (!keyMat->derQ)
		{
			crypto_free_ecdsa(keyMat);
			return NULL;
		}

		unsigned char *derQ = (unsigned char *)keyMat->derQ;
		derQ[0] = V_ASN1_OCTET_STRING;
		derQ[1] = 0x80 | bytes;

		size_t len = point_length;
		for (size_t i = 1; i <= bytes; i++)
		{
			derQ[2+bytes-i] = (unsigned char) (len & 0xFF);
			len >>= 8;
		}

		result = EC_POINT_point2oct(group,
					    point,
					    POINT_CONVERSION_UNCOMPRESSED,
					    &derQ[2+bytes],
					    point_length,
					    NULL);
		if (result == 0)
		{
			crypto_free_ecdsa(keyMat);
			return NULL;
		}
	}

	return keyMat;
}

// Free the memory of the key
void crypto_free_ecdsa(ecdsa_key_material_t* keyMat)
{
	if (keyMat == NULL) return;
	if (keyMat->derParams) free(keyMat->derParams);
	if (keyMat->bigD) free(keyMat->bigD);
	if (keyMat->derQ) free(keyMat->derQ);
	free(keyMat);
}

#endif

#ifdef WITH_EDDSA

// Save the key data in PKCS#11
int crypto_save_eddsa
(
	CK_SESSION_HANDLE hSession,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey,
	EVP_PKEY* eddsa
)
{
	eddsa_key_material_t* keyMat = crypto_malloc_eddsa(eddsa);
	if (keyMat == NULL)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_EC_EDWARDS;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE, ckToken = CK_TRUE;
	if (noPublicKey)
	{
		ckToken = CK_FALSE;
	}
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,          &pubClass,         sizeof(pubClass) },
		{ CKA_KEY_TYPE,       &keyType,          sizeof(keyType) },
		{ CKA_LABEL,          label,             strlen(label) },
		{ CKA_ID,             objID,             objIDLen },
		{ CKA_TOKEN,          &ckToken,          sizeof(ckToken) },
		{ CKA_VERIFY,         &ckTrue,           sizeof(ckTrue) },
		{ CKA_ENCRYPT,        &ckFalse,          sizeof(ckFalse) },
		{ CKA_WRAP,           &ckFalse,          sizeof(ckFalse) },
		{ CKA_EC_PARAMS,      keyMat->derOID,    keyMat->sizeOID },
		{ CKA_EC_POINT,       keyMat->bigA,      keyMat->sizeA },
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,          &privClass,        sizeof(privClass) },
		{ CKA_KEY_TYPE,       &keyType,          sizeof(keyType) },
		{ CKA_LABEL,          label,             strlen(label) },
		{ CKA_ID,             objID,             objIDLen },
		{ CKA_SIGN,           &ckTrue,           sizeof(ckTrue) },
		{ CKA_DECRYPT,        &ckFalse,          sizeof(ckFalse) },
		{ CKA_UNWRAP,         &ckFalse,          sizeof(ckFalse) },
		{ CKA_SENSITIVE,      &ckTrue,           sizeof(ckTrue) },
		{ CKA_TOKEN,          &ckTrue,           sizeof(ckTrue) },
		{ CKA_PRIVATE,        &ckTrue,           sizeof(ckTrue) },
		{ CKA_EXTRACTABLE,    &ckFalse,          sizeof(ckFalse) },
		{ CKA_EC_PARAMS,      keyMat->derOID,    keyMat->sizeOID },
		{ CKA_VALUE,          keyMat->bigK,      keyMat->sizeK }
	};

	CK_OBJECT_HANDLE hKey1, hKey2;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate, 13, &hKey1);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
				"Maybe the algorithm is not supported.\n");
		crypto_free_eddsa(keyMat);
		return 1;
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 10, &hKey2);
	crypto_free_eddsa(keyMat);

	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hKey1);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The key pair has been imported.\n");

	return 0;
}

// Convert the OpenSSL key to binary

#define X25519_KEYLEN	32
#define X448_KEYLEN	57

#define PUBPREFIXLEN	12
#define PRIVPREFIXLEN	16

eddsa_key_material_t* crypto_malloc_eddsa(EVP_PKEY* pkey)
{
	int result;
	int len;
	unsigned char *buf;

	if (pkey == NULL)
	{
		return NULL;
	}

	eddsa_key_material_t* keyMat = (eddsa_key_material_t*)malloc(sizeof(eddsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	int nid = EVP_PKEY_id(pkey);
	memset(keyMat, 0, sizeof(*keyMat));
	keyMat->sizeOID = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), NULL);
	keyMat->derOID = (CK_VOID_PTR)malloc(keyMat->sizeOID);

	switch (nid) {
	case NID_X25519:
	case NID_ED25519:
		keyMat->sizeK = X25519_KEYLEN;
		keyMat->sizeA = X25519_KEYLEN;
		break;
	case NID_X448:
	case NID_ED448:
		keyMat->sizeK = X448_KEYLEN;
		keyMat->sizeA = X448_KEYLEN;
		break;
	default:
		crypto_free_eddsa(keyMat);
		return NULL;
	}
	keyMat->bigK = (CK_VOID_PTR)malloc(keyMat->sizeK);
	keyMat->bigA = (CK_VOID_PTR)malloc(keyMat->sizeA);
	if (!keyMat->derOID || !keyMat->bigK || !keyMat->bigA)
	{
		crypto_free_eddsa(keyMat);
		return NULL;
	}

	unsigned char *p = (unsigned char*) keyMat->derOID;
	result = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), &p);
	if (result <= 0)
	{
		crypto_free_eddsa(keyMat);
		return NULL;
	}

	len = i2d_PUBKEY(pkey, NULL);
	if (((CK_ULONG) len != PUBPREFIXLEN + keyMat->sizeA) ||
	    ((buf = (unsigned char*) malloc(len)) == NULL))
	{
		crypto_free_eddsa(keyMat);
		return NULL;
	}
	p = buf;
	i2d_PUBKEY(pkey, &p);
	memcpy(keyMat->bigA, buf + PUBPREFIXLEN, keyMat->sizeA);
	free(buf);

	len = i2d_PrivateKey(pkey, NULL);
	if (((CK_ULONG) len != PRIVPREFIXLEN + keyMat->sizeK) ||
	    ((buf = (unsigned char*) malloc(len)) == NULL))
	{
		crypto_free_eddsa(keyMat);
		return NULL;
	}
	p = buf;
	i2d_PrivateKey(pkey, &p);
	memcpy(keyMat->bigK, buf + PRIVPREFIXLEN, keyMat->sizeK);
	free(buf);

	return keyMat;
}

// Free the memory of the key
void crypto_free_eddsa(eddsa_key_material_t* keyMat)
{
	if (keyMat == NULL) return;
	if (keyMat->derOID) free(keyMat->derOID);
	if (keyMat->bigK) free(keyMat->bigK);
	if (keyMat->bigA) free(keyMat->bigA);
	free(keyMat);
}

#endif
