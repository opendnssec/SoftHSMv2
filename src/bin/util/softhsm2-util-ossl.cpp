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
/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
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
#ifdef WITH_FALCON
#include "OSSLFalconPrivateKey.h"
#include "OSSLFalconPublicKey.h"
#endif

#include <stdio.h>
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
	const size_t cMaxAesKeySize = 1024;
	char aesKeyValue[cMaxAesKeySize];
	size_t aesKeyLength = 0;
	FILE* fp = fopen(filePath, "rb");
	if (fp == NULL)
	{
		fprintf(stderr, "ERROR: Could not open the secret key file.\n");
		return 1;
	}
	aesKeyLength = fread(aesKeyValue, 1, cMaxAesKeySize, fp);
	if (aesKeyLength == 0)
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
        	{ CKA_VALUE,		&aesKeyValue, aesKeyLength }
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
#ifdef WITH_FALCON
	EVP_PKEY* falcon = NULL;
#endif
#ifdef WITH_ML_DSA
	EVP_PKEY* mldsa = NULL;
#endif
#ifdef WITH_ML_KEM
	EVP_PKEY* mlkem = NULL;
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	int keyType = EVP_PKEY_get_id(pkey);
	if (keyType != EVP_PKEY_KEYMGMT) 
	{
		switch (keyType)
#else
	switch (EVP_PKEY_type(EVP_PKEY_id(pkey)))
#endif
	
		{
			case EVP_PKEY_RSA:
			case EVP_PKEY_RSA_PSS:
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	} else {
		// Provider Keys management
		#if defined(WITH_FALCON) || defined(WITH_ML_DSA) || defined(WITH_ML_KEM)
            int isFalcon = 0;
            int isMldsa = 0;
            int isMlkem = 0;
		#ifdef WITH_FALCON
            isFalcon = (EVP_PKEY_is_a(pkey, "falcon512") ||
                        EVP_PKEY_is_a(pkey, "falcon1024"));
		#endif
		#ifdef WITH_ML_DSA
            isMldsa = (EVP_PKEY_is_a(pkey, "ML-DSA-44") ||
                       EVP_PKEY_is_a(pkey, "ML-DSA-65") ||
                       EVP_PKEY_is_a(pkey, "ML-DSA-87"));
		#endif
		#ifdef WITH_ML_KEM
            isMlkem = (EVP_PKEY_is_a(pkey, "ML-KEM-512") ||
                       EVP_PKEY_is_a(pkey, "ML-KEM-768") ||
                       EVP_PKEY_is_a(pkey, "ML-KEM-1024"));
		#endif
            if (!isFalcon && !isMldsa && !isMlkem)
            {
	            fprintf(stderr, "ERROR: Cannot handle this algorithm.\n");
	            EVP_PKEY_free(pkey);
	            return 1;
	        }
		#ifdef WITH_FALCON
            if (isFalcon)
            {
                EVP_PKEY_up_ref(pkey);
                falcon = pkey;
            }
		#endif
		#ifdef WITH_ML_DSA
	        if (isMldsa)
	        {
                EVP_PKEY_up_ref(pkey);
                mldsa = pkey;
	        }
		#endif
		#ifdef WITH_ML_KEM
            if (isMlkem)
            {
                EVP_PKEY_up_ref(pkey);
                mlkem = pkey;
            }
		#endif
		#endif
	}
#endif
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
#ifdef WITH_FALCON
	else if (falcon)
	{
		result = crypto_save_falcon(hSession, label, objID, objIDLen, noPublicKey, falcon);
		EVP_PKEY_free(falcon);
	}
#endif
#ifdef WITH_ML_DSA
	else if (mldsa)
	{
		result = crypto_save_mldsa(hSession, label, objID, objIDLen, noPublicKey, mldsa);
		EVP_PKEY_free(mldsa);
	}
#endif
#ifdef WITH_ML_KEM
	else if (mlkem)
	{
		result = crypto_save_mlkem(hSession, label, objID, objIDLen, noPublicKey, mlkem);
		EVP_PKEY_free(mlkem);
	}
#endif
	else
	{
		fprintf(stderr, "ERROR: Could not get the key material.\n");
		result = 1;
	}

	return result;
}

int crypto_import_certificate
(
	CK_SESSION_HANDLE hSession,
	char* filePath,
	char* label,
	char* objID,
	size_t objIDLen
)
{
	BIO* in = NULL;
	X509* x509 = NULL;
	CK_BYTE_PTR blob = NULL;
	CK_BYTE_PTR subject = NULL;
	CK_BYTE_PTR issuer = NULL;
	CK_BYTE_PTR serial = NULL;
	CK_BYTE_PTR p;
	int blobSize;
	int subjectSize;
	int issuerSize;
	int serialSize;
	int ret = 1;

	if (!(in = BIO_new_file(filePath, "rb")))
	{
		fprintf(stderr, "ERROR: Could open the PKCS#8 file: %s\n", filePath);
		goto cleanup;
	}

	if ((x509 = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL)
	{
		fprintf(stderr, "ERROR: Could not read the certificate file: %s\n", filePath);
		goto cleanup;
	}

	blobSize = i2d_X509(x509, NULL);
	subjectSize = i2d_X509_NAME(X509_get_subject_name(x509), NULL);
	issuerSize = i2d_X509_NAME(X509_get_issuer_name(x509), NULL);
	serialSize = i2d_ASN1_INTEGER(X509_get_serialNumber(x509), NULL);

	if
	(
		blobSize < 0 ||
		subjectSize < 0 ||
		issuerSize < 0 ||
		serialSize < 0
	)
	{
		fprintf(stderr, "ERROR: Could not convert certificate to DER.\n");
		goto cleanup;
	}

	if (blobSize > 0)
	{
		if ((blob = (CK_BYTE_PTR)malloc(blobSize)) == NULL)
		{
			fprintf(stderr, "ERROR: Could not allocate memory.\n");
			goto cleanup;
		}
		p = blob;
		blobSize = i2d_X509(x509, &p);
	}
	if (subjectSize > 0) {
		if ((subject = (CK_BYTE_PTR)malloc(subjectSize)) == NULL)
		{
			fprintf(stderr, "ERROR: Could not allocate memory.\n");
			goto cleanup;
		}
		p = subject;
		subjectSize = i2d_X509_NAME(X509_get_subject_name(x509), &p);
	}
	if (issuerSize > 0)
	{
		if ((issuer = (CK_BYTE_PTR)malloc(issuerSize)) == NULL)
		{
			fprintf(stderr, "ERROR: Could not allocate memory.\n");
			goto cleanup;
		}
		p = issuer;
		issuerSize = i2d_X509_NAME(X509_get_issuer_name(x509), &p);
	}
	if (serialSize > 0)
	{
		if ((serial = (CK_BYTE_PTR)malloc(serialSize)) == NULL)
		{
			fprintf(stderr, "ERROR: Could not allocate memory.\n");
			goto cleanup;
		}
		p = serial;
		serialSize = i2d_ASN1_INTEGER(X509_get_serialNumber(x509), &p);
	}

	if
	(
		blobSize < 0 ||
		subjectSize < 0 ||
		issuerSize < 0 ||
		serialSize < 0
	)
	{
		fprintf(stderr, "ERROR: Could not convert certificate to DER.\n");
		goto cleanup;
	}

	{
		CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
		CK_CERTIFICATE_TYPE certType = CKC_X_509;
		CK_BBOOL ckFalse = CK_FALSE, ckTrue = CK_TRUE;
		CK_ATTRIBUTE certTemplate[] = {
			{ CKA_CLASS,            &certClass,   sizeof(certClass) },
			{ CKA_CERTIFICATE_TYPE, &certType,    sizeof(certType) },
			{ CKA_LABEL,            label,        strlen(label) },
			{ CKA_ID,               objID,        objIDLen },
			{ CKA_TOKEN,            &ckTrue,      sizeof(ckTrue) },
			{ CKA_PRIVATE,          &ckFalse,     sizeof(ckFalse) },
			{ CKA_VALUE,            blob,         (CK_ULONG)blobSize },
			{ CKA_SUBJECT,          subject,      (CK_ULONG)subjectSize },
			{ CKA_ISSUER,           issuer,       (CK_ULONG)issuerSize },
			{ CKA_SERIAL_NUMBER,    serial,       (CK_ULONG)serialSize }
		};

		CK_OBJECT_HANDLE hCert;
		CK_RV rv = p11->C_CreateObject(hSession, certTemplate, 10, &hCert);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not save the certificate in the token.\n");
			goto cleanup;
		}
	}

	printf("The certificate with label=%s has been imported.\n", label);

	ret = 0;

cleanup:

	free(blob);
	free(subject);
	free(issuer);
	free(serial);
	X509_free(x509);
	BIO_free(in);

	return ret;
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

	printf("The RSA key pair with label=%s has been imported.\n", label);

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

	printf("The DSA key pair with label=%s has been imported.\n", label);

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

	printf("The ECDSA key pair with label=%s has been imported.\n", label);

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

	printf("The EDDSA key pair with label=%s has been imported.\n", label);

	return 0;
}

// Convert the OpenSSL key to binary

#define X25519_KEYLEN	32
#define X448_KEYLEN	56
#define ED448_KEYLEN	57

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

	eddsa_key_material_t* keyMat = (eddsa_key_material_t*)calloc(1, sizeof(eddsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	int nid = EVP_PKEY_id(pkey);
	keyMat->sizeOID = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), NULL);
	keyMat->derOID = (CK_VOID_PTR)malloc(keyMat->sizeOID);

	switch (nid) {
	case NID_X25519:
	case NID_ED25519:
		keyMat->sizeK = X25519_KEYLEN;
		keyMat->sizeA = X25519_KEYLEN;
		break;
	case NID_X448:
		keyMat->sizeK = X448_KEYLEN;
		keyMat->sizeA = X448_KEYLEN;
		break;
	case NID_ED448:
		keyMat->sizeK = ED448_KEYLEN;
		keyMat->sizeA = ED448_KEYLEN;
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

#ifdef WITH_ML_DSA

// Save the key data in PKCS#11
int crypto_save_mldsa
(
	CK_SESSION_HANDLE hSession,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey,
	EVP_PKEY* mldsa
)
{
	mldsa_key_material_t* keyMat = crypto_malloc_mldsa(mldsa);
	if (keyMat == NULL)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_ML_DSA;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE, ckToken = CK_TRUE;
	if (noPublicKey)
	{
		ckToken = CK_FALSE;
	}
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,          &pubClass,               sizeof(pubClass) },
		{ CKA_KEY_TYPE,       &keyType,                sizeof(keyType) },
		{ CKA_LABEL,          label,                   strlen(label) },
		{ CKA_ID,             objID,                   objIDLen },
		{ CKA_TOKEN,          &ckToken,                sizeof(ckToken) },
		{ CKA_VERIFY,         &ckTrue,                 sizeof(ckTrue) },
		{ CKA_ENCRYPT,        &ckFalse,                sizeof(ckFalse) },
		{ CKA_WRAP,           &ckFalse,                sizeof(ckFalse) },
		{ CKA_PARAMETER_SET,  &keyMat->parameterSet,   sizeof(CK_ULONG) },
		{ CKA_VALUE,          keyMat->pubValue,        keyMat->sizePubValue },
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
		{ CKA_PARAMETER_SET,  &keyMat->parameterSet,   sizeof(CK_ULONG) },
		{ CKA_SEED,           keyMat->seed,            keyMat->sizeSeed },
		{ CKA_VALUE,          keyMat->privValue,       keyMat->sizePrivValue },
	};

	CK_OBJECT_HANDLE hKey1, hKey2;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate, 14, &hKey1);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
				"Maybe the algorithm is not supported.\n");
		crypto_free_mldsa(keyMat);
		return 1;
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 10, &hKey2);
	crypto_free_mldsa(keyMat);

	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hKey1);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The ML-DSA key pair with label=%s has been imported.\n", label);

	return 0;
}

mldsa_key_material_t* crypto_malloc_mldsa(EVP_PKEY* pkey)
{

	if (pkey == NULL)
	{
		return NULL;
	}

	mldsa_key_material_t* keyMat = (mldsa_key_material_t*)calloc(1, sizeof(mldsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	uint8_t seed[32];
	size_t seed_len;
	int rv = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ML_DSA_SEED,
								seed, sizeof(seed), &seed_len);

	if(!rv)
	{
		fprintf(stderr, "ERROR: Could not get ML-DSA seed, rv: %d\n", rv);
		memset(seed, 0, sizeof(seed));
		crypto_free_mldsa(keyMat);
		return NULL;
	}

	// let's use max priv length
	uint8_t priv[MLDSAParameters::ML_DSA_87_PRIV_LENGTH];
	size_t priv_len;
	rv = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
									priv, sizeof(priv), &priv_len);
	if(!rv)
	{
		fprintf(stderr, "ERROR: Could not get ML-DSA private key, rv: %d\n", rv);
		memset(seed, 0, sizeof(seed));
		memset(priv, 0, sizeof(priv));
		crypto_free_mldsa(keyMat);
		return NULL;
	}

	if (priv_len != MLDSAParameters::ML_DSA_44_PRIV_LENGTH &&
	    priv_len != MLDSAParameters::ML_DSA_65_PRIV_LENGTH &&
	    priv_len != MLDSAParameters::ML_DSA_87_PRIV_LENGTH)
	{
		fprintf(stderr, "ERROR: Unsupported ML-DSA private key length: %zu\n", priv_len);
		memset(seed, 0, sizeof(seed));
		memset(priv, 0, sizeof(priv));
		crypto_free_mldsa(keyMat);
		return NULL;
	}

	uint8_t pub[MLDSAParameters::ML_DSA_87_PUB_LENGTH];
    size_t pub_len;
	rv = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                    pub, sizeof(pub), &pub_len);

	if(!rv)
	{
		fprintf(stderr, "ERROR: Could not get ML-DSA public key, rv: %d\n", rv);
		memset(seed, 0, sizeof(seed));
		memset(priv, 0, sizeof(priv));
		memset(pub, 0, sizeof(pub));
		crypto_free_mldsa(keyMat);
		return NULL;
	}

	keyMat->sizeSeed = seed_len;
	keyMat->sizePrivValue = priv_len;
	keyMat->sizePubValue = pub_len;

	if (keyMat->sizeSeed > 0) {
		keyMat->seed = (CK_VOID_PTR)malloc(keyMat->sizeSeed);
	}
	if (keyMat->sizePrivValue > 0) {
		keyMat->privValue = (CK_VOID_PTR)malloc(keyMat->sizePrivValue);
	}
	keyMat->pubValue = (CK_VOID_PTR)malloc(keyMat->sizePubValue);

	if (!keyMat->seed || !keyMat->privValue || !keyMat->pubValue)
	{
		crypto_free_mldsa(keyMat);
		return NULL;
	}

	switch (keyMat->sizePrivValue)
	{
		case MLDSAParameters::ML_DSA_44_PRIV_LENGTH:
			keyMat->parameterSet = MLDSAParameters::ML_DSA_44_PARAMETER_SET;
			break;
		
		case MLDSAParameters::ML_DSA_65_PRIV_LENGTH:
			keyMat->parameterSet = MLDSAParameters::ML_DSA_65_PARAMETER_SET;
			break;
		
		case MLDSAParameters::ML_DSA_87_PRIV_LENGTH:
			keyMat->parameterSet = MLDSAParameters::ML_DSA_87_PARAMETER_SET;
			break;
		
		default:
			crypto_free_mldsa(keyMat);
			return NULL;
	}

	if (keyMat->seed) {
		memcpy(keyMat->seed, seed, keyMat->sizeSeed);
	}
	if (keyMat->privValue) {
		memcpy(keyMat->privValue, priv, keyMat->sizePrivValue);
	}
	memcpy(keyMat->pubValue, pub, keyMat->sizePubValue);

	return keyMat;
}

// Free the memory of the key
void crypto_free_mldsa(mldsa_key_material_t* keyMat)
{
	if (keyMat == NULL) return;
	if (keyMat->seed) free(keyMat->seed);
	if (keyMat->privValue) free(keyMat->privValue);
	if (keyMat->pubValue) free(keyMat->pubValue);
	free(keyMat);
}

#endif

#ifdef WITH_ML_KEM

// Save the key data in PKCS#11
int crypto_save_mlkem
(
	CK_SESSION_HANDLE hSession,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey,
	EVP_PKEY* mlkem
)
{
	mlkem_key_material_t* keyMat = crypto_malloc_mlkem(mlkem);
	if (keyMat == NULL)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_ML_KEM;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE, ckToken = CK_TRUE;
	if (noPublicKey)
	{
		ckToken = CK_FALSE;
	}
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,          &pubClass,               sizeof(pubClass) },
		{ CKA_KEY_TYPE,       &keyType,                sizeof(keyType) },
		{ CKA_LABEL,          label,                   strlen(label) },
		{ CKA_ID,             objID,                   objIDLen },
		{ CKA_TOKEN,          &ckToken,                sizeof(ckToken) },
		{ CKA_ENCAPSULATE,    &ckTrue,                 sizeof(ckTrue) },
		{ CKA_VERIFY,         &ckFalse,                sizeof(ckFalse) },
		{ CKA_ENCRYPT,        &ckFalse,                sizeof(ckFalse) },
		{ CKA_WRAP,           &ckFalse,                sizeof(ckFalse) },
		{ CKA_PARAMETER_SET,  &keyMat->parameterSet,   sizeof(CK_ULONG) },
		{ CKA_VALUE,          keyMat->pubValue,        keyMat->sizePubValue },
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,          &privClass,        sizeof(privClass) },
		{ CKA_KEY_TYPE,       &keyType,          sizeof(keyType) },
		{ CKA_LABEL,          label,             strlen(label) },
		{ CKA_ID,             objID,             objIDLen },
		{ CKA_SIGN,           &ckFalse,          sizeof(ckFalse) },
		{ CKA_DECAPSULATE,    &ckTrue,           sizeof(ckTrue) },
		{ CKA_DECRYPT,        &ckFalse,          sizeof(ckFalse) },
		{ CKA_UNWRAP,         &ckFalse,          sizeof(ckFalse) },
		{ CKA_SENSITIVE,      &ckTrue,           sizeof(ckTrue) },
		{ CKA_TOKEN,          &ckTrue,           sizeof(ckTrue) },
		{ CKA_PRIVATE,        &ckTrue,           sizeof(ckTrue) },
		{ CKA_EXTRACTABLE,    &ckFalse,          sizeof(ckFalse) },
		{ CKA_PARAMETER_SET,  &keyMat->parameterSet,   sizeof(CK_ULONG) },
		{ CKA_SEED,           keyMat->seed,            keyMat->sizeSeed },
		{ CKA_VALUE,          keyMat->privValue,       keyMat->sizePrivValue },
	};

	CK_OBJECT_HANDLE hKey1, hKey2;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate, 15, &hKey1);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
				"Maybe the algorithm is not supported.\n");
		crypto_free_mlkem(keyMat);
		return 1;
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 11, &hKey2);
	crypto_free_mlkem(keyMat);

	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hKey1);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The ML-KEM key pair with label=%s has been imported.\n", label);

	return 0;
}

mlkem_key_material_t* crypto_malloc_mlkem(EVP_PKEY* pkey)
{

	if (pkey == NULL)
	{
		return NULL;
	}

	mlkem_key_material_t* keyMat = (mlkem_key_material_t*)calloc(1, sizeof(mlkem_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	uint8_t seed[64];
	size_t seed_len;
	int rv = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ML_KEM_SEED,
								seed, sizeof(seed), &seed_len);

	if(!rv)
	{
		fprintf(stderr, "ERROR: Could not get ML-KEM seed, rv: %d\n", rv);
		memset(seed, 0, sizeof(seed));
		crypto_free_mlkem(keyMat);
		return NULL;
	}

	// let's use max priv length
	uint8_t priv[MLKEMParameters::ML_KEM_1024_PRIV_LENGTH];
	size_t priv_len;
	rv = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
									priv, sizeof(priv), &priv_len);
	if(!rv)
	{
		fprintf(stderr, "ERROR: Could not get ML-KEM private key, rv: %d\n", rv);
		memset(seed, 0, sizeof(seed));
		memset(priv, 0, sizeof(priv));
		crypto_free_mlkem(keyMat);
		return NULL;
	}

	if (priv_len != MLKEMParameters::ML_KEM_512_PRIV_LENGTH &&
	    priv_len != MLKEMParameters::ML_KEM_768_PRIV_LENGTH &&
	    priv_len != MLKEMParameters::ML_KEM_1024_PRIV_LENGTH)
	{
		fprintf(stderr, "ERROR: Unsupported ML-KEM private key length: %zu\n", priv_len);
		memset(seed, 0, sizeof(seed));
		memset(priv, 0, sizeof(priv));
		crypto_free_mlkem(keyMat);
		return NULL;
	}

	uint8_t pub[MLKEMParameters::ML_KEM_1024_PUB_LENGTH];
    size_t pub_len;
	rv = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                    pub, sizeof(pub), &pub_len);

	if(!rv)
	{
		fprintf(stderr, "ERROR: Could not get ML-KEM public key, rv: %d\n", rv);
		memset(seed, 0, sizeof(seed));
		memset(priv, 0, sizeof(priv));
		memset(pub, 0, sizeof(pub));
		crypto_free_mlkem(keyMat);
		return NULL;
	}

	keyMat->sizeSeed = seed_len;
	keyMat->sizePrivValue = priv_len;
	keyMat->sizePubValue = pub_len;

	if (keyMat->sizeSeed > 0) {
		keyMat->seed = (CK_VOID_PTR)malloc(keyMat->sizeSeed);
	}
	if (keyMat->sizePrivValue > 0) {
		keyMat->privValue = (CK_VOID_PTR)malloc(keyMat->sizePrivValue);
	}
	keyMat->pubValue = (CK_VOID_PTR)malloc(keyMat->sizePubValue);

	if (!keyMat->seed || !keyMat->privValue || !keyMat->pubValue)
	{
		crypto_free_mlkem(keyMat);
		return NULL;
	}

	switch (keyMat->sizePrivValue)
	{
		case MLKEMParameters::ML_KEM_512_PRIV_LENGTH:
			keyMat->parameterSet = MLKEMParameters::ML_KEM_512_PARAMETER_SET;
			break;

		case MLKEMParameters::ML_KEM_768_PRIV_LENGTH:
			keyMat->parameterSet = MLKEMParameters::ML_KEM_768_PARAMETER_SET;
			break;

		case MLKEMParameters::ML_KEM_1024_PRIV_LENGTH:
			keyMat->parameterSet = MLKEMParameters::ML_KEM_1024_PARAMETER_SET;
			break;

		default:
			crypto_free_mlkem(keyMat);
			return NULL;
	}

	if (keyMat->seed) {
		memcpy(keyMat->seed, seed, keyMat->sizeSeed);
	}
	if (keyMat->privValue) {
		memcpy(keyMat->privValue, priv, keyMat->sizePrivValue);
	}
	memcpy(keyMat->pubValue, pub, keyMat->sizePubValue);

	return keyMat;
}

// Free the memory of the key
void crypto_free_mlkem(mlkem_key_material_t* keyMat)
{
	if (keyMat == NULL) return;
	if (keyMat->seed) free(keyMat->seed);
	if (keyMat->privValue) free(keyMat->privValue);
	if (keyMat->pubValue) free(keyMat->pubValue);
	free(keyMat);
}

#endif

#ifdef WITH_FALCON
// Save the key data in PKCS#11.
int crypto_save_falcon(CK_SESSION_HANDLE hSession, char* label, char* objID,
	size_t objIDLen, int noPublicKey, EVP_PKEY* falcon)
{
	OSSLFalconPrivateKey privateKey;
	OSSLFalconPublicKey publicKey;
	publicKey.setFromOSSL(falcon);
	if (!privateKey.setFromOSSL(falcon) || publicKey.getValue().size() == 0)
	{
		fprintf(stderr, "ERROR: Could not convert the Falcon key material to binary information.\n");
		return 1;
	}

	ByteString privateValue = privateKey.getValue();
	ByteString publicValue = publicKey.getValue();
	ByteString publicKeyInfo = privateKey.getPublicKeyInfo();
	CK_ULONG parameterSet = privateKey.getParameterSet();
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_FALCON;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
	CK_BBOOL ckToken = noPublicKey ? CK_FALSE : CK_TRUE;
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, label, strlen(label) },
		{ CKA_ID, objID, objIDLen },
		{ CKA_TOKEN, &ckToken, sizeof(ckToken) },
		{ CKA_VERIFY, &ckTrue, sizeof(ckTrue) },
		{ CKA_ENCRYPT, &ckFalse, sizeof(ckFalse) },
		{ CKA_WRAP, &ckFalse, sizeof(ckFalse) },
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_VALUE, publicValue.byte_str(), publicValue.size() }
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, label, strlen(label) },
		{ CKA_ID, objID, objIDLen },
		{ CKA_SIGN, &ckTrue, sizeof(ckTrue) },
		{ CKA_DECRYPT, &ckFalse, sizeof(ckFalse) },
		{ CKA_UNWRAP, &ckFalse, sizeof(ckFalse) },
		{ CKA_SENSITIVE, &ckTrue, sizeof(ckTrue) },
		{ CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
		{ CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
		{ CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_PUBLIC_KEY_INFO, publicKeyInfo.byte_str(), publicKeyInfo.size() },
		{ CKA_VALUE, privateValue.byte_str(), privateValue.size() }
	};

	CK_OBJECT_HANDLE hPrivateKey, hPublicKey;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate,
		sizeof(privTemplate) / sizeof(CK_ATTRIBUTE), &hPrivateKey);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
			"Maybe the algorithm is not supported.\n");
		return 1;
	}
	rv = p11->C_CreateObject(hSession, pubTemplate,
		sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE), &hPublicKey);
	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hPrivateKey);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The Falcon key pair with label=%s has been imported.\n", label);
	return 0;
}
#endif
