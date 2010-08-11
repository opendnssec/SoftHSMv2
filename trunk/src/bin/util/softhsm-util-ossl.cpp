/* $Id$ */

/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
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
 softhsm-util-ossl.cpp

 Code specific for OpenSSL
 *****************************************************************************/

#include <config.h>
#include "softhsm-util.h"
#include "softhsm-util-ossl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

// Init OpenSSL
void crypto_init()
{
	// We do not need to do this one
	// OpenSSL_add_all_algorithms();
}
  
// Final OpenSSL
void crypto_final()
{
	// EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

// Import a key pair from given path
int crypto_import_key_pair
(
	CK_SESSION_HANDLE hSession,
	char *filePath,
	char *filePIN,
	char *label,
	char *objID,
	int objIDLen,
	int noPublicKey
)
{
	EVP_PKEY *pkey = crypto_read_file(filePath, filePIN);
	if (!pkey)
	{
		return 1;
	}

	RSA *rsa = NULL;
	DSA *dsa = NULL;

	switch (EVP_PKEY_type(pkey->type))
	{
		case EVP_PKEY_RSA:
			rsa = EVP_PKEY_get1_RSA(pkey);
			break;
		case EVP_PKEY_DSA:
			dsa = EVP_PKEY_get1_DSA(pkey);
			break;
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
	else
	{
		fprintf(stderr, "ERROR: Could not get the key material.\n");
		result = 1;
	}

	return result;
}

// Read the key from file
EVP_PKEY* crypto_read_file(char* filePath, char *filePIN)
{
	BIO *in = NULL;
	PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	EVP_PKEY *pkey = NULL;
	X509_SIG *p8 = NULL;

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

	if (p8inf->broken)
	{
		fprintf(stderr, "ERROR: Broken key encoding.\n");
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return NULL;
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
	char *label,
	char *objID,
	int objIDLen,
	int noPublicKey,
	RSA *rsa
)
{
	rsa_key_material_t *keyMat = crypto_malloc_rsa(rsa);
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
		{ CKA_ENCRYPT,          &ckFalse,     sizeof(ckFalse) },
		{ CKA_WRAP,             &ckFalse,     sizeof(ckFalse) },
		{ CKA_PUBLIC_EXPONENT,  keyMat->bigE, keyMat->sizeE },
		{ CKA_MODULUS,          keyMat->bigN, keyMat->sizeN }
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,            &privClass,      sizeof(privClass) },
		{ CKA_KEY_TYPE,         &keyType,        sizeof(keyType) },
		{ CKA_LABEL,            label,           strlen(label) },
		{ CKA_ID,               objID,           objIDLen },
		{ CKA_SIGN,             &ckTrue,         sizeof(ckTrue) },
		{ CKA_DECRYPT,          &ckFalse,        sizeof(ckFalse) },
		{ CKA_UNWRAP,           &ckFalse,        sizeof(ckFalse) },
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
rsa_key_material_t* crypto_malloc_rsa(RSA *rsa)
{
	if (!rsa)
	{
		return NULL;
	}

	rsa_key_material_t *keyMat = (rsa_key_material_t *)malloc(sizeof(rsa_key_material_t));
	if (!keyMat)
	{
		return NULL;
	}

	keyMat->sizeE = BN_num_bytes(rsa->e);
	keyMat->sizeN = BN_num_bytes(rsa->n);
	keyMat->sizeD = BN_num_bytes(rsa->d);
	keyMat->sizeP = BN_num_bytes(rsa->p);
	keyMat->sizeQ = BN_num_bytes(rsa->q);
	keyMat->sizeDMP1 = BN_num_bytes(rsa->dmp1);
	keyMat->sizeDMQ1 = BN_num_bytes(rsa->dmq1);
	keyMat->sizeIQMP = BN_num_bytes(rsa->iqmp);

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

	BN_bn2bin(rsa->e, (unsigned char*)keyMat->bigE);
	BN_bn2bin(rsa->n, (unsigned char*)keyMat->bigN);
	BN_bn2bin(rsa->d, (unsigned char*)keyMat->bigD);
	BN_bn2bin(rsa->p, (unsigned char*)keyMat->bigP);
	BN_bn2bin(rsa->q, (unsigned char*)keyMat->bigQ);
	BN_bn2bin(rsa->dmp1, (unsigned char*)keyMat->bigDMP1);
	BN_bn2bin(rsa->dmq1, (unsigned char*)keyMat->bigDMQ1);
	BN_bn2bin(rsa->iqmp, (unsigned char*)keyMat->bigIQMP);

	return keyMat;
}

// Free the memory of the key
void crypto_free_rsa(rsa_key_material_t *keyMat)
{
	if (!keyMat) return;
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
	char *label,
	char *objID,
	int objIDLen,
	int noPublicKey,
	DSA *dsa
)
{
	dsa_key_material_t *keyMat = crypto_malloc_dsa(dsa);
	if (!keyMat)
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
dsa_key_material_t* crypto_malloc_dsa(DSA *dsa)
{
	if (!dsa)
	{
		return NULL;
	}

	dsa_key_material_t *keyMat = (dsa_key_material_t *)malloc(sizeof(dsa_key_material_t));
	if (!keyMat)
	{
		return NULL;
	}

	keyMat->sizeP = BN_num_bytes(dsa->p);
	keyMat->sizeQ = BN_num_bytes(dsa->q);
	keyMat->sizeG = BN_num_bytes(dsa->g);
	keyMat->sizeX = BN_num_bytes(dsa->priv_key);
	keyMat->sizeY = BN_num_bytes(dsa->pub_key);

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

	BN_bn2bin(dsa->p, (unsigned char*)keyMat->bigP);
	BN_bn2bin(dsa->q, (unsigned char*)keyMat->bigQ);
	BN_bn2bin(dsa->g, (unsigned char*)keyMat->bigG);
	BN_bn2bin(dsa->priv_key, (unsigned char*)keyMat->bigX);
	BN_bn2bin(dsa->pub_key, (unsigned char*)keyMat->bigY);

	return keyMat;
}

// Free the memory of the key
void crypto_free_dsa(dsa_key_material_t *keyMat)
{
	if (!keyMat) return;
	if (keyMat->bigP) free(keyMat->bigP);
	if (keyMat->bigQ) free(keyMat->bigQ);
	if (keyMat->bigG) free(keyMat->bigG);
	if (keyMat->bigX) free(keyMat->bigX);
	if (keyMat->bigY) free(keyMat->bigY);
	free(keyMat);
}
