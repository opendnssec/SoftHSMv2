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
 softhsm2-util-botan.cpp

 Code specific for Botan
 *****************************************************************************/

#include <config.h>
#define UTIL_BOTAN
#include "softhsm2-util.h"
#include "softhsm2-util-botan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <botan/init.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/bigint.h>
#include <botan/version.h>
#include <botan/der_enc.h>
#include <botan/oids.h>

#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,14)
#include <botan/libstate.h>
bool wasInitialized = false;
#endif

// Init Botan
void crypto_init()
{
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,14)
	// The PKCS#11 library might be using Botan
	// Check if it has already initialized Botan
	if (Botan::Global_State_Management::global_state_exists())
	{
		wasInitialized = true;
	}

	if (!wasInitialized)
	{
		Botan::LibraryInitializer::initialize("thread_safe=true");
	}
#else
	Botan::LibraryInitializer::initialize("thread_safe=true");
#endif
}

// Final Botan
void crypto_final()
{
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,14)
	if (!wasInitialized)
	{
		Botan::LibraryInitializer::deinitialize();
	}
#else
	Botan::LibraryInitializer::deinitialize();
#endif
}

// Import a aes secret key from given path
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
	Botan::Private_Key* pkey = crypto_read_file(filePath, filePIN);
	if (pkey == NULL)
	{
		return 1;
	}

	Botan::RSA_PrivateKey* rsa = NULL;
	Botan::DSA_PrivateKey* dsa = NULL;
#ifdef WITH_ECC
	Botan::ECDSA_PrivateKey* ecdsa = NULL;
#endif
#ifdef WITH_EDDSA
	Botan::Curve25519_PrivateKey* x25519 = NULL;
	Botan::Ed25519_PrivateKey* ed25519 = NULL;
#endif

	if (pkey->algo_name().compare("RSA") == 0)
	{
		rsa = dynamic_cast<Botan::RSA_PrivateKey*>(pkey);
	}
	else if (pkey->algo_name().compare("DSA") == 0)
	{
		dsa = dynamic_cast<Botan::DSA_PrivateKey*>(pkey);
	}
#ifdef WITH_ECC
	else if (pkey->algo_name().compare("ECDSA") == 0)
	{
		ecdsa = dynamic_cast<Botan::ECDSA_PrivateKey*>(pkey);
	}
#endif
#ifdef WITH_EDDSA
	else if (pkey->algo_name().compare("Curve25519") == 0)
	{
		x25519 = dynamic_cast<Botan::Curve25519_PrivateKey*>(pkey);
	}
	else if (pkey->algo_name().compare("Ed25519") == 0)
	{
		ed25519 = dynamic_cast<Botan::Ed25519_PrivateKey*>(pkey);
	}
#endif
	else
	{
		fprintf(stderr, "ERROR: %s is not a supported algorithm.\n",
				pkey->algo_name().c_str());
		delete pkey;
		return 1;
	}

	int result = 0;

	if (rsa)
	{
		result = crypto_save_rsa(hSession, label, objID, objIDLen, noPublicKey, rsa);
	}
	else if (dsa)
	{
		result = crypto_save_dsa(hSession, label, objID, objIDLen, noPublicKey, dsa);
	}
#ifdef WITH_ECC
	else if (ecdsa)
	{
		result = crypto_save_ecdsa(hSession, label, objID, objIDLen, noPublicKey, ecdsa);
	}
#endif
#ifdef WITH_EDDSA
	else if (x25519)
	{
		result = crypto_save_eddsa(hSession, label, objID, objIDLen, noPublicKey, x25519, 0);
	}
	else if (ed25519)
	{
		result = crypto_save_eddsa(hSession, label, objID, objIDLen, noPublicKey, 0, ed25519);
	}
#endif
	else
	{
		fprintf(stderr, "ERROR: Could not get the key material.\n");
		result = 1;
	}

	delete pkey;
	return result;
}

// Read the key from file
Botan::Private_Key* crypto_read_file(char* filePath, char* filePIN)
{
	if (filePath == NULL)
	{
		return NULL;
	}

	Botan::AutoSeeded_RNG* rng = new Botan::AutoSeeded_RNG();
	Botan::Private_Key* pkey = NULL;

	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
		if (filePIN == NULL)
		{
			pkey = Botan::PKCS8::load_key(std::string(filePath), *rng);
		}
		else
		{
			pkey = Botan::PKCS8::load_key(std::string(filePath), *rng, std::string(filePIN));
		}
#else
		if (filePIN == NULL)
		{
			pkey = Botan::PKCS8::load_key(filePath, *rng);
		}
		else
		{
			pkey = Botan::PKCS8::load_key(filePath, *rng, filePIN);
		}
#endif
	}
	catch (std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Perhaps wrong path to file, wrong file format, "
				"or wrong PIN to file (--file-pin <PIN>).\n");
		delete rng;
		return NULL;
	}
	delete rng;

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
	Botan::RSA_PrivateKey* rsa
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

// Convert the Botan key to binary
rsa_key_material_t* crypto_malloc_rsa(Botan::RSA_PrivateKey* rsa)
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

	keyMat->sizeE = rsa->get_e().bytes();
	keyMat->sizeN = rsa->get_n().bytes();
	keyMat->sizeD = rsa->get_d().bytes();
	keyMat->sizeP = rsa->get_p().bytes();
	keyMat->sizeQ = rsa->get_q().bytes();
	keyMat->sizeDMP1 = rsa->get_d1().bytes();
	keyMat->sizeDMQ1 = rsa->get_d2().bytes();
	keyMat->sizeIQMP = rsa->get_c().bytes();

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

	rsa->get_e().binary_encode((Botan::byte*)keyMat->bigE);
	rsa->get_n().binary_encode((Botan::byte*)keyMat->bigN);
	rsa->get_d().binary_encode((Botan::byte*)keyMat->bigD);
	rsa->get_p().binary_encode((Botan::byte*)keyMat->bigP);
	rsa->get_q().binary_encode((Botan::byte*)keyMat->bigQ);
	rsa->get_d1().binary_encode((Botan::byte*)keyMat->bigDMP1);
	rsa->get_d2().binary_encode((Botan::byte*)keyMat->bigDMQ1);
	rsa->get_c().binary_encode((Botan::byte*)keyMat->bigIQMP);

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
	Botan::DSA_PrivateKey* dsa
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

// Convert the Botan key to binary
dsa_key_material_t* crypto_malloc_dsa(Botan::DSA_PrivateKey* dsa)
{
	if (dsa == NULL)
	{
		return NULL;
	}

	dsa_key_material_t *keyMat = (dsa_key_material_t *)malloc(sizeof(dsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	keyMat->sizeP = dsa->group_p().bytes();
	keyMat->sizeQ = dsa->group_q().bytes();
	keyMat->sizeG = dsa->group_g().bytes();
	keyMat->sizeX = dsa->get_x().bytes();
	keyMat->sizeY = dsa->get_y().bytes();

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

	dsa->group_p().binary_encode((Botan::byte*)keyMat->bigP);
	dsa->group_q().binary_encode((Botan::byte*)keyMat->bigQ);
	dsa->group_g().binary_encode((Botan::byte*)keyMat->bigG);
	dsa->get_x().binary_encode((Botan::byte*)keyMat->bigX);
	dsa->get_y().binary_encode((Botan::byte*)keyMat->bigY);

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
	Botan::ECDSA_PrivateKey* ecdsa
)
{
	ecdsa_key_material_t* keyMat = crypto_malloc_ecdsa(ecdsa);
	if (keyMat == NULL)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_ECDSA;
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
		{ CKA_EC_POINT,       keyMat->derQ,      keyMat->sizeQ }
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

// Convert the Botan key to binary
ecdsa_key_material_t* crypto_malloc_ecdsa(Botan::ECDSA_PrivateKey* ecdsa)
{
	if (ecdsa == NULL)
	{
		return NULL;
	}

	ecdsa_key_material_t *keyMat = (ecdsa_key_material_t *)malloc(sizeof(ecdsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	std::vector<Botan::byte> derEC = ecdsa->domain().DER_encode(Botan::EC_DOMPAR_ENC_OID);
	Botan::secure_vector<Botan::byte> derPoint;
#else
	Botan::SecureVector<Botan::byte> derEC = ecdsa->domain().DER_encode(Botan::EC_DOMPAR_ENC_OID);
	Botan::SecureVector<Botan::byte> derPoint;
#endif

	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
		Botan::secure_vector<Botan::byte> repr = Botan::EC2OSP(ecdsa->public_point(),
			Botan::PointGFp::UNCOMPRESSED);
#else
		Botan::SecureVector<Botan::byte> repr = Botan::EC2OSP(ecdsa->public_point(),
			Botan::PointGFp::UNCOMPRESSED);
#endif

		derPoint = Botan::DER_Encoder()
			.encode(repr, Botan::OCTET_STRING)
			.get_contents();
        }
	catch (...)
	{
		return NULL;
	}

	keyMat->sizeParams = derEC.size();
	keyMat->sizeD = ecdsa->private_value().bytes();
	keyMat->sizeQ = derPoint.size();

	keyMat->derParams = (CK_VOID_PTR)malloc(keyMat->sizeParams);
	keyMat->bigD = (CK_VOID_PTR)malloc(keyMat->sizeD);
	keyMat->derQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);

	if (!keyMat->derParams || !keyMat->bigD || !keyMat->derQ)
	{
		crypto_free_ecdsa(keyMat);
		return NULL;
	}

	memcpy(keyMat->derParams, &derEC[0], derEC.size());
	ecdsa->private_value().binary_encode((Botan::byte*)keyMat->bigD);
	memcpy(keyMat->derQ, &derPoint[0], derPoint.size());

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
	Botan::Curve25519_PrivateKey* x25519,
	Botan::Ed25519_PrivateKey* ed25519
)
{
	eddsa_key_material_t* keyMat = crypto_malloc_eddsa(x25519, ed25519);
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
eddsa_key_material_t* crypto_malloc_eddsa
(
	Botan::Curve25519_PrivateKey* x25519,
	Botan::Ed25519_PrivateKey* ed25519
 )
{
	if ((x25519 == NULL) && (ed25519 == NULL))
	{
		return NULL;
	}

	eddsa_key_material_t* keyMat = (eddsa_key_material_t*)malloc(sizeof(eddsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	Botan::OID oid;
	if (x25519) oid = Botan::OIDS::lookup("Curve25519");
	if (ed25519) oid = Botan::OIDS::lookup("Ed25519");
	if (oid.empty())
	{
		return NULL;
	}

	Botan::secure_vector<Botan::byte> derOID;
	derOID = Botan::DER_Encoder().encode(oid).get_contents();

	memset(keyMat, 0, sizeof(*keyMat));
	keyMat->sizeOID = derOID.size();
	keyMat->derOID = (CK_VOID_PTR)malloc(keyMat->sizeOID);

	std::vector<Botan::byte> pub;
	if (x25519) pub = x25519->public_value();
	if (ed25519) pub = ed25519->get_public_key();
	keyMat->sizeA = pub.size();
	keyMat->bigA = (CK_VOID_PTR)malloc(keyMat->sizeA);

	Botan::secure_vector<Botan::byte> priv;
	if (x25519) priv = x25519->get_x();
	if (ed25519)
	{
		priv = ed25519->get_private_key();
		priv.resize(32);
	}
	keyMat->sizeK = priv.size();
	keyMat->bigK = (CK_VOID_PTR)malloc(keyMat->sizeK);

	if (!keyMat->derOID || !keyMat->bigK || !keyMat->bigA)
	{
		crypto_free_eddsa(keyMat);
		return NULL;
	}

	memcpy(keyMat->derOID, derOID.data(), keyMat->sizeOID);
	memcpy(keyMat->bigA, pub.data(), keyMat->sizeA);
	memcpy(keyMat->bigK, priv.data(), keyMat->sizeK);

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
