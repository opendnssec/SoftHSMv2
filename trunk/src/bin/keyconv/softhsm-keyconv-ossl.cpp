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
 softhsm-keyconv-ossl.cpp

 Code specific for OpenSSL
 *****************************************************************************/

#include <config.h>
#include "softhsm-keyconv.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>

// Init OpenSSL
void crypto_init()
{
	OpenSSL_add_all_algorithms();
}

// Final OpenSSL
void crypto_final()
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

// Save the RSA key as a PKCS#8 file
int save_rsa_pkcs8(char *out_path, char *file_pin, key_material_t *pkey)
{
	RSA *rsa = NULL;
	EVP_PKEY *ossl_pkey;
	PKCS8_PRIV_KEY_INFO *p8inf;
	BIO *out = NULL;
	X509_SIG *p8;
	int result = 0;

	// See if the key material was found.
	if
	(
		pkey[TAG_MODULUS].size <= 0 ||
		pkey[TAG_PUBEXP].size <= 0 ||
		pkey[TAG_PRIVEXP].size <= 0 ||
		pkey[TAG_PRIME1].size <= 0 ||
		pkey[TAG_PRIME2].size <= 0 ||
		pkey[TAG_EXP1].size <= 0 ||
		pkey[TAG_EXP2].size <= 0 ||
		pkey[TAG_COEFF].size <= 0
	)
	{
		fprintf(stderr, "ERROR: Some parts of the key material is missing in the input file.\n");
		return 1;
	}

	rsa = RSA_new();
	rsa->p =    BN_bin2bn((unsigned char*)pkey[TAG_PRIME1].big,  pkey[TAG_PRIME1].size, NULL);
	rsa->q =    BN_bin2bn((unsigned char*)pkey[TAG_PRIME2].big,  pkey[TAG_PRIME2].size, NULL);
	rsa->d =    BN_bin2bn((unsigned char*)pkey[TAG_PRIVEXP].big, pkey[TAG_PRIVEXP].size, NULL);
	rsa->n =    BN_bin2bn((unsigned char*)pkey[TAG_MODULUS].big, pkey[TAG_MODULUS].size, NULL);
	rsa->e =    BN_bin2bn((unsigned char*)pkey[TAG_PUBEXP].big,  pkey[TAG_PUBEXP].size, NULL);
	rsa->dmp1 = BN_bin2bn((unsigned char*)pkey[TAG_EXP1].big,    pkey[TAG_EXP1].size, NULL);
	rsa->dmq1 = BN_bin2bn((unsigned char*)pkey[TAG_EXP2].big,    pkey[TAG_EXP2].size, NULL);
	rsa->iqmp = BN_bin2bn((unsigned char*)pkey[TAG_COEFF].big,   pkey[TAG_COEFF].size, NULL);

	ossl_pkey = EVP_PKEY_new();

	// Convert RSA to EVP_PKEY
	if (!EVP_PKEY_set1_RSA(ossl_pkey, rsa))
	{
		fprintf(stderr, "ERROR: Could not convert RSA key to EVP_PKEY.\n");
		RSA_free(rsa);
		EVP_PKEY_free(ossl_pkey);
		return 1;
	}
	RSA_free(rsa);

	// Convert EVP_PKEY to PKCS#8
	if (!(p8inf = EVP_PKEY2PKCS8(ossl_pkey)))
	{
		fprintf(stderr, "ERROR: Could not convert EVP_PKEY to PKCS#8.\n");
		EVP_PKEY_free(ossl_pkey);
		return 1;
	}
	EVP_PKEY_free(ossl_pkey);

	// Open output file
	if (!(out = BIO_new_file (out_path, "wb")))
	{
		fprintf(stderr, "ERROR: Could not open the output file.\n");
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return 1;
	}

	// Write to disk
	if (file_pin == NULL)
	{
		PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);
		printf("The key has been written to %s\n", out_path);
	}
	else
	{
		// Encrypt p8
		if (!(p8 = PKCS8_encrypt(NID_pbeWithMD5AndDES_CBC, NULL,
					file_pin, strlen(file_pin), NULL, 
					0, PKCS12_DEFAULT_ITER, p8inf)))
		{
			fprintf(stderr, "ERROR: Could not encrypt the PKCS#8 file\n");
			result = 1;
		}
		else
		{
			PEM_write_bio_PKCS8(out, p8);
			X509_SIG_free(p8);
			printf("The key has been written to %s\n", out_path);
		}
	}

	PKCS8_PRIV_KEY_INFO_free(p8inf);
	BIO_free_all(out);

	return result;
}

// Save the DSA key as a PKCS#8 file
int save_dsa_pkcs8(char *out_path, char *file_pin, key_material_t *pkey)
{
	DSA *dsa;
	EVP_PKEY *ossl_pkey;
	PKCS8_PRIV_KEY_INFO *p8inf;
	BIO *out = NULL;
	X509_SIG *p8;
	int result = 0;

	// See if the key material was found.
	if
	(
		pkey[TAG_PRIME].size <= 0 ||
		pkey[TAG_SUBPRIME].size <= 0 ||
		pkey[TAG_BASE].size <= 0 ||
		pkey[TAG_PRIVVAL].size <= 0 ||
		pkey[TAG_PUBVAL].size <= 0
	)
	{
		fprintf(stderr, "ERROR: Some parts of the key material is missing in the input file.\n");
		return 1;
	}

	dsa = DSA_new();
	dsa->p =        BN_bin2bn((unsigned char*)pkey[TAG_PRIME].big,    pkey[TAG_PRIME].size, NULL);
	dsa->q =        BN_bin2bn((unsigned char*)pkey[TAG_SUBPRIME].big, pkey[TAG_SUBPRIME].size, NULL);
	dsa->g =        BN_bin2bn((unsigned char*)pkey[TAG_BASE].big,     pkey[TAG_BASE].size, NULL);
	dsa->priv_key = BN_bin2bn((unsigned char*)pkey[TAG_PRIVVAL].big,  pkey[TAG_PRIVVAL].size, NULL);
	dsa->pub_key =  BN_bin2bn((unsigned char*)pkey[TAG_PUBVAL].big,   pkey[TAG_PUBVAL].size, NULL);
	ossl_pkey = EVP_PKEY_new();

	// Convert DSA to EVP_PKEY
	if (!EVP_PKEY_set1_DSA(ossl_pkey, dsa))
	{
		fprintf(stderr, "ERROR: Could not convert DSA key to EVP_PKEY.\n");
		DSA_free(dsa);
		EVP_PKEY_free(ossl_pkey);
		return 1;
	}
	DSA_free(dsa);

	// Convert EVP_PKEY to PKCS#8
	if (!(p8inf = EVP_PKEY2PKCS8(ossl_pkey)))
	{
		fprintf(stderr, "ERROR: Could not convert EVP_PKEY to PKCS#8.\n");
		EVP_PKEY_free(ossl_pkey);
		return 1;
	}
	EVP_PKEY_free(ossl_pkey);

	// Open output file
	if (!(out = BIO_new_file (out_path, "wb")))
	{
		fprintf(stderr, "ERROR: Could not open the output file.\n");
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return 1;
	}

	// Write to disk
	if (file_pin == NULL)
	{
		PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);
		printf("The key has been written to %s\n", out_path);
	}
	else
	{
		// Encrypt p8
		if (!(p8 = PKCS8_encrypt(NID_pbeWithMD5AndDES_CBC, NULL,
					file_pin, strlen(file_pin), NULL, 
					0, PKCS12_DEFAULT_ITER, p8inf)))
		{
			fprintf(stderr, "ERROR: Could not encrypt the PKCS#8 file\n");
			result = 1;
		}
		else
		{
			PEM_write_bio_PKCS8(out, p8);
			X509_SIG_free(p8);
			printf("The key has been written to %s\n", out_path);
		}
	}

	PKCS8_PRIV_KEY_INFO_free(p8inf);
	BIO_free_all(out);

	return result;
}
