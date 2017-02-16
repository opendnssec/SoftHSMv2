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
 softhsm2-keyconv-botan.cpp

 Code specific for Botan
 *****************************************************************************/

#include <config.h>
#define KEYCONV_BOTAN
#include "softhsm2-keyconv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <botan/init.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/bigint.h>
#include <botan/version.h>

// Init Botan
void crypto_init()
{
	Botan::LibraryInitializer::initialize();
}

// Final Botan
void crypto_final()
{
	Botan::LibraryInitializer::deinitialize();
}

// Save the RSA key as a PKCS#8 file
int save_rsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey)
{
	int result = 0;
	Botan::Private_Key* priv_key = NULL;
	Botan::AutoSeeded_RNG* rng = NULL;
	Botan::BigInt bigE, bigP, bigQ, bigN, bigD;

	// See if the key material was found.
	if
	(
		pkey[TAG_MODULUS].size <= 0 ||
		pkey[TAG_PUBEXP].size <= 0 ||
                pkey[TAG_PRIVEXP].size <= 0 ||
		pkey[TAG_PRIME1].size <= 0 ||
		pkey[TAG_PRIME2].size <= 0
	)
	{
		fprintf(stderr, "ERROR: Some parts of the key material is missing in the input file.\n");
		return 1;
	}

	bigE = Botan::BigInt((Botan::byte*)pkey[TAG_PUBEXP].big,  pkey[TAG_PUBEXP].size);
	bigP = Botan::BigInt((Botan::byte*)pkey[TAG_PRIME1].big,  pkey[TAG_PRIME1].size);
	bigQ = Botan::BigInt((Botan::byte*)pkey[TAG_PRIME2].big,  pkey[TAG_PRIME2].size);
	bigN = Botan::BigInt((Botan::byte*)pkey[TAG_MODULUS].big, pkey[TAG_MODULUS].size);
	bigD = Botan::BigInt((Botan::byte*)pkey[TAG_PRIVEXP].big, pkey[TAG_PRIVEXP].size);

	rng = new Botan::AutoSeeded_RNG();

	try
	{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,34)
		priv_key = new Botan::RSA_PrivateKey(bigP, bigQ, bigE, bigD, bigN);
#else
		priv_key = new Botan::RSA_PrivateKey(*rng, bigP, bigQ, bigE, bigD, bigN);
#endif
	}
	catch(std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not extract the private key from the file.\n");
		delete rng;
		return 1;
	}

	std::ofstream priv_file(out_path);
	if (!priv_file.is_open())
	{
		fprintf(stderr, "ERROR: Could not open file for output.\n");
		delete rng;
		delete priv_key;
		return 1;
	}

	try
	{
		if (file_pin == NULL)
		{
			priv_file << Botan::PKCS8::PEM_encode(*priv_key);
		}
		else
		{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
			priv_file << Botan::PKCS8::PEM_encode(*priv_key, *rng, file_pin, std::chrono::milliseconds(300), "PBE-PKCS5v15(MD5,DES/CBC)");
#else
			priv_file << Botan::PKCS8::PEM_encode(*priv_key, *rng, file_pin, "PBE-PKCS5v15(MD5,DES/CBC)");
#endif
		}

		printf("The key has been written to %s\n", out_path);
	}
	catch(std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not write to file.\n");
		result = 1;
	}

	delete rng;
	delete priv_key;
	priv_file.close();

	return result;
}

// Save the DSA key as a PKCS#8 file
int save_dsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey)
{
	int result = 0;
	Botan::Private_Key* priv_key = NULL;
	Botan::AutoSeeded_RNG* rng = NULL;
	Botan::BigInt bigDP, bigDQ, bigDG, bigDX;

	// See if the key material was found.
	if
	(
		pkey[TAG_PRIME].size <= 0 ||
		pkey[TAG_SUBPRIME].size <= 0 ||
		pkey[TAG_BASE].size <= 0 ||
		pkey[TAG_PRIVVAL].size <= 0
	)
	{
		fprintf(stderr, "ERROR: Some parts of the key material is missing in the input file.\n");
		return 1;
	}

	bigDP = Botan::BigInt((Botan::byte*)pkey[TAG_PRIME].big,    pkey[TAG_PRIME].size);
	bigDQ = Botan::BigInt((Botan::byte*)pkey[TAG_SUBPRIME].big, pkey[TAG_SUBPRIME].size);
	bigDG = Botan::BigInt((Botan::byte*)pkey[TAG_BASE].big,     pkey[TAG_BASE].size);
	bigDX = Botan::BigInt((Botan::byte*)pkey[TAG_PRIVVAL].big,  pkey[TAG_PRIVVAL].size);

	rng = new Botan::AutoSeeded_RNG();

	try
	{
		priv_key = new Botan::DSA_PrivateKey(*rng, Botan::DL_Group(bigDP, bigDQ, bigDG), bigDX);
	}
	catch (std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not extract the private key from the file.\n");
		delete rng;
		return 1;
	}

	std::ofstream priv_file(out_path);
	if (!priv_file.is_open())
	{
		fprintf(stderr, "ERROR: Could not open file for output.\n");
		delete rng;
		delete priv_key;
		return 1;
	}

	try
	{
		if (file_pin == NULL)
		{
			priv_file << Botan::PKCS8::PEM_encode(*priv_key);
		}
		else
		{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
			priv_file << Botan::PKCS8::PEM_encode(*priv_key, *rng, file_pin, std::chrono::milliseconds(300), "PBE-PKCS5v15(MD5,DES/CBC)");
#else
			priv_file << Botan::PKCS8::PEM_encode(*priv_key, *rng, file_pin, "PBE-PKCS5v15(MD5,DES/CBC)");
#endif
		}

		printf("The key has been written to %s\n", out_path);
	}
	catch (std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not write to file.\n");
		result = 1;
	}

	delete rng;
	delete priv_key;
	priv_file.close();

	return result;
}
