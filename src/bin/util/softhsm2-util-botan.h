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
 softhsm2-util-botan.h

 Header file for Botan implemented
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SOFTHSM2_UTIL_BOTAN_H
#define _SOFTHSM_V2_SOFTHSM2_UTIL_BOTAN_H

#include <botan/rsa.h>
#include <botan/dsa.h>
#ifdef WITH_ECC
#include <botan/ecdsa.h>
#endif
#ifdef WITH_EDDSA
#include <botan/curve25519.h>
#include <botan/ed25519.h>
// #include <botan/curve448.h>
// #include <botan/ed448.h>
#endif

typedef struct rsa_key_material_t {
	CK_ULONG sizeE;
	CK_ULONG sizeN;
	CK_ULONG sizeD;
	CK_ULONG sizeP;
	CK_ULONG sizeQ;
	CK_ULONG sizeDMP1;
	CK_ULONG sizeDMQ1;
	CK_ULONG sizeIQMP;
	CK_VOID_PTR bigE;
	CK_VOID_PTR bigN;
	CK_VOID_PTR bigD;
	CK_VOID_PTR bigP;
	CK_VOID_PTR bigQ;
	CK_VOID_PTR bigDMP1;
	CK_VOID_PTR bigDMQ1;
	CK_VOID_PTR bigIQMP;
	rsa_key_material_t() {
		sizeE = 0;
		sizeN = 0;
		sizeD = 0;
		sizeP = 0;
		sizeQ = 0;
		sizeDMP1 = 0;
		sizeDMQ1 = 0;
		sizeIQMP = 0;
		bigE = NULL_PTR;
		bigN = NULL_PTR;
		bigD = NULL_PTR;
		bigP = NULL_PTR;
		bigQ = NULL_PTR;
		bigDMP1 = NULL_PTR;
		bigDMQ1 = NULL_PTR;
		bigIQMP = NULL_PTR;
	}
} rsa_key_material_t;

typedef struct dsa_key_material_t {
	CK_ULONG sizeP;
	CK_ULONG sizeQ;
	CK_ULONG sizeG;
	CK_ULONG sizeX;
	CK_ULONG sizeY;
	CK_VOID_PTR bigP;
	CK_VOID_PTR bigQ;
	CK_VOID_PTR bigG;
	CK_VOID_PTR bigX;
	CK_VOID_PTR bigY;
	dsa_key_material_t() {
		sizeP = 0;
		sizeQ = 0;
		sizeG = 0;
		sizeX = 0;
		sizeY = 0;
		bigP = NULL_PTR;
		bigQ = NULL_PTR;
		bigG = NULL_PTR;
		bigX = NULL_PTR;
		bigY = NULL_PTR;
	}
} dsa_key_material_t;

#ifdef WITH_ECC
typedef struct ecdsa_key_material_t {
	CK_ULONG sizeParams;
	CK_ULONG sizeD;
	CK_ULONG sizeQ;
	CK_VOID_PTR derParams;
	CK_VOID_PTR bigD;
	CK_VOID_PTR derQ;
	ecdsa_key_material_t() {
		sizeParams = 0;
		sizeD = 0;
		sizeQ = 0;
		derParams = NULL_PTR;
		bigD = NULL_PTR;
		derQ = NULL_PTR;
	}
} ecdsa_key_material_t;
#endif

#ifdef WITH_EDDSA
typedef struct eddsa_key_material_t {
	CK_ULONG sizeOID;
	CK_ULONG sizeK;
	CK_ULONG sizeA;
	CK_VOID_PTR derOID;
	CK_VOID_PTR bigK;
	CK_VOID_PTR bigA;
	eddsa_key_material_t() {
		sizeOID = 0;
		sizeK = 0;
		sizeA = 0;
		derOID = NULL_PTR;
		bigK = NULL_PTR;
		bigA = NULL_PTR;
	}
} eddsa_key_material_t;
#endif

Botan::Private_Key* crypto_read_file(char* filePath, char* filePIN);

// RSA
int crypto_save_rsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, Botan::RSA_PrivateKey* rsa);
rsa_key_material_t* crypto_malloc_rsa(Botan::RSA_PrivateKey* rsa);
void crypto_free_rsa(rsa_key_material_t* keyMat);

// DSA
int crypto_save_dsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, Botan::DSA_PrivateKey* dsa);
dsa_key_material_t* crypto_malloc_dsa(Botan::DSA_PrivateKey* dsa);
void crypto_free_dsa(dsa_key_material_t* keyMat);

// ECDSA
#ifdef WITH_ECC
int crypto_save_ecdsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, Botan::ECDSA_PrivateKey* ecdsa);
ecdsa_key_material_t* crypto_malloc_ecdsa(Botan::ECDSA_PrivateKey* ecdsa);
void crypto_free_ecdsa(ecdsa_key_material_t* keyMat);
#endif

// EDDSA
#ifdef WITH_EDDSA
int crypto_save_eddsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, Botan::Curve25519_PrivateKey* x25519, Botan::Ed25519_PrivateKey* ed25519);
eddsa_key_material_t* crypto_malloc_eddsa(Botan::Curve25519_PrivateKey* x25519, Botan::Ed25519_PrivateKey* ed25519);
void crypto_free_eddsa(eddsa_key_material_t* keyMat);
#endif

#endif // !_SOFTHSM_V2_SOFTHSM2_UTIL_BOTAN_H
