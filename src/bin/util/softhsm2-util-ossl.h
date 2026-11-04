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
 softhsm2-util-ossl.h

 Header file for OpenSSL implemented
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SOFTHSM2_UTIL_OSSL_H
#define _SOFTHSM_V2_SOFTHSM2_UTIL_OSSL_H

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#ifdef WITH_ECC
#include <openssl/ec.h>
#endif
#if defined(WITH_EDDSA) || defined(WITH_X_WING) || defined(WITH_ML_DSA) || defined(WITH_ML_KEM)
#include <openssl/evp.h>
#endif
#if defined(WITH_ML_DSA) || defined(WITH_ML_KEM)
#include <openssl/core_names.h>
#endif
#ifdef WITH_X_WING
#include <openssl/x509.h>
#endif
#ifdef WITH_ML_DSA
#include "MLDSAParameters.h"
#endif
#ifdef WITH_ML_KEM
#include "MLKEMParameters.h"
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

#ifdef WITH_ML_DSA
typedef struct mldsa_key_material_t {
	CK_ULONG sizeSeed;
	CK_ULONG sizePrivValue;
	CK_ULONG sizePubValue;
	CK_ULONG parameterSet;
	CK_VOID_PTR seed;
	CK_VOID_PTR privValue;
	CK_VOID_PTR pubValue;
	mldsa_key_material_t() {
		sizeSeed = 0;
		sizePrivValue = 0;
		sizePubValue = 0;
		parameterSet = 0;
		seed = NULL_PTR;
		privValue = NULL_PTR;
		pubValue = NULL_PTR;
	}
} mldsa_key_material_t;
#endif

#ifdef WITH_ML_KEM
typedef struct mlkem_key_material_t {
	CK_ULONG sizeSeed;
	CK_ULONG sizePrivValue;
	CK_ULONG sizePubValue;
	CK_ULONG parameterSet;
	CK_VOID_PTR seed;
	CK_VOID_PTR privValue;
	CK_VOID_PTR pubValue;
	mlkem_key_material_t() {
		sizeSeed = 0;
		sizePrivValue = 0;
		sizePubValue = 0;
		parameterSet = 0;
		seed = NULL_PTR;
		privValue = NULL_PTR;
		pubValue = NULL_PTR;
	}
} mlkem_key_material_t;
#endif

// RSA
int crypto_save_rsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, RSA* rsa);
rsa_key_material_t* crypto_malloc_rsa(RSA* rsa);
void crypto_free_rsa(rsa_key_material_t* keyMat);

// DSA
int crypto_save_dsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, DSA* dsa);
dsa_key_material_t* crypto_malloc_dsa(DSA* dsa);
void crypto_free_dsa(dsa_key_material_t* keyMat);

#ifdef WITH_ECC
// ECDSA
int crypto_save_ecdsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, EC_KEY* ecdsa);
ecdsa_key_material_t* crypto_malloc_ecdsa(EC_KEY* ecdsa);
void crypto_free_ecdsa(ecdsa_key_material_t* keyMat);
#endif

#ifdef WITH_EDDSA
// EDDSA
int crypto_save_eddsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, EVP_PKEY* eddsa);
eddsa_key_material_t* crypto_malloc_eddsa(EVP_PKEY* eddsa);
void crypto_free_eddsa(eddsa_key_material_t* keyMat);
#endif

#ifdef WITH_ML_DSA
// MLDSA
int crypto_save_mldsa(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, EVP_PKEY* mldsa);
mldsa_key_material_t* crypto_malloc_mldsa(EVP_PKEY* mldsa);
void crypto_free_mldsa(mldsa_key_material_t* keyMat);
#endif

#ifdef WITH_ML_KEM
// MLKEM
int crypto_save_mlkem(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, EVP_PKEY* mlkem);
mlkem_key_material_t* crypto_malloc_mlkem(EVP_PKEY* mlkem);
void crypto_free_mlkem(mlkem_key_material_t* keyMat);
#endif

#ifdef WITH_X_WING
// X-Wing
int crypto_save_xwing(CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, PKCS8_PRIV_KEY_INFO* keyInfo);
#endif

#endif // !_SOFTHSM_V2_SOFTHSM2_UTIL_OSSL_H
