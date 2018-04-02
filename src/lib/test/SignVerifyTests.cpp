/*
 * Copyright (c) 2012 SURFnet
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
 SignVerifyTests.cpp

 Contains test cases for:
	 C_SignInit
	 C_Sign
	 C_SignUpdate
	 C_SignFinal
	 C_VerifyInit
	 C_Verify
	 C_VerifyUpdate
	 C_VerifyFinal

 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "SignVerifyTests.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(SignVerifyTests);

CK_RV SignVerifyTests::generateRSA(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ULONG bits = 1536;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_BYTE label[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk) );
}

#ifdef WITH_ECC
CK_RV SignVerifyTests::generateEC(const char* curve, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_EC;
	CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	CK_BYTE oidP384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
	CK_BYTE oidP521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
	CK_BYTE label[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	/* Select the curve */
	if (strcmp(curve, "P-256") == 0)
	{
		pukAttribs[0].pValue = oidP256;
		pukAttribs[0].ulValueLen = sizeof(oidP256);
	}
	else if (strcmp(curve, "P-384") == 0)
	{
		pukAttribs[0].pValue = oidP384;
		pukAttribs[0].ulValueLen = sizeof(oidP384);
	}
	else if (strcmp(curve, "P-521") == 0)
	{
		pukAttribs[0].pValue = oidP521;
		pukAttribs[0].ulValueLen = sizeof(oidP521);
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk) );
}
#endif

#ifdef WITH_EDDSA
CK_RV SignVerifyTests::generateED(const char* curve, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_EC_EDWARDS;
	CK_BYTE oidEd25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
	CK_BYTE label[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	/* Select the curve */
	if (strcmp(curve, "Ed25519") == 0)
	{
		pukAttribs[0].pValue = oidEd25519;
		pukAttribs[0].ulValueLen = sizeof(oidEd25519);
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk) );
}
#endif

void SignVerifyTests::signVerifySingle(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param /* = NULL_PTR */, CK_ULONG paramLen /* = 0 */)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, param, paramLen };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,0x0C, 0x0D, 0x0F };
	CK_BYTE signature[256];
	CK_ULONG ulSignatureLen = 0;

	rv = CRYPTOKI_F_PTR( C_SignInit(hSession,&mechanism,hPrivateKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulSignatureLen = sizeof(signature);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession,data,sizeof(data),signature,&ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Verify(hSession,data,sizeof(data),signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// verify again, but now change the input that is being signed.
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	data[0] = 0xff;
	rv = CRYPTOKI_F_PTR( C_Verify(hSession,data,sizeof(data),signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_SIGNATURE_INVALID);
}

void SignVerifyTests::signVerifySingleData(size_t dataSize, CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param /* = NULL_PTR */, CK_ULONG paramLen /* = 0 */)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, param, paramLen };
	CK_BYTE *data = (CK_BYTE*)malloc(dataSize);
	CK_BYTE signature[1024];
	CK_ULONG ulSignatureLen = 0;
	unsigned i;

	CPPUNIT_ASSERT(data != NULL);

	for (i=0;i<dataSize;i++)
		data[i] = i;

	rv = CRYPTOKI_F_PTR( C_SignInit(hSession,&mechanism,hPrivateKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulSignatureLen = sizeof(signature);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession,data,dataSize,signature,&ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Verify(hSession,data,dataSize,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// verify again, but now change the input that is being signed.
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	data[0] = 0xff;
	rv = CRYPTOKI_F_PTR( C_Verify(hSession,data,dataSize,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_SIGNATURE_INVALID);

	free(data);
}

void SignVerifyTests::signVerifyMulti(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param /* = NULL_PTR */, CK_ULONG paramLen /* = 0 */)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, param, paramLen };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,0x0C, 0x0D, 0x0F };
	CK_BYTE signature[256];
	CK_ULONG ulSignatureLen = 0;

	rv = CRYPTOKI_F_PTR( C_SignInit(hSession,&mechanism,hPrivateKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv =CRYPTOKI_F_PTR( C_SignUpdate(hSession,data,sizeof(data)) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulSignatureLen = sizeof(signature);
	rv =CRYPTOKI_F_PTR( C_SignFinal(hSession,signature,&ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyUpdate(hSession,data,sizeof(data)) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyFinal(hSession,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// verify again, but now change the input that is being signed.
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	data[0] = 0xff;
	rv = CRYPTOKI_F_PTR( C_VerifyUpdate(hSession,data,sizeof(data)) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyFinal(hSession,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_SIGNATURE_INVALID);
}

void SignVerifyTests::testRsaSignVerify()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_RSA_PKCS_PSS_PARAMS params[] = {
		{ CKM_SHA_1,  CKG_MGF1_SHA1,   0  },
		{ CKM_SHA224, CKG_MGF1_SHA224, 28 },
		{ CKM_SHA256, CKG_MGF1_SHA256, 32 },
		{ CKM_SHA384, CKG_MGF1_SHA384, 0  },
		{ CKM_SHA512, CKG_MGF1_SHA512, 0  }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	// Public Session keys
	rv = generateRSA(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	signVerifySingle(CKM_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_RSA_X_509, hSessionRO, hPuk,hPrk);
#ifndef WITH_FIPS
	signVerifyMulti(CKM_MD5_RSA_PKCS, hSessionRO, hPuk,hPrk);
#endif
	signVerifyMulti(CKM_SHA1_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifyMulti(CKM_SHA224_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifyMulti(CKM_SHA256_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifyMulti(CKM_SHA384_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifyMulti(CKM_SHA512_RSA_PKCS, hSessionRO, hPuk,hPrk);

#ifdef WITH_RAW_PSS
	signVerifySingleData(20, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifySingleData(28, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifySingleData(32, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifySingleData(48, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifySingleData(64, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));
#endif

	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));

	// Private Session Keys
	rv = generateRSA(hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	signVerifySingle(CKM_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifySingle(CKM_RSA_X_509, hSessionRW, hPuk,hPrk);
#ifndef WITH_FIPS
	signVerifyMulti(CKM_MD5_RSA_PKCS, hSessionRW, hPuk,hPrk);
#endif
	signVerifyMulti(CKM_SHA1_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA224_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA256_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA384_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA512_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[4], sizeof(params[4]));

	// Public Token Keys
	rv = generateRSA(hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	signVerifySingle(CKM_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifySingle(CKM_RSA_X_509, hSessionRW, hPuk,hPrk);
#ifndef WITH_FIPS
	signVerifyMulti(CKM_MD5_RSA_PKCS, hSessionRW, hPuk,hPrk);
#endif
	signVerifyMulti(CKM_SHA1_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA224_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA256_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA384_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA512_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[4], sizeof(params[4]));

	// Private Token Keys
	rv = generateRSA(hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	signVerifySingle(CKM_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifySingle(CKM_RSA_X_509, hSessionRW, hPuk,hPrk);
#ifndef WITH_FIPS
	signVerifyMulti(CKM_MD5_RSA_PKCS, hSessionRW, hPuk,hPrk);
#endif
	signVerifyMulti(CKM_SHA1_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA224_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA256_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA384_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA512_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[4], sizeof(params[4]));
}

#ifdef WITH_ECC
void SignVerifyTests::testEcSignVerify()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	// Public Session keys
	rv = generateEC("P-256", hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-384", hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-521", hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);

	// Private Session Keys
	rv = generateEC("P-256", hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-384", hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-521", hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);

	// Public Token Keys
	rv = generateEC("P-256", hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-384", hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-521", hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);

	// Private Token Keys
	rv = generateEC("P-256", hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-384", hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	rv = generateEC("P-521", hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
}
#endif

#ifdef WITH_EDDSA
void SignVerifyTests::testEdSignVerify()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	// Public Session keys
	rv = generateED("Ed25519", hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);

	// Private Session Keys
	rv = generateED("Ed25519", hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);

	// Public Token Keys
	rv = generateED("Ed25519", hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);

	// Private Token Keys
	rv = generateED("Ed25519", hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);
}
#endif

CK_RV SignVerifyTests::generateKey(CK_SESSION_HANDLE hSession, CK_KEY_TYPE keyType, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
#ifndef WITH_BOTAN
#define GEN_KEY_LEN	75
#else
#define GEN_KEY_LEN	64
#endif
	CK_RV rv;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BYTE val[GEN_KEY_LEN];
	//CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BYTE oid[] = { 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1F, 0x00 };
	CK_ATTRIBUTE kAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE, val, sizeof(val) },
		{ CKA_GOST28147_PARAMS, oid, sizeof(oid) }
	};

	rv = CRYPTOKI_F_PTR( C_GenerateRandom(hSession, val, GEN_KEY_LEN) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	hKey = CK_INVALID_HANDLE;
	if (keyType == CKK_GOST28147)
	{
		return CRYPTOKI_F_PTR( C_CreateObject(hSession, kAttribs, 9, &hKey) );
	}
	else
	{
		return CRYPTOKI_F_PTR( C_CreateObject(hSession, kAttribs, 8, &hKey) );
	}
}

CK_RV SignVerifyTests::generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES2_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) }
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

CK_RV SignVerifyTests::generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) }
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

CK_RV SignVerifyTests::generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) }
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

void SignVerifyTests::macSignVerify(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,0x0C, 0x0D, 0x0F };
	CK_BYTE signature[256];
	CK_ULONG ulSignatureLen = 0;

	rv = CRYPTOKI_F_PTR( C_SignInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv =CRYPTOKI_F_PTR( C_SignUpdate(hSession,data,sizeof(data)) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulSignatureLen = sizeof(signature);
	rv =CRYPTOKI_F_PTR( C_SignFinal(hSession,signature,&ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyUpdate(hSession,data,sizeof(data)) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyFinal(hSession,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// verify again, but now change the input that is being signed.
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	data[0] = 0xff;
	rv = CRYPTOKI_F_PTR( C_VerifyUpdate(hSession,data,sizeof(data)) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyFinal(hSession,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_SIGNATURE_INVALID);
}

void SignVerifyTests::testMacSignVerify()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Public Session keys
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
#ifndef WITH_FIPS
	rv = generateKey(hSessionRW,CKK_MD5_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_MD5_HMAC, hSessionRO, hKey);
#endif

	rv = generateKey(hSessionRW,CKK_SHA_1_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA_1_HMAC, hSessionRO, hKey);

	rv = generateKey(hSessionRW,CKK_SHA224_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA224_HMAC, hSessionRO, hKey);

	rv = generateKey(hSessionRW,CKK_SHA256_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA256_HMAC, hSessionRO, hKey);

	rv = generateKey(hSessionRW,CKK_SHA384_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA384_HMAC, hSessionRO, hKey);

	rv = generateKey(hSessionRW,CKK_SHA512_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA512_HMAC, hSessionRO, hKey);

#ifdef WITH_GOST
	rv = generateKey(hSessionRW,CKK_GOST28147,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_GOSTR3411_HMAC, hSessionRO, hKey);
#endif

	rv = generateDes2Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateDes3Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateAesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_AES_CMAC, hSessionRO, hKey);

	// Private Session Keys
#ifndef WITH_FIPS
	rv = generateKey(hSessionRW,CKK_MD5_HMAC,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_MD5_HMAC, hSessionRW, hKey);
#endif

	rv = generateKey(hSessionRW,CKK_SHA_1_HMAC,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA_1_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA224_HMAC,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA224_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA256_HMAC,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA256_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA384_HMAC,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA384_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA512_HMAC,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA512_HMAC, hSessionRW, hKey);

#ifdef WITH_GOST
	rv = generateKey(hSessionRW,CKK_GOST28147,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_GOSTR3411_HMAC, hSessionRW, hKey);
#endif

	rv = generateDes2Key(hSessionRW,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateDes3Key(hSessionRW,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateAesKey(hSessionRW,IN_SESSION,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_AES_CMAC, hSessionRO, hKey);

	// Public Token Keys
#ifndef WITH_FIPS
	rv = generateKey(hSessionRW,CKK_MD5_HMAC,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_MD5_HMAC, hSessionRW, hKey);
#endif

	rv = generateKey(hSessionRW,CKK_SHA_1_HMAC,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA_1_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA224_HMAC,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA224_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA256_HMAC,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA256_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA384_HMAC,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA384_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA512_HMAC,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA512_HMAC, hSessionRW, hKey);

#ifdef WITH_GOST
	rv = generateKey(hSessionRW,CKK_GOST28147,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_GOSTR3411_HMAC, hSessionRW, hKey);
#endif

	rv = generateDes2Key(hSessionRW,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateDes3Key(hSessionRW,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateAesKey(hSessionRW,ON_TOKEN,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_AES_CMAC, hSessionRO, hKey);

	// Private Token Keys
#ifndef WITH_FIPS
	rv = generateKey(hSessionRW,CKK_MD5_HMAC,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_MD5_HMAC, hSessionRW, hKey);
#endif

	rv = generateKey(hSessionRW,CKK_SHA_1_HMAC,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA_1_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA224_HMAC,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA224_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA256_HMAC,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA256_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA384_HMAC,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA384_HMAC, hSessionRW, hKey);

	rv = generateKey(hSessionRW,CKK_SHA512_HMAC,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA512_HMAC, hSessionRW, hKey);

#ifdef WITH_GOST
	rv = generateKey(hSessionRW,CKK_GOST28147,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_GOSTR3411_HMAC, hSessionRW, hKey);
#endif

	rv = generateDes2Key(hSessionRW,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateDes3Key(hSessionRW,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_DES3_CMAC, hSessionRO, hKey);

	rv = generateAesKey(hSessionRW,ON_TOKEN,IS_PRIVATE,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_AES_CMAC, hSessionRO, hKey);
}

