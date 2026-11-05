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
	CK_BYTE curveNameEd25519[] = { 0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72,
				       0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39 };
	CK_BYTE curveNameEd448[] = { 0x13, 0x0a, 0x65, 0x64, 0x77, 0x61,
				     0x72, 0x64, 0x73, 0x34, 0x34, 0x38 };
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
		pukAttribs[0].pValue = curveNameEd25519;
		pukAttribs[0].ulValueLen = sizeof(curveNameEd25519);
	}
	else if (strcmp(curve, "Ed448") == 0)
	{
		pukAttribs[0].pValue = curveNameEd448;
		pukAttribs[0].ulValueLen = sizeof(curveNameEd448);
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

#ifdef WITH_ML_DSA
CK_RV SignVerifyTests::generateMLDSA(CK_ULONG parameterSet, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_ML_DSA;
	CK_BYTE label[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
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
	CK_BYTE signature[64 * 1024];
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
	CK_BYTE signature[1024];
	CK_ULONG ulSignatureLen = 0;

	CPPUNIT_ASSERT(dataSize > 0);
	CK_BYTE *data = (CK_BYTE*)malloc(dataSize);
	CPPUNIT_ASSERT(data != NULL);

	for (size_t i = 0; i < dataSize; i++)
		data[i] = (CK_BYTE) i;

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

void SignVerifyTests::signVerifySingleData(CK_BYTE_PTR data, size_t dataSize, CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param /* = NULL_PTR */, CK_ULONG paramLen /* = 0 */)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, param, paramLen };
	CK_BYTE signature[1024];
	CK_ULONG ulSignatureLen = 0;

	CPPUNIT_ASSERT(dataSize > 0);
	CPPUNIT_ASSERT(data != NULL);

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

	CK_BYTE origByte = data[0];
	data[0] = 0xff;
	rv = CRYPTOKI_F_PTR( C_Verify(hSession,data,dataSize,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_SIGNATURE_INVALID);

	// the caller owns the buffer and may reuse it, so leave it untouched
	data[0] = origByte;
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
		{ CKM_SHA512, CKG_MGF1_SHA512, 0  },
#ifdef WITH_SHA3
		{ CKM_SHA3_224, CKG_MGF1_SHA3_224, 28 },
		{ CKM_SHA3_256, CKG_MGF1_SHA3_256, 32 },
		{ CKM_SHA3_384, CKG_MGF1_SHA3_384, 48 },
		{ CKM_SHA3_512, CKG_MGF1_SHA3_512, 64 }
#endif
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
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS, hSessionRO, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS, hSessionRO, hPuk,hPrk);
#endif

#ifdef WITH_RAW_PSS
	signVerifySingleData(20, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifySingleData(28, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifySingleData(32, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifySingleData(48, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifySingleData(64, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));
#ifdef WITH_SHA3
	signVerifySingleData(28, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[5], sizeof(params[5]));
	signVerifySingleData(32, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[6], sizeof(params[6]));
	signVerifySingleData(48, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[7], sizeof(params[7]));
	signVerifySingleData(64, CKM_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[8], sizeof(params[8]));
#endif
#endif

	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[5], sizeof(params[5]));
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[6], sizeof(params[6]));
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[7], sizeof(params[7]));
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS_PSS, hSessionRO, hPuk,hPrk, &params[8], sizeof(params[8]));
#endif

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
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS, hSessionRW, hPuk,hPrk);
#endif
	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[4], sizeof(params[4]));
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[5], sizeof(params[5]));
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[6], sizeof(params[6]));
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[7], sizeof(params[7]));
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[8], sizeof(params[8]));
#endif

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
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS, hSessionRW, hPuk,hPrk);
#endif
	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[4], sizeof(params[4]));
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[5], sizeof(params[5]));
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[6], sizeof(params[6]));
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[7], sizeof(params[7]));
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[8], sizeof(params[8]));
#endif

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
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS, hSessionRW, hPuk,hPrk);
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS, hSessionRW, hPuk,hPrk);
#endif
	signVerifyMulti(CKM_SHA1_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifyMulti(CKM_SHA224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifyMulti(CKM_SHA256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifyMulti(CKM_SHA384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifyMulti(CKM_SHA512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[4], sizeof(params[4]));
#ifdef WITH_SHA3
	signVerifyMulti(CKM_SHA3_224_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[5], sizeof(params[5]));
	signVerifyMulti(CKM_SHA3_256_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[6], sizeof(params[6]));
	signVerifyMulti(CKM_SHA3_384_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[7], sizeof(params[7]));
	signVerifyMulti(CKM_SHA3_512_RSA_PKCS_PSS, hSessionRW, hPuk,hPrk, &params[8], sizeof(params[8]));
#endif
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
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-384", hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-521", hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	// Private Session Keys
	rv = generateEC("P-256", hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-384", hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-521", hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	// Public Token Keys
	rv = generateEC("P-256", hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-384", hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-521", hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	// Private Token Keys
	rv = generateEC("P-256", hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-384", hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	rv = generateEC("P-521", hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ECDSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifySingle(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifySingle(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif

	signVerifyMulti(CKM_ECDSA_SHA1, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA512, hSessionRO, hPuk, hPrk);
#ifdef WITH_SHA3
	signVerifyMulti(CKM_ECDSA_SHA3_224, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_256, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_384, hSessionRO, hPuk, hPrk);
	signVerifyMulti(CKM_ECDSA_SHA3_512, hSessionRO, hPuk, hPrk);
#endif
}
#endif

#ifdef WITH_EDDSA
void SignVerifyTests::testEdSignVerify(const char* curve)
{
#ifdef WITH_BOTAN
	if (strcmp(curve, "Ed448") == 0)
		return;
#endif

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
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);

	// Private Session Keys
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);

	// Public Token Keys
	rv = generateED(curve, hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);

	// Private Token Keys
	rv = generateED(curve, hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk,hPrk);
}

void SignVerifyTests::testEdSignVerifyWithContext(const char* curve)
{
	bool contextSupported = true;

#ifdef WITH_BOTAN
	// Botan 2.X has no context support
	contextSupported = false;
#endif
#if defined(WITH_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x30200000L
	contextSupported = false;
#endif

	if (!contextSupported)
	{
		fprintf(stdout, "EdDSA context is not supported. Skipping testEdSignVerifyWithContext.\n");
		return;
	}	

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

	// Test EdDSA signature with context data
	// Create EdDSA parameters with context
	CK_BYTE contextData[] = "context-data";
	CK_ULONG dataSize = (CK_ULONG)(sizeof(contextData) - 1); // exclude trailing NULL
	CK_EDDSA_PARAMS params = 
			{
			CK_FALSE,  // phFlag = 0 (no pre-hash)
			dataSize,  // context_data_len
			contextData  // context_data
	};

	// Public Session keys with context
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk, hPrk, &params, sizeof(params));

	// Private Session Keys with context
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk, hPrk, &params, sizeof(params));

	// Test with different context data
	CK_BYTE anotherContext[] = "Bob";
	dataSize = (CK_ULONG)(sizeof(anotherContext) - 1); // exclude trailing NULL
	CK_EDDSA_PARAMS eddsaParams2 = {
		CK_FALSE,  // phFlag = 0
		dataSize,  // context_data_len
		anotherContext  // context_data
	};

	// Public Token Keys with different context
	rv = generateED(curve, hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParams2, sizeof(eddsaParams2));

	// Private Token Keys with different context
	rv = generateED(curve, hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParams2, sizeof(eddsaParams2));

	// Test with empty context
	CK_EDDSA_PARAMS eddsaParamsNoCtx = {
		CK_FALSE,  // phFlag = 0
		0,     // context_data_len = 0
		NULL   // context_data = NULL
	};

	// Generate new keys for empty context test
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParamsNoCtx, sizeof(CK_EDDSA_PARAMS));
}

void SignVerifyTests::testEdSignVerifyWithContextPreHashed(const char* curve)
{
#ifdef WITH_BOTAN
	// Botan 2.X does not support Ed448 curve, so we skip this test for now.
	if (strcmp(curve, "Ed448") == 0)
	{
		fprintf(stdout, "Botan 2.X does not support Ed448. Skipping testEdSignVerifyWithContextPreHashed for Ed448.\n");
		return;
	}
#endif
#if defined(WITH_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x30200000L
	fprintf(stdout, "OpenSSL 3.2.0 or later is required for EDDSA with context support. Skipping testEdSignVerifyWithContextPreHashed.\n");
	return;
#endif

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

	// With phFlag set the token does the pre-hashing, so this is just the message to be signed
	CK_BYTE message[] = { 0x11, 0x79, 0x06, 0xd8, 0xd7, 0xd9, 0x4d, 0xbc, 0x02, 0x01, 0x93, 0x2f, 0xbb, 0xab, 0x01, 0xed, 0x5b, 0x9e, 0xbc, 0x0f, 0x3c, 0x85, 0xef, 0xa0, 0x78, 0x61, 0xa1, 0xfa, 0xff, 0xb4, 0xee, 0xb2, 0x33, 0xdf, 0x44, 0xaa, 0xa0, 0x2d, 0x7b, 0x8f, 0xf2, 0x50, 0x7f, 0x98, 0x42, 0x7e, 0x3e, 0x1f, 0x5c, 0x7b, 0x9d, 0x6a, 0x2e, 0x4c, 0x8f, 0x1a, 0x3b, 0x5d, 0x6e, 0x7f, 0x8a, 0x9b };
	CK_EDDSA_PARAMS eddsaParams = {
		CK_TRUE,  // phFlag = 1 (pre-hash)
		0,     // context_data_len = 0
		NULL   // context_data = NULL
	};

	// Public Session keys
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingleData(message, sizeof(message), CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParams, sizeof(CK_EDDSA_PARAMS));

	// Private Session Keys
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingleData(message, sizeof(message), CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParams, sizeof(CK_EDDSA_PARAMS));

	// Test with a different message
	CK_BYTE anotherMessage[] = { 0x13, 0xe8, 0x06, 0x38, 0x7a, 0xdc, 0x2d, 0x73, 0x3c, 0x85, 0xa9, 0xd0, 0x81, 0x91, 0xfa, 0xa0, 0xcd, 0xeb, 0x11, 0xca, 0x4d, 0x1c, 0x2a, 0x05, 0x7c, 0x27, 0xf3, 0x6c, 0xeb, 0xc4, 0xdf, 0x88, 0x8a, 0x45, 0x6a, 0xc5, 0xc0, 0x91, 0x69, 0x31, 0x4e, 0xb0, 0x49, 0xe7, 0xdf, 0xdc, 0xf8, 0x68, 0x67, 0x21, 0xf6, 0xda, 0x13, 0x46, 0x1c, 0x57, 0x5c, 0x6e, 0x78, 0x36, 0x91, 0xc4, 0x2d, 0x09 };
	CK_EDDSA_PARAMS eddsaParams2 = {
		CK_TRUE,  // phFlag = 1 (pre-hash)
		0,     // context_data_len = 0
		NULL   // context_data = NULL
	};

	// Public Token Keys
	rv = generateED(curve, hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingleData(anotherMessage, sizeof(anotherMessage), CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParams2, sizeof(CK_EDDSA_PARAMS));

	// Private Token Keys
	rv = generateED(curve, hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingleData(anotherMessage, sizeof(anotherMessage), CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParams2, sizeof(CK_EDDSA_PARAMS));

	// Test with empty context
	CK_EDDSA_PARAMS eddsaParamsNoCtx = {
		CK_TRUE,  // phFlag = 1 (pre-hash)
		0,     // context_data_len = 0
		NULL   // context_data = NULL
	};

	// Generate new keys for empty context test
	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingleData(64, CKM_EDDSA, hSessionRO, hPuk, hPrk, &eddsaParamsNoCtx, sizeof(CK_EDDSA_PARAMS));
}

void SignVerifyTests::signVerifyMismatchedParams(CK_BYTE_PTR data, size_t dataSize, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR signParam, CK_ULONG signParamLen, CK_VOID_PTR verifyParam, CK_ULONG verifyParamLen)
{
	CK_RV rv;
	CK_MECHANISM signMechanism = { CKM_EDDSA, signParam, signParamLen };
	CK_MECHANISM verifyMechanism = { CKM_EDDSA, verifyParam, verifyParamLen };
	CK_BYTE signature[1024];
	CK_ULONG ulSignatureLen = sizeof(signature);

	rv = CRYPTOKI_F_PTR( C_SignInit(hSession,&signMechanism,hPrivateKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Sign(hSession,data,dataSize,signature,&ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession,&verifyMechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Verify(hSession,data,dataSize,signature,ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_SIGNATURE_INVALID);
}

// A signature made with one set of EdDSA parameters must not verify under another
void SignVerifyTests::testEdSignVerifyMismatchedParams(const char* curve)
{
	bool contextSupported = true;
	bool preHashSupported = true;

#ifdef WITH_BOTAN
	// Botan 2.X has no context support and only pre-hashes Ed25519
	contextSupported = false;
	if (strcmp(curve, "Ed448") == 0)
		preHashSupported = false;
#endif
#if defined(WITH_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x30200000L
	contextSupported = false;
	preHashSupported = false;
#endif

	if (!contextSupported && !preHashSupported)
	{
		fprintf(stdout, "Neither EdDSA context nor pre-hash is supported. Skipping testEdSignVerifyMismatchedParams.\n");
		return;
	}

	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = generateED(curve, hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_BYTE data[64];
	for (size_t i = 0; i < sizeof(data); i++)
		data[i] = (CK_BYTE) i;

	CK_BYTE contextAlice[] = "Alice";
	CK_BYTE contextBob[] = "Bob";
	CK_EDDSA_PARAMS aliceParams = { CK_FALSE, (CK_ULONG)(sizeof(contextAlice) - 1), contextAlice };
	CK_EDDSA_PARAMS bobParams   = { CK_FALSE, (CK_ULONG)(sizeof(contextBob) - 1), contextBob };
	CK_EDDSA_PARAMS pureParams  = { CK_FALSE, 0, NULL };
	CK_EDDSA_PARAMS preHashParams = { CK_TRUE, 0, NULL };

	if (contextSupported)
	{
		// Different context data
		signVerifyMismatchedParams(data, sizeof(data), hSessionRO, hPuk, hPrk,
					   &aliceParams, sizeof(aliceParams), &bobParams, sizeof(bobParams));

		// Context data on signing only
		signVerifyMismatchedParams(data, sizeof(data), hSessionRO, hPuk, hPrk,
					   &aliceParams, sizeof(aliceParams), &pureParams, sizeof(pureParams));

		// Context data dropped by omitting the parameters altogether
		signVerifyMismatchedParams(data, sizeof(data), hSessionRO, hPuk, hPrk,
					   &aliceParams, sizeof(aliceParams), NULL_PTR, 0);
	}

	if (preHashSupported)
	{
		// Pre-hash on signing only
		signVerifyMismatchedParams(data, sizeof(data), hSessionRO, hPuk, hPrk,
					   &preHashParams, sizeof(preHashParams), &pureParams, sizeof(pureParams));
	}
}

void SignVerifyTests::testEdSignVerifyInvalidParams()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = generateED("Ed25519", hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_BYTE context[256] = { 0 };
	CK_EDDSA_PARAMS validParams = { CK_FALSE, 0, NULL };
	CK_EDDSA_PARAMS tooLongContext = { CK_FALSE, (CK_ULONG) sizeof(context), context };
	CK_EDDSA_PARAMS nullContext = { CK_FALSE, 1, NULL };

	CK_MECHANISM mechanisms[] = {
		// No parameters but a non-zero length
		{ CKM_EDDSA, NULL_PTR, sizeof(CK_EDDSA_PARAMS) },
		// Wrong parameter length
		{ CKM_EDDSA, &validParams, sizeof(CK_EDDSA_PARAMS) - 1 },
		{ CKM_EDDSA, &validParams, sizeof(CK_EDDSA_PARAMS) + 1 },
		// Context data longer than 255 bytes
		{ CKM_EDDSA, &tooLongContext, sizeof(tooLongContext) },
		// Non-zero context length with a NULL context pointer
		{ CKM_EDDSA, &nullContext, sizeof(nullContext) }
	};

	for (size_t i = 0; i < sizeof(mechanisms) / sizeof(CK_MECHANISM); i++)
	{
		rv = CRYPTOKI_F_PTR( C_SignInit(hSessionRO,&mechanisms[i],hPrk) );
		CPPUNIT_ASSERT_EQUAL((CK_RV) CKR_MECHANISM_PARAM_INVALID, rv);

		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSessionRO,&mechanisms[i],hPuk) );
		CPPUNIT_ASSERT_EQUAL((CK_RV) CKR_MECHANISM_PARAM_INVALID, rv);
	}
}
#endif

#ifdef WITH_ML_DSA
void SignVerifyTests::testMLDSASignVerify(CK_ULONG parameterSet)
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

    CK_BYTE data[] = "context-context-context";
    CK_ULONG dataSize = (CK_ULONG)(sizeof(data) - 1); // exclude trailing NULL

	CK_SIGN_ADDITIONAL_CONTEXT params[] = {
		{ CKH_HEDGE_PREFERRED,  NULL,   0  },
		{ CKH_HEDGE_PREFERRED,  data,   dataSize  },
		{ CKH_HEDGE_REQUIRED,  NULL,   0  },
		{ CKH_HEDGE_REQUIRED,  data,   dataSize  },
		{ CKH_DETERMINISTIC_REQUIRED,  NULL,   0  },
		{ CKH_DETERMINISTIC_REQUIRED,  data,   dataSize  },
	};

	// Public Session keys
	rv = generateMLDSA(parameterSet,hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[5], sizeof(params[5]));

	// Private Session Keys
	rv = generateMLDSA(parameterSet,hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[5], sizeof(params[5]));

	// Public Token Keys
	rv = generateMLDSA(parameterSet,hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[5], sizeof(params[5]));

	// Private Token Keys
	rv = generateMLDSA(parameterSet, hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk);
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[0], sizeof(params[0]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[1], sizeof(params[1]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[2], sizeof(params[2]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[3], sizeof(params[3]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[4], sizeof(params[4]));
	signVerifySingle(CKM_ML_DSA, hSessionRO, hPuk,hPrk, &params[5], sizeof(params[5]));
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

#ifdef WITH_SHA3
	rv = generateKey(hSessionRW,CKK_SHA3_224_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA3_224_HMAC, hSessionRO, hKey);

	rv = generateKey(hSessionRW,CKK_SHA3_256_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA3_256_HMAC, hSessionRO, hKey);

	rv = generateKey(hSessionRW,CKK_SHA3_384_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA3_384_HMAC, hSessionRO, hKey);

	rv = generateKey(hSessionRW,CKK_SHA3_512_HMAC,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	macSignVerify(CKM_SHA3_512_HMAC, hSessionRO, hKey);

#endif
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

// C_SignInit with mismatched key type must return CKR_KEY_TYPE_INCONSISTENT,
// not accept the key and crash during C_Sign.
void SignVerifyTests::testSignInitWrongKeyType()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// EC private key with RSA/DSA mechanisms
	CK_OBJECT_HANDLE hEcPub = CK_INVALID_HANDLE, hEcPriv = CK_INVALID_HANDLE;
#ifdef WITH_ECC
	rv = generateEC("P-256", hSession, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC, hEcPub, hEcPriv);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// RSA mechanisms with EC key
	CK_MECHANISM_TYPE rsaMechs[] = {
		CKM_RSA_PKCS, CKM_RSA_X_509,
		CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS
	};
	for (size_t i = 0; i < sizeof(rsaMechs)/sizeof(rsaMechs[0]); i++)
	{
		CK_MECHANISM mechanism = { rsaMechs[i], NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hEcPriv) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}

	// DSA mechanisms with EC key
	CK_MECHANISM_TYPE dsaMechs[] = { CKM_DSA, CKM_DSA_SHA1, CKM_DSA_SHA256
#ifdef WITH_SHA3
		, CKM_DSA_SHA3_256
#endif
	};
	for (size_t i = 0; i < sizeof(dsaMechs)/sizeof(dsaMechs[0]); i++)
	{
		CK_MECHANISM mechanism = { dsaMechs[i], NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hEcPriv) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

	// RSA private key with ECDSA/EdDSA mechanisms
	CK_OBJECT_HANDLE hRsaPub = CK_INVALID_HANDLE, hRsaPriv = CK_INVALID_HANDLE;
	rv = generateRSA(hSession, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC, hRsaPub, hRsaPriv);
	CPPUNIT_ASSERT(rv == CKR_OK);

#ifdef WITH_ECC
	// ECDSA mechanisms with RSA key
	CK_MECHANISM_TYPE ecdsaMechs[] = { CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA256 };
	for (size_t i = 0; i < sizeof(ecdsaMechs)/sizeof(ecdsaMechs[0]); i++)
	{
		CK_MECHANISM mechanism = { ecdsaMechs[i], NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hRsaPriv) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

#ifdef WITH_EDDSA
	// EdDSA mechanism with RSA key
	{
		CK_MECHANISM mechanism = { CKM_EDDSA, NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hRsaPriv) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

#ifdef WITH_GOST
	// GOST mechanism with RSA key
	{
		CK_MECHANISM mechanism = { CKM_GOSTR3410, NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hRsaPriv) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

#ifdef WITH_ML_DSA
	// ML-DSA mechanism with RSA key
	{
		CK_MECHANISM mechanism = { CKM_ML_DSA, NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hRsaPriv) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

	C_Logout(hSession);
	C_CloseSession(hSession);
}

// Same as above but for C_VerifyInit.
void SignVerifyTests::testVerifyInitWrongKeyType()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// EC public key with RSA/DSA mechanisms
	CK_OBJECT_HANDLE hEcPub = CK_INVALID_HANDLE, hEcPriv = CK_INVALID_HANDLE;
#ifdef WITH_ECC
	rv = generateEC("P-256", hSession, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC, hEcPub, hEcPriv);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// RSA mechanisms with EC key
	CK_MECHANISM_TYPE rsaMechs[] = {
		CKM_RSA_PKCS, CKM_RSA_X_509,
		CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS
	};
	for (size_t i = 0; i < sizeof(rsaMechs)/sizeof(rsaMechs[0]); i++)
	{
		CK_MECHANISM mechanism = { rsaMechs[i], NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mechanism, hEcPub) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}

	// DSA mechanisms with EC key
	CK_MECHANISM_TYPE dsaMechs[] = { CKM_DSA, CKM_DSA_SHA1, CKM_DSA_SHA256
#ifdef WITH_SHA3
		, CKM_DSA_SHA3_256
#endif
	};
	for (size_t i = 0; i < sizeof(dsaMechs)/sizeof(dsaMechs[0]); i++)
	{
		CK_MECHANISM mechanism = { dsaMechs[i], NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mechanism, hEcPub) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

	// RSA public key with ECDSA/EdDSA mechanisms
	CK_OBJECT_HANDLE hRsaPub = CK_INVALID_HANDLE, hRsaPriv = CK_INVALID_HANDLE;
	rv = generateRSA(hSession, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC, hRsaPub, hRsaPriv);
	CPPUNIT_ASSERT(rv == CKR_OK);

#ifdef WITH_ECC
	// ECDSA mechanisms with RSA key
	CK_MECHANISM_TYPE ecdsaMechs[] = { CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA256 };
	for (size_t i = 0; i < sizeof(ecdsaMechs)/sizeof(ecdsaMechs[0]); i++)
	{
		CK_MECHANISM mechanism = { ecdsaMechs[i], NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mechanism, hRsaPub) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

#ifdef WITH_EDDSA
	// EdDSA mechanism with RSA key
	{
		CK_MECHANISM mechanism = { CKM_EDDSA, NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mechanism, hRsaPub) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

#ifdef WITH_GOST
	// GOST mechanism with RSA key
	{
		CK_MECHANISM mechanism = { CKM_GOSTR3410, NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mechanism, hRsaPub) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

#ifdef WITH_ML_DSA
	// ML-DSA mechanism with RSA key
	{
		CK_MECHANISM mechanism = { CKM_ML_DSA, NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mechanism, hRsaPub) );
		CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	}
#endif

	C_Logout(hSession);
	C_CloseSession(hSession);
}
