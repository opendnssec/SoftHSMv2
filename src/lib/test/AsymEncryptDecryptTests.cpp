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
 AsymEncryptDecryptTests.cpp

 Contains test cases for C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt
 using asymmetrical algorithms (i.e., RSA)
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "AsymEncryptDecryptTests.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(AsymEncryptDecryptTests);

CK_RV AsymEncryptDecryptTests::generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 1536;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk) );
}

void AsymEncryptDecryptTests::rsaEncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, 1, NULL_PTR, 0 };
	CK_BYTE plainText[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,0x0C, 0x0D, 0x0F };
	CK_BYTE cipherText[256];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[256];
	CK_ULONG ulRecoveredTextLen;
	CK_RV rv;

	if (mechanismType == CKM_RSA_PKCS_OAEP)
	{
		mechanism.pParameter = &oaepParams;
		mechanism.ulParameterLen = sizeof(oaepParams);
	}

	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulCipherTextLen = sizeof(cipherText);
	rv =CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText),cipherText,&ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hPrivateKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CPPUNIT_ASSERT(memcmp(plainText, &recoveredText[ulRecoveredTextLen-sizeof(plainText)], sizeof(plainText)) == 0);
}

// Check that RSA OAEP mechanism properly validates all input parameters
void AsymEncryptDecryptTests::rsaOAEPParams(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey)
{
	// This is only supported combination of parameters
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_OAEP, NULL, 0 };
	CK_RV rv;

	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	mechanism.pParameter = &oaepParams;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	mechanism.ulParameterLen = sizeof(oaepParams);

	oaepParams.hashAlg = CKM_AES_CBC;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.hashAlg = CKM_SHA_1;
	oaepParams.mgf = CKG_MGF1_SHA256;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.mgf = CKG_MGF1_SHA1;
	oaepParams.source = CKZ_DATA_SPECIFIED - 1;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.source = CKZ_DATA_SPECIFIED;
	oaepParams.pSourceData = &oaepParams;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.ulSourceDataLen = sizeof(oaepParams);
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.pSourceData = NULL;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);
}

void AsymEncryptDecryptTests::testRsaEncryptDecrypt()
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

	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token public/private key pairs.
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPublicKey,hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rsaOAEPParams(hSessionRO,hPublicKey);
	rsaEncryptDecrypt(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
	rsaEncryptDecrypt(CKM_RSA_X_509,hSessionRO,hPublicKey,hPrivateKey);
	rsaEncryptDecrypt(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
}
