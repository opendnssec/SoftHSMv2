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
 SymmetricAlgorithmTests.cpp

 Contains test cases for symmetrical algorithms (i.e., AES and DES)
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "SymmetricAlgorithmTests.h"
#include "testconfig.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(SymmetricAlgorithmTests);

void SymmetricAlgorithmTests::setUp()
{
//    printf("\nObjectTests\n");

	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);

	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSession;

	CK_UTF8CHAR label[32];
	memset(label, ' ', 32);
	memcpy(label, "token1", strlen("token1"));

	// (Re)initialize the token
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_InitToken(SLOT_INIT_TOKEN, sopin,sopinLength, label);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login SO
	rv = C_Login(hSession,CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Initialize the user pin
	rv = C_InitPIN(hSession, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void SymmetricAlgorithmTests::tearDown()
{
	C_Finalize(NULL_PTR);
}

CK_RV SymmetricAlgorithmTests::generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

CK_RV SymmetricAlgorithmTests::generateDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

CK_RV SymmetricAlgorithmTests::generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES2_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

CK_RV SymmetricAlgorithmTests::generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

void SymmetricAlgorithmTests::aesEncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BYTE iv[16];
	CK_BYTE plainText[256];
	CK_BYTE cipherText[300];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[300];
	CK_ULONG ulRecoveredTextLen;
	CK_RV rv;

	rv = C_GenerateRandom(hSession, plainText, sizeof(plainText));
	CPPUNIT_ASSERT(rv==CKR_OK);

	if (mechanismType == CKM_AES_CBC)
	{
		rv = C_GenerateRandom(hSession, iv, sizeof(iv));
		CPPUNIT_ASSERT(rv==CKR_OK);
		mechanism.pParameter = iv;
		mechanism.ulParameterLen = sizeof(iv);
	}

	rv = C_EncryptInit(hSession,&mechanism,hKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulCipherTextLen = sizeof(cipherText);
	rv = C_Encrypt(hSession,plainText,sizeof(plainText),cipherText,&ulCipherTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulCipherTextLen==sizeof(plainText));

	rv = C_DecryptInit(hSession,&mechanism,hKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulRecoveredTextLen==sizeof(plainText));

	CPPUNIT_ASSERT(memcmp(plainText, recoveredText, sizeof(plainText)) == 0);
}

void SymmetricAlgorithmTests::desEncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BYTE iv[8];
	CK_BYTE plainText[256];
	CK_BYTE cipherText[300];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[300];
	CK_ULONG ulRecoveredTextLen;
	CK_RV rv;

	rv = C_GenerateRandom(hSession, plainText, sizeof(plainText));
	CPPUNIT_ASSERT(rv==CKR_OK);

	if (mechanismType == CKM_DES_CBC)
	{
		rv = C_GenerateRandom(hSession, iv, sizeof(iv));
		CPPUNIT_ASSERT(rv==CKR_OK);
		mechanism.pParameter = iv;
		mechanism.ulParameterLen = sizeof(iv);
	}

	rv = C_EncryptInit(hSession,&mechanism,hKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulCipherTextLen = sizeof(cipherText);
	rv = C_Encrypt(hSession,plainText,sizeof(plainText),cipherText,&ulCipherTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulCipherTextLen==sizeof(plainText));

	rv = C_DecryptInit(hSession,&mechanism,hKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulRecoveredTextLen==sizeof(plainText));

	CPPUNIT_ASSERT(memcmp(plainText, recoveredText, sizeof(plainText)) == 0);
}

void SymmetricAlgorithmTests::des3EncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BYTE iv[8];
	CK_BYTE plainText[256];
	CK_BYTE cipherText[300];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[300];
	CK_ULONG ulRecoveredTextLen;
	CK_RV rv;

	rv = C_GenerateRandom(hSession, plainText, sizeof(plainText));
	CPPUNIT_ASSERT(rv==CKR_OK);

	if (mechanismType == CKM_DES3_CBC)
	{
		rv = C_GenerateRandom(hSession, iv, sizeof(iv));
		CPPUNIT_ASSERT(rv==CKR_OK);
		mechanism.pParameter = iv;
		mechanism.ulParameterLen = sizeof(iv);
	}

	rv = C_EncryptInit(hSession,&mechanism,hKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulCipherTextLen = sizeof(cipherText);
	rv = C_Encrypt(hSession,plainText,sizeof(plainText),cipherText,&ulCipherTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulCipherTextLen==sizeof(plainText));

	rv = C_DecryptInit(hSession,&mechanism,hKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulRecoveredTextLen==sizeof(plainText));

	CPPUNIT_ASSERT(memcmp(plainText, recoveredText, sizeof(plainText)) == 0);
}

void SymmetricAlgorithmTests::testAesEncryptDecrypt()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Open read-only session on when the token is not initialized should fail
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateAesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	aesEncryptDecrypt(CKM_AES_ECB,hSessionRO,hKey);
	aesEncryptDecrypt(CKM_AES_CBC,hSessionRO,hKey);
}

void SymmetricAlgorithmTests::testDesEncryptDecrypt()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Open read-only session on when the token is not initialized should fail
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	desEncryptDecrypt(CKM_DES_ECB,hSessionRO,hKey);
	desEncryptDecrypt(CKM_DES_CBC,hSessionRO,hKey);

	CK_OBJECT_HANDLE hKey2 = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDes2Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey2);
	CPPUNIT_ASSERT(rv == CKR_OK);

	des3EncryptDecrypt(CKM_DES3_ECB,hSessionRO,hKey2);
	des3EncryptDecrypt(CKM_DES3_CBC,hSessionRO,hKey2);

	CK_OBJECT_HANDLE hKey3 = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDes3Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey3);
	CPPUNIT_ASSERT(rv == CKR_OK);

	des3EncryptDecrypt(CKM_DES3_ECB,hSessionRO,hKey3);
	des3EncryptDecrypt(CKM_DES3_CBC,hSessionRO,hKey3);
}
