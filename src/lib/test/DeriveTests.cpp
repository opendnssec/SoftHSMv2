/*
 * Copyright (c) 2014 SURFnet
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
 DeriveTests.cpp

 Contains test cases for:
	 C_DeriveKey

 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DeriveTests.h"
#include "testconfig.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(DeriveTests);

void DeriveTests::setUp()
{
//    printf("\nDeriveTests\n");

#ifndef _WIN32
	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);
#else
	setenv("SOFTHSM2_CONF", ".\\softhsm2.conf", 1);
#endif

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

void DeriveTests::tearDown()
{
	C_Finalize(NULL_PTR);
}

CK_RV DeriveTests::generateDhKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_BYTE bn1024[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
		0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
		0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
		0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22,
		0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
		0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b,
		0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
		0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
		0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
		0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b,
		0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
		0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5,
		0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6,
		0x49, 0x28, 0x66, 0x51, 0xec, 0xe6, 0x53, 0x81,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	CK_BYTE bn2[] = { 2 };
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_PRIME, &bn1024, sizeof(bn1024) },
		{ CKA_BASE, &bn2, sizeof(bn2) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return C_GenerateKeyPair(hSession, &mechanism,
			pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
			prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
			&hPuk, &hPrk);
}

CK_RV DeriveTests::generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) }
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

#ifndef WITH_FIPS
CK_RV DeriveTests::generateDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}
#endif

CK_RV DeriveTests::generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES2_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

CK_RV DeriveTests::generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

void DeriveTests::dhDerive(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_OBJECT_HANDLE &hKey)
{
	CK_ATTRIBUTE valAttrib = { CKA_VALUE, NULL_PTR, 0 };
	CK_RV rv = C_GetAttributeValue(hSession, hPublicKey, &valAttrib, 1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	valAttrib.pValue = (CK_BYTE_PTR)malloc(valAttrib.ulValueLen);
	rv = C_GetAttributeValue(hSession, hPublicKey, &valAttrib, 1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_MECHANISM mechanism = { CKM_DH_PKCS_DERIVE, NULL_PTR, 0 };
	mechanism.pParameter = valAttrib.pValue;
	mechanism.ulParameterLen = valAttrib.ulValueLen;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ULONG secLen = 100;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &secLen, sizeof(secLen) }
	};

	hKey = CK_INVALID_HANDLE;
	rv = C_DeriveKey(hSession, &mechanism, hPrivateKey,
			 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			 &hKey);
	free(valAttrib.pValue);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

bool DeriveTests::compareSecret(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey1, CK_OBJECT_HANDLE hKey2)
{
	CK_ATTRIBUTE valAttrib = { CKA_VALUE, NULL_PTR, 0 };
	CK_BYTE val1[128];
	valAttrib.pValue = val1;
	valAttrib.ulValueLen = sizeof(val1);
	CK_RV rv = C_GetAttributeValue(hSession, hKey1, &valAttrib, 1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(valAttrib.ulValueLen == 100);
	CK_BYTE val2[128];
	valAttrib.pValue = val2;
	valAttrib.ulValueLen = sizeof(val2);
	rv = C_GetAttributeValue(hSession, hKey2, &valAttrib, 1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(valAttrib.ulValueLen == 100);
	return memcmp(val1, val2, 100) == 0;
}

void DeriveTests::testDhDerive()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
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
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Public Session keys
        CK_OBJECT_HANDLE hPuk1 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hPrk1 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hPuk2 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hPrk2 = CK_INVALID_HANDLE;

        rv = generateDhKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk1,hPrk1);
        CPPUNIT_ASSERT(rv == CKR_OK);
        rv = generateDhKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk2,hPrk2);
        CPPUNIT_ASSERT(rv == CKR_OK);
	CK_OBJECT_HANDLE hKey1 = CK_INVALID_HANDLE;
	dhDerive(hSessionRW,hPuk1,hPrk2,hKey1);
	CK_OBJECT_HANDLE hKey2 = CK_INVALID_HANDLE;
	dhDerive(hSessionRW,hPuk2,hPrk1,hKey2);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Private Session Keys
        rv = generateDhKeyPair(hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk1,hPrk1);
        CPPUNIT_ASSERT(rv == CKR_OK);
        rv = generateDhKeyPair(hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk2,hPrk2);
        CPPUNIT_ASSERT(rv == CKR_OK);
	dhDerive(hSessionRW,hPuk1,hPrk2,hKey1);
	dhDerive(hSessionRW,hPuk2,hPrk1,hKey2);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Public Token Keys
        rv = generateDhKeyPair(hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk1,hPrk1);
        CPPUNIT_ASSERT(rv == CKR_OK);
        rv = generateDhKeyPair(hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk2,hPrk2);
        CPPUNIT_ASSERT(rv == CKR_OK);
	dhDerive(hSessionRW,hPuk1,hPrk2,hKey1);
	dhDerive(hSessionRW,hPuk2,hPrk1,hKey2);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Private Token Keys
        rv = generateDhKeyPair(hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk1,hPrk1);
        CPPUNIT_ASSERT(rv == CKR_OK);
        rv = generateDhKeyPair(hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk2,hPrk2);
        CPPUNIT_ASSERT(rv == CKR_OK);
	dhDerive(hSessionRW,hPuk1,hPrk2,hKey1);
	dhDerive(hSessionRW,hPuk2,hPrk1,hKey2);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));
}

void DeriveTests::symDerive(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_OBJECT_HANDLE &hDerive, CK_MECHANISM_TYPE mechType, CK_KEY_TYPE keyType)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechType, NULL_PTR, 0 };
	CK_MECHANISM mechEncrypt = { CKM_VENDOR_DEFINED, NULL_PTR, 0 };
	CK_KEY_DERIVATION_STRING_DATA param1;
	CK_DES_CBC_ENCRYPT_DATA_PARAMS param2;
	CK_AES_CBC_ENCRYPT_DATA_PARAMS param3;

	CK_BYTE data[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
		0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
		0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32
	};
	CK_ULONG secLen = 0;

	switch (mechType)
	{
		case CKM_DES_ECB_ENCRYPT_DATA:
		case CKM_DES3_ECB_ENCRYPT_DATA:
		case CKM_AES_ECB_ENCRYPT_DATA:
			param1.pData = &data[0];
			param1.ulLen = sizeof(data);
			mechanism.pParameter = &param1;
			mechanism.ulParameterLen = sizeof(param1);
			break;
		case CKM_DES_CBC_ENCRYPT_DATA:
		case CKM_DES3_CBC_ENCRYPT_DATA:
			memcpy(param2.iv, "12345678", 8);
			param2.pData = &data[0];
			param2.length = sizeof(data);
			mechanism.pParameter = &param2;
			mechanism.ulParameterLen = sizeof(param2);
			break;
		case CKM_AES_CBC_ENCRYPT_DATA:
			memcpy(param3.iv, "1234567890ABCDEF", 16);
			param3.pData = &data[0];
			param3.length = sizeof(data);
			mechanism.pParameter = &param3;
			mechanism.ulParameterLen = sizeof(param3);
			break;
		default:
			CPPUNIT_FAIL("Invalid mechanism");
	}

	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			secLen = 32;
			break;
		case CKK_DES:
			mechEncrypt.mechanism = CKM_DES_ECB;
			break;
		case CKK_DES2:
		case CKK_DES3:
			mechEncrypt.mechanism = CKM_DES3_ECB;
			break;
		case CKK_AES:
			mechEncrypt.mechanism = CKM_AES_ECB;
			secLen = 32;
			break;
		default:
			CPPUNIT_FAIL("Invalid key type");
	}

	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &secLen, sizeof(secLen) }
	};

	hDerive = CK_INVALID_HANDLE;
	if (secLen > 0)
	{
		rv = C_DeriveKey(hSession, &mechanism, hKey,
				 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
				 &hDerive);
	}
	else
	{
		rv = C_DeriveKey(hSession, &mechanism, hKey,
				 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE) - 1,
				 &hDerive);
	}
	CPPUNIT_ASSERT(rv == CKR_OK);

	if (keyType == CKK_GENERIC_SECRET) return;

	CK_BYTE cipherText[300];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[300];
	CK_ULONG ulRecoveredTextLen;

	rv = C_EncryptInit(hSession,&mechEncrypt,hDerive);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulCipherTextLen = sizeof(cipherText);
	rv = C_Encrypt(hSession,data,sizeof(data),cipherText,&ulCipherTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = C_DecryptInit(hSession,&mechEncrypt,hDerive);
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulRecoveredTextLen==sizeof(data));

	CPPUNIT_ASSERT(memcmp(data, recoveredText, sizeof(data)) == 0);
}

void DeriveTests::testSymDerive()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
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

	// Login USER into the sessions so we can create private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Generate base key
#ifndef WITH_FIPS
        CK_OBJECT_HANDLE hKeyDes = CK_INVALID_HANDLE;
#endif
        CK_OBJECT_HANDLE hKeyDes2 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hKeyDes3 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hKeyAes = CK_INVALID_HANDLE;
#ifndef WITH_FIPS
        rv = generateDesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKeyDes);
        CPPUNIT_ASSERT(rv == CKR_OK);
#endif
        rv = generateDes2Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKeyDes2);
        CPPUNIT_ASSERT(rv == CKR_OK);
        rv = generateDes3Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKeyDes3);
        CPPUNIT_ASSERT(rv == CKR_OK);
        rv = generateAesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKeyAes);
        CPPUNIT_ASSERT(rv == CKR_OK);

	// Derive keys
	CK_OBJECT_HANDLE hDerive = CK_INVALID_HANDLE;
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_ECB_ENCRYPT_DATA,CKK_GENERIC_SECRET);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_ECB_ENCRYPT_DATA,CKK_DES);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_ECB_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_ECB_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_ECB_ENCRYPT_DATA,CKK_AES);
#endif
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_GENERIC_SECRET);
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_DES);
#endif
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_AES);
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_GENERIC_SECRET);
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_DES);
#endif
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_ECB_ENCRYPT_DATA,CKK_AES);
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_ECB_ENCRYPT_DATA,CKK_GENERIC_SECRET);
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_ECB_ENCRYPT_DATA,CKK_DES);
#endif
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_ECB_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_ECB_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_ECB_ENCRYPT_DATA,CKK_AES);
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_CBC_ENCRYPT_DATA,CKK_GENERIC_SECRET);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_CBC_ENCRYPT_DATA,CKK_DES);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_CBC_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_CBC_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyDes,hDerive,CKM_DES_CBC_ENCRYPT_DATA,CKK_AES);
#endif
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_GENERIC_SECRET);
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_DES);
#endif
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyDes2,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_AES);
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_GENERIC_SECRET);
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_DES);
#endif
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyDes3,hDerive,CKM_DES3_CBC_ENCRYPT_DATA,CKK_AES);
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_CBC_ENCRYPT_DATA,CKK_GENERIC_SECRET);
#ifndef WITH_FIPS
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_CBC_ENCRYPT_DATA,CKK_DES);
#endif
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_CBC_ENCRYPT_DATA,CKK_DES2);
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_CBC_ENCRYPT_DATA,CKK_DES3);
	symDerive(hSessionRW,hKeyAes,hDerive,CKM_AES_CBC_ENCRYPT_DATA,CKK_AES);
}

