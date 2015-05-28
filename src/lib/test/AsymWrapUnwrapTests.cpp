/*
 * Copyright (c) 2014 Red Hat
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
 AsymWrapUnwrapTests.cpp

 Contains test cases for C_WrapKey and C_UnwrapKey
 using asymmetrical algorithms (RSA)
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "AsymWrapUnwrapTests.h"
#include "testconfig.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(AsymWrapUnwrapTests);

void AsymWrapUnwrapTests::setUp()
{
//    printf("\nObjectTests\n");

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

void AsymWrapUnwrapTests::tearDown()
{
	C_Finalize(NULL_PTR);
}

// Generate throw-away (session) symmetric key
CK_RV AsymWrapUnwrapTests::generateAesKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bTrue) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
	};

	hKey = CK_INVALID_HANDLE;
	return C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey);
}

CK_RV AsymWrapUnwrapTests::generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
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
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bFalse, sizeof(bFalse) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk);
}

void AsymWrapUnwrapTests::rsaWrapUnwrap(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_BYTE cipherText[2048];
	CK_ULONG ulCipherTextLen;
	CK_BYTE symValue[64];
	CK_ULONG ulSymValueLen = sizeof(symValue);
	CK_BYTE unwrappedValue[64];
	CK_ULONG ulUnwrappedValueLen = sizeof(unwrappedValue);
	CK_OBJECT_HANDLE symKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE unwrappedKey = CK_INVALID_HANDLE;
	CK_RV rv;
	CK_ULONG wrappedLenEstimation;

	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE unwrapTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	CK_ATTRIBUTE valueTemplate[] = {
		{ CKA_VALUE, &symValue, ulSymValueLen }
	};

	CK_MECHANISM_INFO mechInfo;

	if (mechanismType == CKM_RSA_PKCS_OAEP)
	{
		mechanism.pParameter = &oaepParams;
		mechanism.ulParameterLen = sizeof(oaepParams);
	}

	// Generate temporary symmetric key and remember it's value
	rv = generateAesKey(hSession, symKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = C_GetAttributeValue(hSession, symKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE));
	CPPUNIT_ASSERT(rv==CKR_OK);
	ulSymValueLen = valueTemplate[0].ulValueLen;

	// CKM_RSA_PKCS Wrap/Unwrap support
	rv = C_GetMechanismInfo(SLOT_INIT_TOKEN, CKM_RSA_PKCS, &mechInfo);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_WRAP);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_UNWRAP);

	// Estimate wrapped length
	rv = C_WrapKey(hSession, &mechanism, hPublicKey, symKey, NULL_PTR, &wrappedLenEstimation);
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(wrappedLenEstimation>0);

	// This should always fail because wrapped data have to be longer than 0 bytes
	ulCipherTextLen = 0;
	rv = C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen);
	CPPUNIT_ASSERT(rv==CKR_BUFFER_TOO_SMALL);

	// Do real wrapping
	ulCipherTextLen = sizeof(cipherText);
	rv = C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen);
	CPPUNIT_ASSERT(rv==CKR_OK);
	// Check length 'estimation'
	CPPUNIT_ASSERT(wrappedLenEstimation>=ulCipherTextLen);

	rv = C_UnwrapKey(hSession, &mechanism, hPrivateKey, cipherText, ulCipherTextLen, unwrapTemplate, sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE), &unwrappedKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	valueTemplate[0].pValue = &unwrappedValue;
	rv = C_GetAttributeValue(hSession, unwrappedKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE));
	CPPUNIT_ASSERT(rv==CKR_OK);
	ulUnwrappedValueLen = valueTemplate[0].ulValueLen;

	CPPUNIT_ASSERT(ulSymValueLen == ulUnwrappedValueLen);
	CPPUNIT_ASSERT(memcmp(symValue, unwrappedValue, ulSymValueLen) == 0);
}

void AsymWrapUnwrapTests::testRsaWrapUnwrap()
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
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token public/private key pairs.
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPublicKey,hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rsaWrapUnwrap(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
}
