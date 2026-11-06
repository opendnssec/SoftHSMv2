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
#include "AsymWrapUnwrapTests.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PUBLIC = CK_FALSE;
const CK_BBOOL IS_PRIVATE = CK_TRUE;

CPPUNIT_TEST_SUITE_REGISTRATION(AsymWrapUnwrapTests);

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
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

CK_RV AsymWrapUnwrapTests::generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 1536;
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS pvtClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{ CKA_ENCRYPT,&bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_CLASS, &pvtClass, sizeof(pvtClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue)},
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk) );
}

void AsymWrapUnwrapTests::rsaWrapUnwrapPvt(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_RV rv = CKR_OK;
	CK_MECHANISM_INFO mechInfo;
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_RSA_AES_KEY_WRAP_PARAMS rsa_aes_params = { 256, &oaepParams };
	CK_MECHANISM mechanism = {CKM_RSA_AES_KEY_WRAP, &rsa_aes_params, sizeof(rsa_aes_params)};
	CK_MECHANISM sv_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,0x0C, 0x0D, 0x0F };
	CK_BYTE signature[256];
	CK_ULONG ulSignatureLen = 0;
	CK_BYTE cipherText[2048];
	CK_ULONG ulCipherTextLen = 0;
	CK_ULONG wrappedLenEstimation = 0;
	CK_OBJECT_HANDLE targetPvtKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE targetPubKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE unwrappedKey = CK_INVALID_HANDLE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ATTRIBUTE unwrapTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	// Generate temporary asymmetric key pair
	rv = generateRsaKeyPair( hSession, IN_SESSION, IS_PRIVATE, IN_SESSION, IS_PRIVATE, targetPubKey, targetPvtKey );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check if the specified mechanism supports Wrap/Unwrap
	rv = CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, CKM_RSA_AES_KEY_WRAP, &mechInfo) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_WRAP);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_UNWRAP);

	// Estimate wrapped length
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, targetPvtKey, NULL_PTR, &wrappedLenEstimation) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(wrappedLenEstimation>0);

	// This should always fail because wrapped data have to be longer than 0 bytes
	ulCipherTextLen = 0;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, targetPvtKey, cipherText, &ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_BUFFER_TOO_SMALL);

	// Do real wrapping
	ulCipherTextLen = sizeof(cipherText);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, targetPvtKey, cipherText, &ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(wrappedLenEstimation==ulCipherTextLen);

	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hPrivateKey, cipherText, ulCipherTextLen, unwrapTemplate, sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE), &unwrappedKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(unwrappedKey != CK_INVALID_HANDLE);

	// Verify the private key is unwrapped properly
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &sv_mechanism, unwrappedKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulSignatureLen = sizeof(signature);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession, data, sizeof(data), signature, &ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &sv_mechanism, targetPubKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Verify(hSession, data, sizeof(data), signature, ulSignatureLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);
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

	if (mechanismType == CKM_RSA_AES_KEY_WRAP)
	{
		rsaWrapUnwrapPvt(hSession, hPublicKey, hPrivateKey);
		return;
	}

	// Generate temporary symmetric key and remember it's value
	rv = generateAesKey(hSession, symKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, symKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	ulSymValueLen = valueTemplate[0].ulValueLen;

	// Check if the specified mechanism supports Wrap/Unwrap
	rv = CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, mechanismType, &mechInfo) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_WRAP);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_UNWRAP);

	// Estimate wrapped length
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, NULL_PTR, &wrappedLenEstimation) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(wrappedLenEstimation>0);

	// This should always fail because wrapped data have to be longer than 0 bytes
	ulCipherTextLen = 0;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_BUFFER_TOO_SMALL);

	// Do real wrapping
	ulCipherTextLen = sizeof(cipherText);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	// Check length 'estimation'
	CPPUNIT_ASSERT(wrappedLenEstimation>=ulCipherTextLen);

	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hPrivateKey, cipherText, ulCipherTextLen, unwrapTemplate, sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE), &unwrappedKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	valueTemplate[0].pValue = &unwrappedValue;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, unwrappedKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	ulUnwrappedValueLen = valueTemplate[0].ulValueLen;

	CPPUNIT_ASSERT(ulSymValueLen == ulUnwrappedValueLen);
	CPPUNIT_ASSERT(memcmp(symValue, unwrappedValue, ulSymValueLen) == 0);
}

void AsymWrapUnwrapTests::testRsaWrapUnwrap()
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
	// Public Session Keys
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPublicKey,hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rsaWrapUnwrap(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_AES_KEY_WRAP, hSessionRO, hPublicKey, hPrivateKey);

	// Private Session Keys
	rv = generateRsaKeyPair(hSessionRW, IN_SESSION, IS_PRIVATE, IN_SESSION, IS_PRIVATE, hPublicKey, hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rsaWrapUnwrap(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_AES_KEY_WRAP, hSessionRO, hPublicKey, hPrivateKey);

	// Public Token Keys
	rv = generateRsaKeyPair(hSessionRW, ON_TOKEN, IS_PUBLIC, ON_TOKEN, IS_PUBLIC, hPublicKey, hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rsaWrapUnwrap(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_AES_KEY_WRAP, hSessionRO, hPublicKey, hPrivateKey);

	// Private Token Keys
	rv = generateRsaKeyPair(hSessionRW, ON_TOKEN, IS_PRIVATE, ON_TOKEN, IS_PRIVATE, hPublicKey, hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rsaWrapUnwrap(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
	rsaWrapUnwrap(CKM_RSA_AES_KEY_WRAP, hSessionRO, hPublicKey, hPrivateKey);
}

// Reproducer: CKA_WRAP_TEMPLATE entries that carry a byte string value
// (e.g. CKA_LABEL) must match against the PLAINTEXT attribute of the key
// being wrapped. Byte string attributes of a private object are stored
// encrypted, so comparing the raw stored value against the caller supplied
// template can never match and C_WrapKey wrongly returns
// CKR_KEY_NOT_WRAPPABLE for a key that does satisfy the template.
void AsymWrapUnwrapTests::testWrapTemplatePrivateAttribute()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_UTF8CHAR label[] = "authorized";
	CK_UTF8CHAR otherLabel[] = "unauthorized";

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	// Wrapping key restricted to secrets labelled "authorized"
	CK_ATTRIBUTE wrapTemplate[] = {
		{ CKA_LABEL, label, sizeof(label) - 1 }
	};

	CK_BBOOL bTrue = CK_TRUE;
	CK_ULONG modulusBits = 1536;
	CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
	CK_MECHANISM keyGenMech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
		{ CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent) },
		{ CKA_WRAP_TEMPLATE, wrapTemplate, sizeof(wrapTemplate) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTrue, sizeof(bTrue) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) }
	};

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &keyGenMech,
		pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
		prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE), &hPuk, &hPrk) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	CK_MECHANISM wrapMech = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE wrapped[1024];
	CK_ULONG wrappedLen;

	CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_BYTE secretValue[16] = { 0 };

	// A PRIVATE secret whose label satisfies the template: must be wrappable
	CK_ATTRIBUTE matching[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genericType, sizeof(genericType) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, secretValue, sizeof(secretValue) },
		{ CKA_TOKEN, &bTrue, sizeof(bTrue) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hMatching = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, matching,
		sizeof(matching)/sizeof(CK_ATTRIBUTE), &hMatching) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	wrappedLen = sizeof(wrapped);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &wrapMech, hPuk, hMatching, wrapped, &wrappedLen) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	// A PRIVATE secret whose label does not satisfy the template: must be refused
	CK_ATTRIBUTE nonMatching[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genericType, sizeof(genericType) },
		{ CKA_LABEL, otherLabel, sizeof(otherLabel) - 1 },
		{ CKA_VALUE, secretValue, sizeof(secretValue) },
		{ CKA_TOKEN, &bTrue, sizeof(bTrue) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hNonMatching = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, nonMatching,
		sizeof(nonMatching)/sizeof(CK_ATTRIBUTE), &hNonMatching) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	wrappedLen = sizeof(wrapped);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &wrapMech, hPuk, hNonMatching, wrapped, &wrappedLen) );
	CPPUNIT_ASSERT_EQUAL(CKR_KEY_NOT_WRAPPABLE, rv);

	// A PRIVATE secret carrying no CKA_LABEL at all: must also be refused.
	// The attribute defaults to an empty byte string, so this exercises the
	// path where the key side of the comparison decrypts to nothing rather
	// than to a differing value -- the template must still not match.
	CK_ATTRIBUTE noLabel[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genericType, sizeof(genericType) },
		{ CKA_VALUE, secretValue, sizeof(secretValue) },
		{ CKA_TOKEN, &bTrue, sizeof(bTrue) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hNoLabel = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, noLabel,
		sizeof(noLabel)/sizeof(CK_ATTRIBUTE), &hNoLabel) );
	CPPUNIT_ASSERT_EQUAL(CKR_OK, rv);

	wrappedLen = sizeof(wrapped);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &wrapMech, hPuk, hNoLabel, wrapped, &wrappedLen) );
	CPPUNIT_ASSERT_EQUAL(CKR_KEY_NOT_WRAPPABLE, rv);

	CRYPTOKI_F_PTR( C_Logout(hSession) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}
