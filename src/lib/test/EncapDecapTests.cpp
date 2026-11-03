/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 EncapDecapTests.cpp

 Contains test cases for C_EncapsulateKey and C_DecapsulateKey
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "EncapDecapTests.h"

#if defined(WITH_ML_KEM) || defined(WITH_X_WING)
const CK_BBOOL IN_SESSION = CK_FALSE;
const CK_BBOOL ON_TOKEN = CK_TRUE;

const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;
#endif
#ifdef WITH_X_WING
const CK_ULONG X_WING_CIPHERTEXT_LENGTH = 1120;
#endif

CPPUNIT_TEST_SUITE_REGISTRATION(EncapDecapTests);

#ifdef WITH_X_WING
CK_RV EncapDecapTests::generateXWing(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_X_WING_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_X_WING;
	CK_BYTE label[] = { 0x12, 0x34 };
	CK_BYTE id[] = { 123 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_ENCAPSULATE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_DECAPSULATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
		pukAttribs, sizeof(pukAttribs) / sizeof(CK_ATTRIBUTE),
		prkAttribs, sizeof(prkAttribs) / sizeof(CK_ATTRIBUTE),
		&hPuk, &hPrk) );
}

void EncapDecapTests::testXWingEncapsulation()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_SESSION_HANDLE hSession;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	const CK_BBOOL tokenValues[] = {
		IN_SESSION, IN_SESSION, ON_TOKEN, ON_TOKEN
	};
	const CK_BBOOL privateValues[] = {
		IS_PUBLIC, IS_PRIVATE, IS_PUBLIC, IS_PRIVATE
	};
	for (size_t i = 0; i < sizeof(tokenValues) / sizeof(tokenValues[0]); i++)
	{
		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
		rv = generateXWing(hSession, tokenValues[i], privateValues[i],
		                   tokenValues[i], privateValues[i], hPuk, hPrk);
		CPPUNIT_ASSERT(rv == CKR_OK);
		CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
		CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

		encapsulateXWing(hSession, hPuk);

		rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
		CPPUNIT_ASSERT(rv == CKR_OK);
		rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
		CPPUNIT_ASSERT(rv == CKR_OK);
	}

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::encapsulateXWing(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hPublicKey)
{
	CK_MECHANISM mechanism = { CKM_X_WING, NULL_PTR, 0 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG valueLen = 32;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) }
	};

	CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
	CK_ULONG ulCipherTextLen = 0;
	CK_RV rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism,
		hPublicKey,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
		NULL_PTR, &ulCipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(ulCipherTextLen == X_WING_CIPHERTEXT_LENGTH);
	CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);

	CK_BYTE cipherText[X_WING_CIPHERTEXT_LENGTH];
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hPublicKey,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
		cipherText, &ulCipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(ulCipherTextLen == X_WING_CIPHERTEXT_LENGTH);
	CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);

	CK_KEY_TYPE storedKeyType = CKK_VENDOR_DEFINED;
	CK_ULONG storedValueLen = 0;
	CK_BBOOL canEncrypt = CK_FALSE;
	CK_BBOOL canDecrypt = CK_FALSE;
	CK_ATTRIBUTE storedAttribs[] = {
		{ CKA_KEY_TYPE, &storedKeyType, sizeof(storedKeyType) },
		{ CKA_VALUE_LEN, &storedValueLen, sizeof(storedValueLen) },
		{ CKA_ENCRYPT, &canEncrypt, sizeof(canEncrypt) },
		{ CKA_DECRYPT, &canDecrypt, sizeof(canDecrypt) }
	};
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hEncapKey,
		storedAttribs, sizeof(storedAttribs) / sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(storedKeyType == CKK_AES);
	CPPUNIT_ASSERT(storedValueLen == valueLen);
	CPPUNIT_ASSERT(canEncrypt == CK_TRUE);
	CPPUNIT_ASSERT(canDecrypt == CK_TRUE);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testXWingEncapsulationDecapsulation()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_SESSION_HANDLE hSession;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1,
		m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	const CK_BBOOL tokenValues[] = {
		IN_SESSION, IN_SESSION, ON_TOKEN, ON_TOKEN
	};
	const CK_BBOOL privateValues[] = {
		IS_PUBLIC, IS_PRIVATE, IS_PUBLIC, IS_PRIVATE
	};
	for (size_t i = 0; i < sizeof(tokenValues) / sizeof(tokenValues[0]); i++)
	{
		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
		rv = generateXWing(hSession, tokenValues[i], privateValues[i],
		                   tokenValues[i], privateValues[i], hPuk, hPrk);
		CPPUNIT_ASSERT(rv == CKR_OK);
		CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
		CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

		encapsulateDecapsulateXWing(hSession, hPuk, hPrk);

		rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
		CPPUNIT_ASSERT(rv == CKR_OK);
		rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
		CPPUNIT_ASSERT(rv == CKR_OK);
	}

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::encapsulateDecapsulateXWing(
	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey,
	CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mechanism = { CKM_X_WING, NULL_PTR, 0 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG valueLen = 32;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) }
	};
	CK_BYTE cipherText[X_WING_CIPHERTEXT_LENGTH];
	CK_ULONG cipherTextLen = sizeof(cipherText);
	CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism,
		hPublicKey,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		&cipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(cipherTextLen == X_WING_CIPHERTEXT_LENGTH);
	CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);

	CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrivateKey,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hDecapKey != CK_INVALID_HANDLE);

	CK_BYTE encapCheckValue[32];
	CK_BYTE decapCheckValue[32];
	CK_ATTRIBUTE encapCheckValueAttrib = {
		CKA_CHECK_VALUE, encapCheckValue, sizeof(encapCheckValue)
	};
	CK_ATTRIBUTE decapCheckValueAttrib = {
		CKA_CHECK_VALUE, decapCheckValue, sizeof(decapCheckValue)
	};
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hEncapKey,
		&encapCheckValueAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hDecapKey,
		&decapCheckValueAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(encapCheckValueAttrib.ulValueLen ==
	               decapCheckValueAttrib.ulValueLen);
	CPPUNIT_ASSERT(memcmp(encapCheckValue, decapCheckValue,
	                      encapCheckValueAttrib.ulValueLen) == 0);

	CK_KEY_TYPE storedKeyType = CKK_VENDOR_DEFINED;
	CK_ULONG storedValueLen = 0;
	CK_BBOOL canEncrypt = CK_FALSE;
	CK_BBOOL canDecrypt = CK_FALSE;
	CK_ATTRIBUTE storedAttribs[] = {
		{ CKA_KEY_TYPE, &storedKeyType, sizeof(storedKeyType) },
		{ CKA_VALUE_LEN, &storedValueLen, sizeof(storedValueLen) },
		{ CKA_ENCRYPT, &canEncrypt, sizeof(canEncrypt) },
		{ CKA_DECRYPT, &canDecrypt, sizeof(canDecrypt) }
	};
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hDecapKey,
		storedAttribs, sizeof(storedAttribs) / sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(storedKeyType == CKK_AES);
	CPPUNIT_ASSERT(storedValueLen == valueLen);
	CPPUNIT_ASSERT(canEncrypt == CK_TRUE);
	CPPUNIT_ASSERT(canDecrypt == CK_TRUE);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testXWingEncapsulationBufferTooSmall()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_SESSION_HANDLE hSession;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1,
		m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	rv = generateXWing(hSession, IN_SESSION, IS_PUBLIC, IN_SESSION,
	                    IS_PRIVATE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_MECHANISM mechanism = { CKM_X_WING, NULL_PTR, 0 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_BYTE cipherText[X_WING_CIPHERTEXT_LENGTH - 1];
	CK_ULONG ulCipherTextLen = sizeof(cipherText);
	CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hPuk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		&ulCipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);
	CPPUNIT_ASSERT(ulCipherTextLen == X_WING_CIPHERTEXT_LENGTH);
	CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testXWingEncapsulationInvalidInputs()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_SESSION_HANDLE hSession;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1,
		m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	rv = generateXWing(hSession, IN_SESSION, IS_PUBLIC, IN_SESSION,
	                    IS_PRIVATE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_MECHANISM mechanism = { CKM_X_WING, NULL_PTR, 0 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_BYTE cipherText[X_WING_CIPHERTEXT_LENGTH];
	CK_ULONG ulCipherTextLen = sizeof(cipherText);
	CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hPuk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		NULL_PTR, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);
	CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);

	CK_BBOOL bFalse = CK_FALSE;
	CK_ATTRIBUTE encapsulateAttrib = {
		CKA_ENCAPSULATE, &bFalse, sizeof(bFalse)
	};
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPuk,
		&encapsulateAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hPuk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		&ulCipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_KEY_FUNCTION_NOT_PERMITTED);
	CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);

	CK_BBOOL bTrue = CK_TRUE;
	encapsulateAttrib.pValue = &bTrue;
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPuk,
		&encapsulateAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_CLASS invalidClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE invalidClassAttribs[] = {
		{ CKA_CLASS, &invalidClass, sizeof(invalidClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hPuk,
		invalidClassAttribs,
		sizeof(invalidClassAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		&ulCipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);

	CK_BYTE suppliedValue[32] = { 0 };
	CK_ATTRIBUTE valueAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE, suppliedValue, sizeof(suppliedValue) }
	};
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hPuk,
		valueAttribs, sizeof(valueAttribs) / sizeof(CK_ATTRIBUTE),
		cipherText, &ulCipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);
	CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);

#ifdef WITH_ML_KEM
	CK_OBJECT_HANDLE hMLKEMPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hMLKEMPrk = CK_INVALID_HANDLE;
	rv = generateMLKEM(CKP_ML_KEM_512, hSession, IN_SESSION, IS_PUBLIC,
	                   IN_SESSION, IS_PRIVATE, hMLKEMPuk, hMLKEMPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	ulCipherTextLen = sizeof(cipherText);
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hMLKEMPuk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		&ulCipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hMLKEMPuk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hMLKEMPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
#endif

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testXWingDecapsulationInvalidInputs()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_SESSION_HANDLE hSession;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1,
		m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	rv = generateXWing(hSession, IN_SESSION, IS_PUBLIC, IN_SESSION,
	                    IS_PRIVATE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_MECHANISM mechanism = { CKM_X_WING, NULL_PTR, 0 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_BYTE cipherText[X_WING_CIPHERTEXT_LENGTH];
	CK_ULONG cipherTextLen = sizeof(cipherText);
	CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mechanism, hPuk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		&cipherTextLen, &hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), NULL_PTR,
		cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		cipherTextLen - 1, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	CK_BYTE longCipherText[X_WING_CIPHERTEXT_LENGTH + 1];
	memcpy(longCipherText, cipherText, cipherTextLen);
	longCipherText[X_WING_CIPHERTEXT_LENGTH] = 0;
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), longCipherText,
		sizeof(longCipherText), &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		0, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	CK_BBOOL bFalse = CK_FALSE;
	CK_ATTRIBUTE decapsulateAttrib = {
		CKA_DECAPSULATE, &bFalse, sizeof(bFalse)
	};
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPrk,
		&decapsulateAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_KEY_FUNCTION_NOT_PERMITTED);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	CK_BBOOL bTrue = CK_TRUE;
	decapsulateAttrib.pValue = &bTrue;
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPrk,
		&decapsulateAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_BYTE label[] = "xwing-invalid-decap";
	CK_OBJECT_CLASS invalidClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE invalidClassAttribs[] = {
		{ CKA_CLASS, &invalidClass, sizeof(invalidClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, label, sizeof(label) }
	};
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		invalidClassAttribs,
		sizeof(invalidClassAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	CK_KEY_TYPE invalidKeyType = CKK_RSA;
	CK_ATTRIBUTE invalidTypeAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &invalidKeyType, sizeof(invalidKeyType) },
		{ CKA_LABEL, label, sizeof(label) }
	};
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		invalidTypeAttribs,
		sizeof(invalidTypeAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	CK_BYTE suppliedValue[32] = { 0 };
	CK_ATTRIBUTE valueAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, label, sizeof(label) },
		{ CKA_VALUE, suppliedValue, sizeof(suppliedValue) }
	};
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		valueAttribs, sizeof(valueAttribs) / sizeof(CK_ATTRIBUTE),
		cipherText, cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	CK_ULONG invalidValueLen = 10;
	CK_ATTRIBUTE valueLenAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, label, sizeof(label) },
		{ CKA_VALUE_LEN, &invalidValueLen, sizeof(invalidValueLen) }
	};
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		valueLenAttribs, sizeof(valueLenAttribs) / sizeof(CK_ATTRIBUTE),
		cipherText, cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	invalidValueLen = 33;
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		valueLenAttribs, sizeof(valueLenAttribs) / sizeof(CK_ATTRIBUTE),
		cipherText, cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_WRAPPED_KEY_LEN_RANGE);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

#ifdef WITH_ML_KEM
	CK_OBJECT_HANDLE hMLKEMPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hMLKEMPrk = CK_INVALID_HANDLE;
	rv = generateMLKEM(CKP_ML_KEM_512, hSession, IN_SESSION, IS_PUBLIC,
	                   IN_SESSION, IS_PRIVATE, hMLKEMPuk, hMLKEMPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hMLKEMPrk,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_KEY_TYPE_INCONSISTENT);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hMLKEMPuk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hMLKEMPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
#endif

	memset(cipherText + X_WING_CIPHERTEXT_LENGTH - 32, 0, 32);
	invalidValueLen = 32;
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mechanism, hPrk,
		valueLenAttribs, sizeof(valueLenAttribs) / sizeof(CK_ATTRIBUTE), cipherText,
		cipherTextLen, &hDecapKey) );
	CPPUNIT_ASSERT(rv == CKR_GENERAL_ERROR);
	CPPUNIT_ASSERT(hDecapKey == CK_INVALID_HANDLE);

	CK_ATTRIBUTE findAttrib = { CKA_LABEL, label, sizeof(label) };
	rv = CRYPTOKI_F_PTR( C_FindObjectsInit(hSession, &findAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_OBJECT_HANDLE hFound = CK_INVALID_HANDLE;
	CK_ULONG foundCount = 0;
	rv = CRYPTOKI_F_PTR( C_FindObjects(hSession, &hFound, 1, &foundCount) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(foundCount == 0);
	rv = CRYPTOKI_F_PTR( C_FindObjectsFinal(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hEncapKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

#endif

#ifdef WITH_ML_KEM
CK_RV EncapDecapTests::generateMLKEM(CK_ULONG parameterSet, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_ML_KEM;
	CK_BYTE label[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_ENCAPSULATE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_DECAPSULATE, &bTrue, sizeof(bFalse) },
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

void EncapDecapTests::testMLKEMEncapsulationDecapsulation(CK_ULONG parameterSet)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    CK_BYTE encapKCV[64];
    CK_ULONG encapKCVLen = sizeof(encapKCV);
    CK_ATTRIBUTE getEncapKCVAttrib = { CKA_CHECK_VALUE, encapKCV, encapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hEncapKey, &getEncapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    encapKCVLen = getEncapKCVAttrib.ulValueLen;

    // Test decapsulation - recover the shared secret using the ciphertext
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        ulCipherTextLen,
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hDecapKey != CK_INVALID_HANDLE);

    // Verify that the decapsulated key has the same value as the encapsulated key
    CK_BYTE decapKCV[64];
    CK_ULONG decapKCVLen = sizeof(decapKCV);
    CK_ATTRIBUTE getDecapKCVAttrib = { CKA_CHECK_VALUE, decapKCV, decapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hDecapKey, &getDecapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    decapKCVLen = getDecapKCVAttrib.ulValueLen;

    CPPUNIT_ASSERT(encapKCVLen == decapKCVLen);
    CPPUNIT_ASSERT(memcmp(encapKCV, decapKCV, encapKCVLen) == 0);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hDecapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMEncapsulationCiphertextIsNull()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_ULONG ulCipherTextLen = sizeof(CK_ULONG);

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        NULL_PTR,  // Passing NULL_PTR for ciphertext to test behavior
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMDecapsulationCiphertextLengthIsZero()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    // Test decapsulation - recover the shared secret using the ciphertext
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        0,  // Passing 0 for ciphertext length to test behavior
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMDecapsulationCiphertextIsNull()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    // Test decapsulation - recover the shared secret using the ciphertext
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        NULL_PTR,  // Passing NULL_PTR for ciphertext to test behavior
        ulCipherTextLen,
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMEncapsulationDecapsulationWithValueLen(CK_ULONG ulValueLen)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

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

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation with specific key length
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &ulValueLen, sizeof(ulValueLen) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    // Verify the decapsulated key has the correct length
    CK_ULONG encapKeyLength = 0;
    CK_ULONG encapKeyLengthLen = sizeof(encapKeyLength);
    CK_ATTRIBUTE getEncapKeyValueAttrib = { CKA_VALUE_LEN, &encapKeyLength, encapKeyLengthLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hEncapKey, &getEncapKeyValueAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(encapKeyLength == ulValueLen);

    // Get key check value for encapsulated key
    CK_BYTE encapKCV[64];
    CK_ULONG encapKCVLen = sizeof(encapKCV);
    CK_ATTRIBUTE getEncapKCVAttrib = { CKA_CHECK_VALUE, encapKCV, encapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hEncapKey, &getEncapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    encapKCVLen = getEncapKCVAttrib.ulValueLen;

    // Test decapsulation with specific key length
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &ulValueLen, sizeof(ulValueLen) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        ulCipherTextLen,
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hDecapKey != CK_INVALID_HANDLE);

    // Verify the decapsulated key has the correct length
    CK_ULONG decapKeyLength = 0;
    CK_ULONG decapKeyLengthLen = sizeof(decapKeyLength);
    CK_ATTRIBUTE getDecapKeyValueAttrib = { CKA_VALUE_LEN, &decapKeyLength, decapKeyLengthLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hDecapKey, &getDecapKeyValueAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(decapKeyLength == ulValueLen);

    // Get key check value for decapsulated key
    CK_BYTE decapKCV[64];
    CK_ULONG decapKCVLen = sizeof(decapKCV);
    CK_ATTRIBUTE getDecapKCVAttrib = { CKA_CHECK_VALUE, decapKCV, decapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hDecapKey, &getDecapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    decapKCVLen = getDecapKCVAttrib.ulValueLen;

    // Verify both keys have the same check values
    CPPUNIT_ASSERT(encapKCVLen == decapKCVLen);
    CPPUNIT_ASSERT(memcmp(encapKCV, decapKCV, encapKCVLen) == 0);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hDecapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMEncapsulationDecapsulationWithValueLenWrong()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;
    CK_ULONG ulValueLen = 10; // Intentionally incorrect value length for testing

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation with specific key length
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &ulValueLen, sizeof(ulValueLen) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
    CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen == 0);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

#endif

#if defined(WITH_ML_KEM) || defined(WITH_X_WING)
CK_RV EncapDecapTests::generateKEM(CK_MECHANISM_TYPE mechanismType,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE& publicKey,
	CK_OBJECT_HANDLE& privateKey)
{
#ifdef WITH_ML_KEM
	if (mechanismType == CKM_ML_KEM)
		return generateMLKEM(CKP_ML_KEM_768, session, IN_SESSION,
			IS_PUBLIC, IN_SESSION, IS_PRIVATE, publicKey, privateKey);
#endif
#ifdef WITH_X_WING
	if (mechanismType == CKM_X_WING)
		return generateXWing(session, IN_SESSION, IS_PUBLIC, IN_SESSION,
			IS_PRIVATE, publicKey, privateKey);
#endif
	return CKR_MECHANISM_INVALID;
}

void EncapDecapTests::testKEMTemplateValidation(CK_MECHANISM_TYPE mechanismType)
{
	CRYPTOKI_F_PTR(C_Finalize(NULL_PTR));
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_Initialize(NULL_PTR)));
	CK_SESSION_HANDLE session;
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_OpenSession(
		m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL_PTR, NULL_PTR, &session)));
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_Login(
		session, CKU_USER, m_userPin1, m_userPin1Length)));
	CK_OBJECT_HANDLE publicKey, privateKey;
	CPPUNIT_ASSERT_EQUAL(CKR_OK, generateKEM(mechanismType, session, publicKey, privateKey));
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &objectClass, sizeof(objectClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_BYTE ciphertext[2048];
	CK_ULONG ciphertextLength = sizeof(ciphertext);
	CK_OBJECT_HANDLE secretKey = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_EncapsulateKey(
		session, &mechanism, publicKey, attributes, 2,
		ciphertext, &ciphertextLength, &secretKey)));
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_DestroyObject(session, secretKey)));

	// Both APIs must reject parameters, including inconsistent pointer/length pairs.
	CK_BYTE parameter = 0;
	CK_MECHANISM invalidMechanisms[] = {
		{ mechanismType, &parameter, 1 },
		{ mechanismType, &parameter, 0 },
		{ mechanismType, NULL_PTR, 1 }
	};
	for (const CK_MECHANISM& invalid : invalidMechanisms)
	{
		CK_MECHANISM invalidMechanism = invalid;
		CK_ULONG capacity = sizeof(ciphertext);
		secretKey = publicKey;
		CPPUNIT_ASSERT_EQUAL(CKR_MECHANISM_PARAM_INVALID, CRYPTOKI_F_PTR(C_EncapsulateKey(
			session, &invalidMechanism, publicKey, attributes, 2,
			ciphertext, &capacity, &secretKey)));
		CPPUNIT_ASSERT_EQUAL(CK_INVALID_HANDLE, secretKey);
		secretKey = privateKey;
		CPPUNIT_ASSERT_EQUAL(CKR_MECHANISM_PARAM_INVALID, CRYPTOKI_F_PTR(C_DecapsulateKey(
			session, &invalidMechanism, privateKey, attributes, 2,
			ciphertext, ciphertextLength, &secretKey)));
		CPPUNIT_ASSERT_EQUAL(CK_INVALID_HANDLE, secretKey);
	}

	// An oversized template must fail, rather than silently discard its attributes.
	CK_BYTE label = 1;
	CK_ATTRIBUTE oversized[29];
	for (CK_ULONG i = 0; i < 29; i++)
		oversized[i] = CK_ATTRIBUTE{ CKA_LABEL, &label, sizeof(label) };
	oversized[0] = attributes[0];
	oversized[1] = attributes[1];
	CK_ULONG capacity = sizeof(ciphertext);
	CPPUNIT_ASSERT_EQUAL(CKR_TEMPLATE_INCONSISTENT, CRYPTOKI_F_PTR(C_EncapsulateKey(
		session, &mechanism, publicKey, oversized, sizeof(oversized) / sizeof(CK_ATTRIBUTE),
		ciphertext, &capacity, &secretKey)));
	CPPUNIT_ASSERT_EQUAL(CK_INVALID_HANDLE, secretKey);
	CPPUNIT_ASSERT_EQUAL(CKR_TEMPLATE_INCONSISTENT, CRYPTOKI_F_PTR(C_DecapsulateKey(
		session, &mechanism, privateKey, oversized, sizeof(oversized) / sizeof(CK_ATTRIBUTE),
		ciphertext, ciphertextLength, &secretKey)));
	CPPUNIT_ASSERT_EQUAL(CK_INVALID_HANDLE, secretKey);

	CPPUNIT_ASSERT_EQUAL(CKR_ARGUMENTS_BAD, CRYPTOKI_F_PTR(C_EncapsulateKey(
		session, &mechanism, publicKey, NULL_PTR, 2,
		ciphertext, &capacity, &secretKey)));
	CPPUNIT_ASSERT_EQUAL(CKR_ARGUMENTS_BAD, CRYPTOKI_F_PTR(C_DecapsulateKey(
		session, &mechanism, privateKey, NULL_PTR, 2,
		ciphertext, ciphertextLength, &secretKey)));
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_CloseSession(session)));
	CRYPTOKI_F_PTR(C_Finalize(NULL_PTR));
}

void EncapDecapTests::testKEMSecretCheckValue(CK_MECHANISM_TYPE mechanismType)
{
	CRYPTOKI_F_PTR(C_Finalize(NULL_PTR));
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_Initialize(NULL_PTR)));
	CK_SESSION_HANDLE session;
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_OpenSession(
		m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL_PTR, NULL_PTR, &session)));
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_Login(
		session, CKU_USER, m_userPin1, m_userPin1Length)));
	CK_OBJECT_HANDLE publicKey, privateKey;
	CPPUNIT_ASSERT_EQUAL(CKR_OK, generateKEM(mechanismType, session, publicKey, privateKey));
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	CK_ULONG lengths[] = { 1, 16, 24, 32 };
	for (CK_ULONG length : lengths)
	{
		CK_ATTRIBUTE attributes[] = {
			{ CKA_CLASS, &objectClass, sizeof(objectClass) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
			{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
			{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
			{ CKA_VALUE_LEN, &length, sizeof(length) }
		};
		// Exercise the default length as well as explicit truncation.
		CK_ULONG count = length == 32 ? 5 : 6;
		CK_BYTE ciphertext[2048];
		CK_ULONG ciphertextLength = sizeof(ciphertext);
		CK_OBJECT_HANDLE encapKey, decapKey;
		CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_EncapsulateKey(
			session, &mechanism, publicKey, attributes, count,
			ciphertext, &ciphertextLength, &encapKey)));
		CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_DecapsulateKey(
			session, &mechanism, privateKey, attributes, count,
			ciphertext, ciphertextLength, &decapKey)));
		CK_BYTE encapValue[32] = { 0 };
		for (CK_OBJECT_HANDLE key : { encapKey, decapKey })
		{
			CK_BYTE value[32], checkValue[3];
			CK_ULONG storedLength = 0;
			CK_ATTRIBUTE outputs[] = {
				{ CKA_VALUE, value, sizeof(value) },
				{ CKA_CHECK_VALUE, checkValue, sizeof(checkValue) },
				{ CKA_VALUE_LEN, &storedLength, sizeof(storedLength) }
			};
			CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_GetAttributeValue(session, key, outputs, 3)));
			CPPUNIT_ASSERT_EQUAL(length, outputs[0].ulValueLen);
			CPPUNIT_ASSERT_EQUAL(length, storedLength);
			CPPUNIT_ASSERT_EQUAL((CK_ULONG)3, outputs[1].ulValueLen);
			CK_MECHANISM digestMechanism = { CKM_SHA_1, NULL_PTR, 0 };
			CK_BYTE digest[20];
			CK_ULONG digestLength = sizeof(digest);
			CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_DigestInit(session, &digestMechanism)));
			CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_Digest(session, value, length, digest, &digestLength)));
			CPPUNIT_ASSERT(memcmp(checkValue, digest, sizeof(checkValue)) == 0);
			if (key == encapKey) memcpy(encapValue, value, length);
			else CPPUNIT_ASSERT(memcmp(encapValue, value, length) == 0);
			CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_DestroyObject(session, key)));
		}
	}
	CPPUNIT_ASSERT_EQUAL(CKR_OK, CRYPTOKI_F_PTR(C_CloseSession(session)));
	CRYPTOKI_F_PTR(C_Finalize(NULL_PTR));
}
#endif
