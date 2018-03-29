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
#include "DeriveTests.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(DeriveTests);

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
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
			pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
			prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
			&hPuk, &hPrk) );
}

#ifdef WITH_ECC
CK_RV DeriveTests::generateEcKeyPair(const char* curve, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_EC;
	CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	CK_BYTE oidP384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
	CK_BYTE oidP521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
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
CK_RV DeriveTests::generateEdKeyPair(const char* curve, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_EC_EDWARDS;
	CK_BYTE oidX25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x6E };
	CK_BYTE oidX448[] = { 0x06, 0x03, 0x2B, 0x65, 0x6F };
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};

	/* Select the curve */
	if (strcmp(curve, "X25519") == 0)
	{
		pukAttribs[0].pValue = oidX25519;
		pukAttribs[0].ulValueLen = sizeof(oidX25519);
	}
	else if (strcmp(curve, "X448") == 0)
	{
		pukAttribs[0].pValue = oidX448;
		pukAttribs[0].ulValueLen = sizeof(oidX448);
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
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
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
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
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
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
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
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

void DeriveTests::dhDerive(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_OBJECT_HANDLE &hKey)
{
	CK_ATTRIBUTE valAttrib = { CKA_VALUE, NULL_PTR, 0 };
	CK_RV rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPublicKey, &valAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	valAttrib.pValue = (CK_BYTE_PTR)malloc(valAttrib.ulValueLen);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPublicKey, &valAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_MECHANISM mechanism = { CKM_DH_PKCS_DERIVE, NULL_PTR, 0 };
	mechanism.pParameter = valAttrib.pValue;
	mechanism.ulParameterLen = valAttrib.ulValueLen;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ULONG secLen = 32;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &secLen, sizeof(secLen) }
	};

	hKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &mechanism, hPrivateKey,
			 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			 &hKey) );
	free(valAttrib.pValue);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

#if defined(WITH_ECC) || defined(WITH_EDDSA)
void DeriveTests::ecdhDerive(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_OBJECT_HANDLE &hKey, bool useRaw)
{
	CK_ATTRIBUTE valAttrib = { CKA_EC_POINT, NULL_PTR, 0 };
	CK_RV rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPublicKey, &valAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	valAttrib.pValue = (CK_BYTE_PTR)malloc(valAttrib.ulValueLen);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPublicKey, &valAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_ECDH1_DERIVE_PARAMS parms = { CKD_NULL, 0, NULL_PTR, 0, NULL_PTR };
	// Use RAW or DER format
	if (useRaw)
	{
		size_t offset = 0;
		unsigned char* buf = (unsigned char*)valAttrib.pValue;
		if (valAttrib.ulValueLen > 2 && buf[0] == 0x04)
		{
			if (buf[1] < 0x80)
			{
				offset = 2;
			}
			else
			{
				if (valAttrib.ulValueLen > ((buf[1] & 0x7F) + (unsigned int)2))
				{
					offset = 2 + (buf[1] & 0x7F);
				}
			}
		}
		parms.pPublicData = buf + offset;
		parms.ulPublicDataLen = valAttrib.ulValueLen - offset;
	}
	else
	{
		parms.pPublicData = (unsigned char*)valAttrib.pValue;
		parms.ulPublicDataLen = valAttrib.ulValueLen;
	}

	CK_MECHANISM mechanism = { CKM_ECDH1_DERIVE, NULL, 0 };
	mechanism.pParameter = &parms;
	mechanism.ulParameterLen = sizeof(parms);
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ULONG secLen = 32;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &secLen, sizeof(secLen) }
	};

	hKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &mechanism, hPrivateKey,
			 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			 &hKey) );
	free(valAttrib.pValue);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
#endif

bool DeriveTests::compareSecret(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey1, CK_OBJECT_HANDLE hKey2)
{
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_VALUE, NULL_PTR, 0 },
		{ CKA_CHECK_VALUE, NULL_PTR, 0 }
	};
	CK_BYTE val1[128];
	CK_BYTE check1[3];
	keyAttribs[0].pValue = val1;
	keyAttribs[0].ulValueLen = sizeof(val1);
	keyAttribs[1].pValue = check1;
	keyAttribs[1].ulValueLen = sizeof(check1);
	CK_RV rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hKey1, keyAttribs, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(keyAttribs[0].ulValueLen == 32);
	CPPUNIT_ASSERT(keyAttribs[1].ulValueLen == 3);
	CK_BYTE val2[128];
	CK_BYTE check2[3];
	keyAttribs[0].pValue = val2;
	keyAttribs[0].ulValueLen = sizeof(val2);
	keyAttribs[1].pValue = check2;
	keyAttribs[1].ulValueLen = sizeof(check2);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hKey2, keyAttribs, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(keyAttribs[0].ulValueLen == 32);
	CPPUNIT_ASSERT(keyAttribs[1].ulValueLen == 3);
	return memcmp(val1, val2, 32) == 0 &&
	       memcmp(check1, check2, 3) == 0;
}

void DeriveTests::testDhDerive()
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

#ifdef WITH_ECC
void DeriveTests::testEcdsaDerive()
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
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Public Session keys
	CK_OBJECT_HANDLE hPuk1 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk1 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPuk2 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk2 = CK_INVALID_HANDLE;

	rv = generateEcKeyPair("P-256",hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEcKeyPair("P-256",hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_OBJECT_HANDLE hKey1 = CK_INVALID_HANDLE;
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	CK_OBJECT_HANDLE hKey2 = CK_INVALID_HANDLE;
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Private Session Keys
	rv = generateEcKeyPair("P-384",hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEcKeyPair("P-384",hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Public Token Keys
	rv = generateEcKeyPair("P-521",hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEcKeyPair("P-521",hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Private Token Keys
	rv = generateEcKeyPair("P-256",hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEcKeyPair("P-256",hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));
}
#endif

#ifdef WITH_EDDSA
void DeriveTests::testEddsaDerive()
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
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Public Session keys
	CK_OBJECT_HANDLE hPuk1 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk1 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPuk2 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk2 = CK_INVALID_HANDLE;

	rv = generateEdKeyPair("X25519",hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEdKeyPair("X25519",hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_OBJECT_HANDLE hKey1 = CK_INVALID_HANDLE;
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	CK_OBJECT_HANDLE hKey2 = CK_INVALID_HANDLE;
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Private Session Keys
	rv = generateEdKeyPair("X25519",hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEdKeyPair("X25519",hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Public Token Keys
	rv = generateEdKeyPair("X25519",hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEdKeyPair("X25519",hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));

	// Private Token Keys
	rv = generateEdKeyPair("X25519",hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk1,hPrk1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateEdKeyPair("X25519",hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk2,hPrk2);
	CPPUNIT_ASSERT(rv == CKR_OK);
	ecdhDerive(hSessionRW,hPuk1,hPrk2,hKey1,true);
	ecdhDerive(hSessionRW,hPuk2,hPrk1,hKey2,false);
	CPPUNIT_ASSERT(compareSecret(hSessionRW,hKey1,hKey2));
}
#endif

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
		rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &mechanism, hKey,
				 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
				 &hDerive) );
	}
	else
	{
		rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &mechanism, hKey,
				 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE) - 1,
				 &hDerive) );
	}
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check that KCV has been set
	CK_ATTRIBUTE checkAttribs[] = {
		{ CKA_CHECK_VALUE, NULL_PTR, 0 }
	};
	CK_BYTE check[3];
	checkAttribs[0].pValue = check;
	checkAttribs[0].ulValueLen = sizeof(check);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hDerive, checkAttribs, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(checkAttribs[0].ulValueLen == 3);

	if (keyType == CKK_GENERIC_SECRET) return;

	CK_BYTE cipherText[300];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[300];
	CK_ULONG ulRecoveredTextLen;

	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechEncrypt,hDerive) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulCipherTextLen = sizeof(cipherText);
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,data,sizeof(data),cipherText,&ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechEncrypt,hDerive) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(ulRecoveredTextLen==sizeof(data));

	CPPUNIT_ASSERT(memcmp(data, recoveredText, sizeof(data)) == 0);
}

void DeriveTests::testSymDerive()
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

	// Login USER into the sessions so we can create private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
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

