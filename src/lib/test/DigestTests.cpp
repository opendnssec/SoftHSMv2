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

/*****************************************************************************
 DigestTests.cpp

 Contains test cases to C_DigestInit, C_Digest, C_DigestUpdate, C_DigestFinal
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "DigestTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(DigestTests);

void DigestTests::testDigestInit()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_VENDOR_DEFINED, NULL_PTR, 0
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_DigestInit(CK_INVALID_HANDLE, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_MECHANISM_INVALID);

	mechanism.mechanism = CKM_SHA512;
	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_ACTIVE);
}

void DigestTests::testDigest()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_SHA512, NULL_PTR, 0
	};
	CK_ULONG digestLen;
	CK_BYTE_PTR digest;
	CK_BYTE data[] = {"Text to digest"};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Digest(CK_INVALID_HANDLE, data, sizeof(data)-1, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	
	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Digest(hSession, NULL_PTR, sizeof(data)-1, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	digest = (CK_BYTE_PTR)malloc(digestLen);
	digestLen = 0;

	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);
	free(digest);
}

void DigestTests::testDigestUpdate()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_SHA512, NULL_PTR, 0
	};
	CK_BYTE data[] = {"Text to digest"};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_DigestUpdate(hSession, data, sizeof(data)-1) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestUpdate(CK_INVALID_HANDLE, data, sizeof(data)-1) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	
	rv = CRYPTOKI_F_PTR( C_DigestUpdate(hSession, data, sizeof(data)-1) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestUpdate(hSession, NULL_PTR, sizeof(data)-1) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_DigestUpdate(hSession, data, sizeof(data)-1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void DigestTests::testDigestKey()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_SHA512, NULL_PTR, 0
	};
	CK_BYTE data[] = {"Text to digest"};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_DigestKey(hSession, (CK_OBJECT_HANDLE)123UL) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create the generic secret key to digest
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE genKeyType = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_VALUE, data, sizeof(data) - 1 }
	};
	CK_OBJECT_HANDLE hKey;

	hKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hKey != CK_INVALID_HANDLE);

	rv = CRYPTOKI_F_PTR( C_DigestKey(CK_INVALID_HANDLE, hKey) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	
	rv = CRYPTOKI_F_PTR( C_DigestKey(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestKey(hSession, CK_INVALID_HANDLE) );
	CPPUNIT_ASSERT(rv == CKR_KEY_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_DigestKey(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void DigestTests::testDigestFinal()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_SHA512, NULL_PTR, 0
	};
	CK_BYTE data[] = {"Text to digest"};
	CK_ULONG digestLen;
	CK_BYTE_PTR digest;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_DigestFinal(hSession, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestFinal(CK_INVALID_HANDLE, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	
	rv = CRYPTOKI_F_PTR( C_DigestFinal(hSession, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestUpdate(hSession, data, sizeof(data)-1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DigestFinal(hSession, NULL_PTR, NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_DigestFinal(hSession, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	digest = (CK_BYTE_PTR)malloc(digestLen);
	digestLen = 0;

	rv = CRYPTOKI_F_PTR( C_DigestFinal(hSession, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	rv = CRYPTOKI_F_PTR( C_DigestFinal(hSession, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	free(digest);

	rv = CRYPTOKI_F_PTR( C_DigestFinal(hSession, NULL_PTR, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);
}

void DigestTests::testDigestAll()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanisms[] = {
#ifndef WITH_FIPS
		{ CKM_MD5, NULL_PTR, 0 },
#endif
		{ CKM_SHA_1, NULL_PTR, 0 },
		{ CKM_SHA224, NULL_PTR, 0 },
		{ CKM_SHA256, NULL_PTR, 0 },
		{ CKM_SHA384, NULL_PTR, 0 },
		{ CKM_SHA512, NULL_PTR, 0 },
#ifdef WITH_GOST
		{ CKM_GOSTR3411, NULL_PTR, 0 },
#endif
	};
	CK_ULONG digestLen;
	CK_BYTE_PTR digest;
	CK_BYTE data[] = {"Text to digest"};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	for (unsigned int i = 0; i < sizeof(mechanisms)/sizeof(CK_MECHANISM); i++)
	{
		rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanisms[i]) );
		CPPUNIT_ASSERT(rv == CKR_OK);

		rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen) );
		CPPUNIT_ASSERT(rv == CKR_OK);

		digest = (CK_BYTE_PTR)malloc(digestLen);

		rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen) );
		CPPUNIT_ASSERT(rv == CKR_OK);
		free(digest);
	}
}
