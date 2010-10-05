/* $Id$ */

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

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DigestTests.h"
#include "testconfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION(DigestTests);

void DigestTests::setUp()
{
	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);

	CK_UTF8CHAR pin[] = SLOT_0_SO1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR label[32];
	memset(label, ' ', 32);
	memcpy(label, "token1", strlen("token1"));

	// (Re)initialize the token
	CK_RV rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_InitToken(SLOT_INIT_TOKEN, pin, pinLength, label);
	CPPUNIT_ASSERT(rv == CKR_OK);
	C_Finalize(NULL_PTR);
}

void DigestTests::tearDown()
{
	C_Finalize(NULL_PTR);
}

void DigestTests::testDigestInit()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism = {
		CKM_VENDOR_DEFINED, NULL_PTR, 0
	};

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_DigestInit(hSession, &mechanism);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_DigestInit(hSession, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_DigestInit(CK_INVALID_HANDLE, &mechanism);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = C_DigestInit(hSession, &mechanism);
	CPPUNIT_ASSERT(rv == CKR_MECHANISM_INVALID);

	mechanism.mechanism = CKM_SHA512;
	rv = C_DigestInit(hSession, &mechanism);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_DigestInit(hSession, &mechanism);
	CPPUNIT_ASSERT(rv == CKR_OPERATION_ACTIVE);
}

void DigestTests::testDigest()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism = {
		CKM_SHA512, NULL_PTR, 0
	};
	CK_ULONG digestLen;
	CK_BYTE_PTR digest;
	CK_BYTE data[] = {"Text to digest"};

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Digest(CK_INVALID_HANDLE, data, sizeof(data)-1, NULL_PTR, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	
	rv = C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	rv = C_DigestInit(hSession, &mechanism);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Digest(hSession, NULL_PTR, sizeof(data)-1, NULL_PTR, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_OK);

	digest = (CK_BYTE_PTR)malloc(digestLen);
	digestLen = 0;

	rv = C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	rv = C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_OK);
	free(digest);

	rv = C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen);
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);
}

void DigestTests::testDigestUpdate()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism = {
		CKM_SHA512, NULL_PTR, 0
	};
	CK_BYTE data[] = {"Text to digest"};

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_DigestUpdate(hSession, data, sizeof(data)-1);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_DigestUpdate(CK_INVALID_HANDLE, data, sizeof(data)-1);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	
	rv = C_DigestUpdate(hSession, data, sizeof(data)-1);
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	rv = C_DigestInit(hSession, &mechanism);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_DigestUpdate(hSession, NULL_PTR, sizeof(data)-1);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_DigestUpdate(hSession, data, sizeof(data)-1);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
