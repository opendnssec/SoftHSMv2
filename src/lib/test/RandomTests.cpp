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
 RandomTests.cpp

 Contains test cases to C_SeedRandom and C_GenerateRandom
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "RandomTests.h"
#include "testconfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION(RandomTests);

void RandomTests::setUp()
{
//    printf("\nRandomTests\n");

#ifndef _WIN32
	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);
#else
	setenv("SOFTHSM2_CONF", ".\\softhsm2.conf", 1);
#endif

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

void RandomTests::tearDown()
{
	C_Finalize(NULL_PTR);
}

void RandomTests::testSeedRandom()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_BYTE seed[] = {"Some random data"};

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_SeedRandom(CK_INVALID_HANDLE, seed, sizeof(seed));
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_SeedRandom(hSession, NULL_PTR, sizeof(seed));
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_SeedRandom(hSession, seed, sizeof(seed));
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_SeedRandom(hSession, seed, sizeof(seed));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void RandomTests::testGenerateRandom()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_BYTE randomData[40];

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_GenerateRandom(CK_INVALID_HANDLE, randomData, 40);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GenerateRandom(hSession, NULL_PTR, 40);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_GenerateRandom(hSession, randomData, 40);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GenerateRandom(hSession, randomData, 40);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
