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
 TokenTests.cpp

 Contains test cases to C_InitToken
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "TokenTests.h"
#include "testconfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION(TokenTests);

void TokenTests::setUp()
{
	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);
}

void TokenTests::tearDown()
{
	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);
}

void TokenTests::testInitToken()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_SO1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR label[32];
	CK_SESSION_HANDLE hSession;

	memset(label, ' ', 32);
	memcpy(label, "token1", strlen("token1"));

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_InitToken(SLOT_INIT_TOKEN, pin, pinLength, label);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_InitToken(SLOT_INIT_TOKEN, NULL_PTR, pinLength, label);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_InitToken(SLOT_INVALID, pin, pinLength, label);
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	// Initialize
	rv = C_InitToken(SLOT_INIT_TOKEN, pin, pinLength, label);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Initialize with wrong password
	rv = C_InitToken(SLOT_INIT_TOKEN, pin, pinLength - 1, label);
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_InitToken(SLOT_INIT_TOKEN, pin, pinLength, label);
	CPPUNIT_ASSERT(rv == CKR_SESSION_EXISTS);

	rv = C_CloseSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Re-initialize
	rv = C_InitToken(SLOT_INIT_TOKEN, pin, pinLength, label);
	CPPUNIT_ASSERT(rv == CKR_OK);

	C_Finalize(NULL_PTR);
}
