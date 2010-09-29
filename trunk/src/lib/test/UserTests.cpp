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
 UserTests.cpp

 Contains test cases to C_InitPIN, C_SetPIN, C_Login, and C_Logout
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "UserTests.h"
#include "testconfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION(UserTests);

void UserTests::setUp()
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

void UserTests::tearDown()
{
	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);
}

void UserTests::testInitPIN()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_InitPIN(hSession, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_InitPIN(hSession, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	rv = C_Login(hSession, CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_InitPIN(CK_INVALID_HANDLE, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = C_InitPIN(hSession, pin, 0);
	CPPUNIT_ASSERT(rv == CKR_PIN_LEN_RANGE);

	rv = C_InitPIN(hSession, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void UserTests::testLogin()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSession[2];

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Set up user PIN
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_Login(hSession[0], CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_InitPIN(hSession[0], pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);
	C_Finalize(NULL_PTR);

	rv = C_Login(hSession[0], CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(CK_INVALID_HANDLE, CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = C_Login(hSession[0], CKU_SO, NULL_PTR, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_Login(hSession[0], CKU_SO, sopin, 0);
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession[0], CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY_EXISTS);

	rv = C_CloseSession(hSession[1]);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession[0], CKU_USER, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession[0], CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = C_Logout(hSession[0]);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession[0], CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession[0], CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_USER_ALREADY_LOGGED_IN);

	rv = C_Login(hSession[0], CKU_USER, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = C_Logout(hSession[0]);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession[0], CKU_USER, pin, pinLength - 1);
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = C_Login(hSession[0], CKU_USER, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession[0], CKU_USER, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_USER_ALREADY_LOGGED_IN);
}

void UserTests::testLogout()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_SO1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_Logout(hSession);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession, CKU_SO, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Logout(CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = C_Logout(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Logout(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void UserTests::testSetPIN()
{
	CK_RV rv;
	CK_UTF8CHAR pin1[] = SLOT_0_USER1_PIN;
	CK_ULONG pin1Length = sizeof(pin1) - 1;
	CK_UTF8CHAR pin2[] = SLOT_0_USER2_PIN;
	CK_ULONG pin2Length = sizeof(pin2) - 1;
	CK_UTF8CHAR so1pin[] = SLOT_0_SO1_PIN;
	CK_ULONG so1pinLength = sizeof(so1pin) - 1;
	CK_UTF8CHAR so2pin[] = SLOT_0_SO2_PIN;
	CK_ULONG so2pinLength = sizeof(so2pin) - 1;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Set up user PIN
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_Login(hSession, CKU_SO, so1pin, so1pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_InitPIN(hSession, pin1, pin1Length);
	CPPUNIT_ASSERT(rv == CKR_OK);
	C_Finalize(NULL_PTR);

	rv = C_SetPIN(hSession, pin1, pin1Length, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_SetPIN(CK_INVALID_HANDLE, pin1, pin1Length, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = C_SetPIN(hSession, pin1, pin1Length, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	rv = C_CloseSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_SetPIN(hSession, NULL_PTR, pin1Length, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_SetPIN(hSession, pin1, pin1Length, NULL_PTR, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_SetPIN(hSession, pin1, pin1Length, pin2, 0);
	CPPUNIT_ASSERT(rv == CKR_PIN_LEN_RANGE);

	rv = C_SetPIN(hSession, pin2, pin2Length, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = C_SetPIN(hSession, pin1, pin1Length, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession, CKU_USER, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_SetPIN(hSession, pin1, pin1Length, pin2, pin2Length);
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = C_SetPIN(hSession, pin2, pin2Length, pin1, pin1Length);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession, CKU_SO, so1pin, so1pinLength);
	CPPUNIT_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = C_Logout(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Login(hSession, CKU_SO, so1pin, so1pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_SetPIN(hSession, so2pin, so2pinLength, so2pin, so2pinLength);
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = C_SetPIN(hSession, so1pin, so1pinLength, so2pin, so2pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_SetPIN(hSession, so1pin, so1pinLength, so1pin, so1pinLength);
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = C_SetPIN(hSession, so2pin, so2pinLength, so1pin, so1pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
