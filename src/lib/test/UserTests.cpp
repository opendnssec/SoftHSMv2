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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "UserTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(UserTests);

void UserTests::testInitPIN()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_InitPIN(hSession, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_InitPIN(hSession, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_InitPIN(CK_INVALID_HANDLE, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_InitPIN(hSession, m_userPin1, 0) );
	CPPUNIT_ASSERT(rv == CKR_PIN_LEN_RANGE);

	rv = CRYPTOKI_F_PTR( C_InitPIN(hSession, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void UserTests::testLogin()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Set up user PIN
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[0]) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_USER_PIN_NOT_INITIALIZED);
	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_InitPIN(hSession[0], m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[0]) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(CK_INVALID_HANDLE, CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, NULL_PTR, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, m_soPin1, 0) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[1]) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY_EXISTS);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession[1]) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = CRYPTOKI_F_PTR( C_Logout(hSession[0]) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_USER_ALREADY_LOGGED_IN);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = CRYPTOKI_F_PTR( C_Logout(hSession[0]) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_USER, m_userPin1, m_userPin1Length - 1) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession[0], CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_USER_ALREADY_LOGGED_IN);
}

void UserTests::testLogout()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Logout(hSession) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Logout(CK_INVALID_HANDLE) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_Logout(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Logout(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void UserTests::testSetPIN()
{
	CK_RV rv;
	const CK_UTF8CHAR_PTR pin2((CK_UTF8CHAR_PTR)"12345");
	const CK_ULONG pin2Length(strlen((char*)pin2));
	const CK_UTF8CHAR_PTR so2pin((CK_UTF8CHAR_PTR)"123456789");
	const CK_ULONG so2pinLength(strlen((char*)so2pin));
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Set up user PIN
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_InitPIN(hSession, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_userPin1, m_userPin1Length, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_SetPIN(CK_INVALID_HANDLE, m_userPin1, m_userPin1Length, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_userPin1, m_userPin1Length, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, NULL_PTR, m_userPin1Length, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_userPin1, m_userPin1Length, NULL_PTR, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_userPin1, m_userPin1Length, pin2, 0) );
	CPPUNIT_ASSERT(rv == CKR_PIN_LEN_RANGE);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, pin2, pin2Length, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_userPin1, m_userPin1Length, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_userPin1, m_userPin1Length, pin2, pin2Length) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, pin2, pin2Length, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

	rv = CRYPTOKI_F_PTR( C_Logout(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_SO, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, so2pin, so2pinLength, so2pin, so2pinLength) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_soPin1, m_soPin1Length, so2pin, so2pinLength) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, m_soPin1, m_soPin1Length, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = CRYPTOKI_F_PTR( C_SetPIN(hSession, so2pin, so2pinLength, m_soPin1, m_soPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}
