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
 SessionTests.cpp

 Contains test cases to C_OpenSession, C_CloseSession, C_CloseAllSessions, and
 C_GetSessionInfo
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "SessionTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SessionTests);

void SessionTests::testOpenSession()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_invalidSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_notInitializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_TOKEN_NOT_RECOGNIZED);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, 0, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void SessionTests::testCloseSession()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseSession(CK_INVALID_HANDLE) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession + 1) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
}

void SessionTests::testCloseAllSessions()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_SESSION_INFO info;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_initializedTokenSlotID) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_invalidSlotID) );
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_notInitializedTokenSlotID) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_initializedTokenSlotID) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
}

void SessionTests::testGetSessionInfo()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_SESSION_INFO info;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(CK_INVALID_HANDLE, &info) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession + 1, &info) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    CPPUNIT_ASSERT(info.state == CKS_RO_PUBLIC_SESSION);
	CPPUNIT_ASSERT(info.flags == CKF_SERIAL_SESSION);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
}
