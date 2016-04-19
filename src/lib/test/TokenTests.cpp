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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "TokenTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(TokenTests);

void TokenTests::testInitToken()
{
	CK_RV rv;
	CK_UTF8CHAR label[32];
	CK_SESSION_HANDLE hSession;
	CK_TOKEN_INFO tokenInfo;
	CK_CHAR serialNumber[16];

	memset(label, ' ', 32);
	memcpy(label, "token1", strlen("token1"));

	// Just make sure that we finalize any previous failed tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_InitToken(m_initializedTokenSlotID, m_soPin1, m_soPin1Length, label) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_InitToken(m_initializedTokenSlotID, NULL_PTR, m_soPin1Length, label) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = CRYPTOKI_F_PTR( C_InitToken(m_invalidSlotID, m_soPin1, m_soPin1Length, label) );
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	// Initialize
	rv = CRYPTOKI_F_PTR( C_InitToken(m_initializedTokenSlotID, m_soPin1, m_soPin1Length, label) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Get token serial
	rv = CRYPTOKI_F_PTR( C_GetTokenInfo(m_initializedTokenSlotID, &tokenInfo) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	memcpy(serialNumber, tokenInfo.serialNumber, 16);

	// Initialize with wrong password
	rv = CRYPTOKI_F_PTR( C_InitToken(m_initializedTokenSlotID, m_soPin1, m_soPin1Length - 1, label) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_InitToken(m_initializedTokenSlotID, m_soPin1, m_soPin1Length, label) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_EXISTS);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Re-initialize
	rv = CRYPTOKI_F_PTR( C_InitToken(m_initializedTokenSlotID, m_soPin1, m_soPin1Length, label) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Compare token serial
	rv = CRYPTOKI_F_PTR( C_GetTokenInfo(m_initializedTokenSlotID, &tokenInfo) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(memcmp(serialNumber, tokenInfo.serialNumber, 16) == 0);

	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}
