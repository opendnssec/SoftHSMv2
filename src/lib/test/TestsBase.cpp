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
 TestsBase.cpp

 Base class for test classes.
 *****************************************************************************/

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

void TestsBase::setUp() {
	TestsNoPINInitBase::setUp();

	CK_SESSION_HANDLE hSession;

	// Open session
	CPPUNIT_ASSERT( CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession)==CKR_OK ) );

	// Login SO
	CPPUNIT_ASSERT( CRYPTOKI_F_PTR( C_Login(hSession,CKU_SO, m_soPin1, m_soPin1Length)==CKR_OK ) );

	// Initialize the user pin
	CPPUNIT_ASSERT( CRYPTOKI_F_PTR( C_InitPIN(hSession, m_userPin1, m_userPin1Length)==CKR_OK ) );
}
