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
 SessionManagerTests.cpp

 Contains test cases for SessionManager
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "SessionManagerTests.h"
#include "ObjectStore.h"
#include "SessionManager.h"
#include "Session.h"
#include "SlotManager.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SessionManagerTests);

void SessionManagerTests::setUp()
{
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void SessionManagerTests::tearDown()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void SessionManagerTests::testOpenClose()
{
	// Create an empty object store
#ifndef _WIN32
	ObjectStore store("./testdir");
#else
	ObjectStore store(".\\testdir");
#endif

	// Create the managers
	SlotManager slotManager(&store);
	SessionManager sessionManager;

	// Get a slot
	CK_SLOT_ID slotID = 0;
	Slot* slot = slotManager.getSlot(slotID);

	// Use some bad data
	CK_SESSION_HANDLE hSession;
	CK_RV rv = sessionManager.openSession(NULL, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);
	rv = sessionManager.openSession(slot, 0, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	// Try open a slot with an uninitialized token
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_TOKEN_NOT_RECOGNIZED);

	// Initialize the token
	ByteString soPIN((unsigned char*)"1234", 4);
	CK_UTF8CHAR label[33] = "My test token                   ";
	CPPUNIT_ASSERT(slot->initToken(soPIN, label) == CKR_OK);

	// Open a session
	bool haveSession = sessionManager.haveSession(slotID);
	CPPUNIT_ASSERT(haveSession == false);
	bool haveROSession = sessionManager.haveROSession(slotID);
	CPPUNIT_ASSERT(haveROSession == false);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	haveSession = sessionManager.haveSession(slotID);
	CPPUNIT_ASSERT(haveSession == true);
	haveROSession = sessionManager.haveROSession(slotID);
	CPPUNIT_ASSERT(haveROSession == true);

	// Close session
	rv = sessionManager.closeSession(CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	haveSession = sessionManager.haveSession(slotID);
	CPPUNIT_ASSERT(haveSession == false);
	haveROSession = sessionManager.haveROSession(slotID);
	CPPUNIT_ASSERT(haveROSession == false);

	// Try open a Read-Only session when in SO mode
	rv = slot->getToken()->loginSO(soPIN);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_WRITE_SO_EXISTS);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	haveSession = sessionManager.haveSession(slotID);
	CPPUNIT_ASSERT(haveSession == true);
	haveROSession = sessionManager.haveROSession(slotID);
	CPPUNIT_ASSERT(haveROSession == false);

	// Close session and check that we are logged out
	bool isLoggedIn = slot->getToken()->isSOLoggedIn();
	CPPUNIT_ASSERT(isLoggedIn == true);
	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	isLoggedIn = slot->getToken()->isSOLoggedIn();
	CPPUNIT_ASSERT(isLoggedIn == false);
	haveSession = sessionManager.haveSession(slotID);
	CPPUNIT_ASSERT(haveSession == false);
	haveROSession = sessionManager.haveROSession(slotID);
	CPPUNIT_ASSERT(haveROSession == false);

	// Open a new logged in session
	rv = slot->getToken()->loginSO(soPIN);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close all sessions and check that we are logged out
	isLoggedIn = slot->getToken()->isSOLoggedIn();
	CPPUNIT_ASSERT(isLoggedIn == true);
	rv = sessionManager.closeAllSessions(NULL);
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);
	rv = sessionManager.closeAllSessions(slot);
	CPPUNIT_ASSERT(rv == CKR_OK);
	isLoggedIn = slot->getToken()->isSOLoggedIn();
	CPPUNIT_ASSERT(isLoggedIn == false);
}

void SessionManagerTests::testSessionInfo()
{
	// Create an empty object store
#ifndef _WIN32
	ObjectStore store("./testdir");
#else
	ObjectStore store(".\\testdir");
#endif

	// Create the managers
	SlotManager slotManager(&store);
	SessionManager sessionManager;

	// Get a slot
	CK_SLOT_ID slotID = 0;
	Slot* slot = slotManager.getSlot(slotID);

	// Initialize the token
	ByteString soPIN((unsigned char*)"1234", 4);
	ByteString userPIN((unsigned char*)"1234", 4);
	CK_UTF8CHAR label[33] = "My test token                   ";
	CPPUNIT_ASSERT(slot->initToken(soPIN, label) == CKR_OK);
	CPPUNIT_ASSERT(slot->getToken()->loginSO(soPIN) == CKR_OK);
	CPPUNIT_ASSERT(slot->getToken()->initUserPIN(userPIN) == CKR_OK);
	slot->getToken()->logout();

	// Get a session
	CK_SESSION_HANDLE hSession;
	CK_RV rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Get session info
	CK_SESSION_INFO info;
	rv = sessionManager.getSessionInfo(CK_INVALID_HANDLE, &info);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
	rv = sessionManager.getSessionInfo(hSession, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);
	rv = sessionManager.getSessionInfo(hSession, &info);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Public RO session info
	CPPUNIT_ASSERT(info.slotID == slotID);
	CPPUNIT_ASSERT(info.state == CKS_RO_PUBLIC_SESSION);
	CPPUNIT_ASSERT(info.flags == CKF_SERIAL_SESSION);

	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Public RW session info
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	Session* session = sessionManager.getSession(CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session == NULL);
	session = sessionManager.getSession(hSession);
	CPPUNIT_ASSERT(session != NULL);
	rv = session->getInfo(&info);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(info.state == CKS_RW_PUBLIC_SESSION);
	CPPUNIT_ASSERT(info.flags == (CKF_SERIAL_SESSION | CKF_RW_SESSION));

	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// User RO session info
	rv = slot->getToken()->loginUser(userPIN);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.getSessionInfo(hSession, &info);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(info.state == CKS_RO_USER_FUNCTIONS);
	CPPUNIT_ASSERT(info.flags == CKF_SERIAL_SESSION);

	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// User RW session info
	rv = slot->getToken()->loginUser(userPIN);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.getSessionInfo(hSession, &info);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(info.state == CKS_RW_USER_FUNCTIONS);
	CPPUNIT_ASSERT(info.flags == (CKF_SERIAL_SESSION | CKF_RW_SESSION));

	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// SO RW session info
	rv = slot->getToken()->loginSO(soPIN);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = sessionManager.getSessionInfo(hSession, &info);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(info.state == CKS_RW_SO_FUNCTIONS);
	CPPUNIT_ASSERT(info.flags == (CKF_SERIAL_SESSION | CKF_RW_SESSION));

	rv = sessionManager.closeSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
