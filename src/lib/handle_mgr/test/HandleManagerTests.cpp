/*
 * Copyright (c) 2012 SURFnet bv
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
 HandleManagerTests.cpp

 Contains test cases to test the handle manager implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "HandleManagerTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(HandleManagerTests);

void HandleManagerTests::setUp()
{
	handleManager = new HandleManager();
}

void HandleManagerTests::tearDown()
{
	delete handleManager;
}

void HandleManagerTests::testHandleManager()
{
	CPPUNIT_ASSERT(handleManager != NULL);

	CK_SLOT_ID slotID = 1234; // we need a unique value
	CK_SESSION_HANDLE hSession;
	CK_VOID_PTR session = &hSession; // we need a unique value
	CK_SESSION_HANDLE hSession2;
	CK_VOID_PTR session2 = &hSession2; // we need a unique value
	CK_OBJECT_HANDLE hObject;
	CK_VOID_PTR object = &hObject; // we need a unique value
	CK_OBJECT_HANDLE hObject2;
	CK_VOID_PTR object2 = &hObject2; // we need a unique value
	CK_OBJECT_HANDLE hObject3;
	CK_VOID_PTR object3 = &hObject3; // we need a unique value
	CK_OBJECT_HANDLE hObject4;
	CK_VOID_PTR object4 = &hObject4; // we need a unique value
	CK_OBJECT_HANDLE hObject5;
	CK_VOID_PTR object5 = &hObject5; // we need a unique value

	// Check session object management.
	hSession = handleManager->addSession(slotID, session);
	CPPUNIT_ASSERT(hSession != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session == handleManager->getSession(hSession));
	CPPUNIT_ASSERT_NO_THROW(handleManager->sessionClosed(123124));
	handleManager->sessionClosed(hSession);
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession));

	// Add an object, hSession doesn't have to exists
	hObject = handleManager->addSessionObject(slotID, 4412412, true, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject));
	handleManager->sessionClosed(4412412);
	// Object still exists as the hSession was invalid
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject));
	handleManager->allSessionsClosed(slotID);
	// Object is now gone as all sessions for the given slotID have been removed.
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject));

	// Add an object and then destroy it.
	hObject = handleManager->addSessionObject(slotID, 4412412, true, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	handleManager->destroyObject(hObject);
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject));

	hObject = handleManager->addTokenObject(slotID, false, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	handleManager->destroyObject(hObject);
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject));

	// Create a valid session again
	hSession = handleManager->addSession(slotID, session);
	CPPUNIT_ASSERT(hSession != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session == handleManager->getSession(hSession));

	// Now some magic with a couple of objects
	// First add a public object
	hObject = handleManager->addTokenObject(slotID, false, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject));

	// Now add a private object
	hObject2 = handleManager->addTokenObject(slotID, true, object2);
	CPPUNIT_ASSERT(hObject2 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object2 == handleManager->getObject(hObject2));

	// Now add another private object
	hObject3 = handleManager->addTokenObject(slotID, true, object3);
	CPPUNIT_ASSERT(hObject3 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object3 == handleManager->getObject(hObject3));

	// Adding the same object will return the same handle whether the object is marked private or public.
	CPPUNIT_ASSERT(hObject2 == handleManager->addTokenObject(slotID, true, object2));
	// Because the private state of an object cannot be changed it won't be marked as public, it remains private
	CPPUNIT_ASSERT(hObject2 == handleManager->addTokenObject(slotID, false, object2));

	// It is not allowed to migrate an object from one slot to another, so here we return an invalid handle.
	CPPUNIT_ASSERT(CK_INVALID_HANDLE == handleManager->addTokenObject(124121, false, object2));

	// Now add another private session object
	hObject4 = handleManager->addSessionObject(slotID, hSession, true, object4);
	CPPUNIT_ASSERT(hObject4 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object4 == handleManager->getObject(hObject4));

	// Now add another public session object
	hObject5 = handleManager->addSessionObject(slotID, hSession, false, object5);
	CPPUNIT_ASSERT(hObject5 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object5 == handleManager->getObject(hObject5));

	// Logout, now private objects should be gone.
	handleManager->tokenLoggedOut(slotID);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject));
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject2)); // should still be private and removed.
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject3));
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject4));
	CPPUNIT_ASSERT(object5 == handleManager->getObject(hObject5));

	// Create another valid session for the slot
	hSession2 = handleManager->addSession(slotID, session2);
	CPPUNIT_ASSERT(hSession2 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session2 == handleManager->getSession(hSession2));

	handleManager->sessionClosed(hSession);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject)); // token object should still be there.
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject5)); // session object should be gone.

	// Removing the last remaining session should kill the remaining handle.
	handleManager->sessionClosed(hSession2);
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject)); // should be gone now.

	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession));
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession2));


	// Create a valid session again
	hSession = handleManager->addSession(slotID, session);
	CPPUNIT_ASSERT(hSession != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session == handleManager->getSession(hSession));

	// Create another valid session for the slot
	hSession2 = handleManager->addSession(slotID, session2);
	CPPUNIT_ASSERT(hSession2 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session2 == handleManager->getSession(hSession2));

	handleManager->allSessionsClosed(slotID);

	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession));
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession2));
}
