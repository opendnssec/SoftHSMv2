/*
 * Copyright (c) 2010 SURFnet bv
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
 SessionObjectStoreTests.cpp

 Contains test cases to test the session object store implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include <memory>
#include "SessionObjectStoreTests.h"
#include "SessionObjectStore.h"
#include "SessionObject.h"
#include "OSAttribute.h"
#include "OSAttributes.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SessionObjectStoreTests);

void SessionObjectStoreTests::setUp()
{
}

void SessionObjectStoreTests::tearDown()
{
}

void SessionObjectStoreTests::testCreateDeleteObjects()
{
	// Test IDs
	ByteString id[5] = { "112233445566", "AABBCCDDEEFF", "ABABABABABAB", "557788991122", "005500550055" };
	OSAttribute idAtt[5] = { id[0], id[1], id[2], id[3], id[4] };
	ByteString label = "AABBCCDDEEFF";
	ByteString serial = "1234567890";

	// Get access to the session object store
	SessionObjectStore* testStore = new SessionObjectStore();

	// Create 3 objects in the store
	SessionObject* obj1 = testStore->createObject(1, 1);
	CPPUNIT_ASSERT(obj1 != NULL);
	SessionObject* obj2 = testStore->createObject(1, 1);
	CPPUNIT_ASSERT(obj2 != NULL);
	SessionObject* obj3 = testStore->createObject(1, 1);
	CPPUNIT_ASSERT(obj3 != NULL);

	// Now set the IDs of the 3 objects
	obj1->setAttribute(CKA_ID, idAtt[0]);
	obj2->setAttribute(CKA_ID, idAtt[1]);
	obj3->setAttribute(CKA_ID, idAtt[2]);

	// Check that the store contains 3 objects
	CPPUNIT_ASSERT(testStore->getObjects().size() == 3);

	// Check that all three objects are distinct and present
	std::set<SessionObject*> objects = testStore->getObjects();
	bool present1[3] = { false, false, false };

	for (std::set<SessionObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		for (int j = 0; j < 3; j++)
		{
			if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[j])
			{
				present1[j] = true;
			}
		}
	}

	for (int j = 0; j < 3; j++)
	{
		CPPUNIT_ASSERT(present1[j] == true);
	}

	// Now delete the second object
	for (std::set<SessionObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[1])
		{
			CPPUNIT_ASSERT(testStore->deleteObject(*i));
			break;
		}
	}

	// Verify that it was indeed removed
	CPPUNIT_ASSERT(testStore->getObjects().size() == 2);

	objects = testStore->getObjects();
	bool present3[2] = { false, false };

	for (std::set<SessionObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[0])
		{
			present3[0] = true;
		}
		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[2])
		{
			present3[1] = true;
		}
	}

	for (int j = 0; j < 2; j++)
	{
		CPPUNIT_ASSERT(present3[j] == true);
	}

	delete testStore;
}

void SessionObjectStoreTests::testMultiSession()
{
	// Get access to the store
	SessionObjectStore* store = new SessionObjectStore();

	// Check that the store is empty
	CPPUNIT_ASSERT(store->getObjects().size() == 0);

	// Test IDs
	ByteString id[5] = { "112233445566", "AABBCCDDEEFF", "ABABABABABAB", "557788991122", "005500550055" };
	OSAttribute idAtt[5] = { id[0], id[1], id[2], id[3], id[4] };

	// Create 3 objects in the store for three different sessions
	SessionObject* obj1 = store->createObject(1, 1);
	CPPUNIT_ASSERT(obj1 != NULL);
	SessionObject* obj2 = store->createObject(1, 2);
	CPPUNIT_ASSERT(obj2 != NULL);
	SessionObject* obj3 = store->createObject(1, 3);
	CPPUNIT_ASSERT(obj3 != NULL);

	// Now set the IDs of the 3 objects
	obj1->setAttribute(CKA_ID, idAtt[0]);
	obj2->setAttribute(CKA_ID, idAtt[1]);
	obj3->setAttribute(CKA_ID, idAtt[2]);

	// Check that the store contains 3 objects
	CPPUNIT_ASSERT(store->getObjects().size() == 3);

	// Check that all three objects are distinct and present
	std::set<SessionObject*> objects = store->getObjects();
	bool present1[3] = { false, false, false };

	for (std::set<SessionObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		for (int j = 0; j < 3; j++)
		{
			if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[j])
			{
				present1[j] = true;
			}
		}
	}

	for (int j = 0; j < 3; j++)
	{
		CPPUNIT_ASSERT(present1[j] == true);
	}

	// Now indicate that the second session has been closed
	store->sessionClosed(2);

	// Verify that it was indeed removed
	CPPUNIT_ASSERT(store->getObjects().size() == 2);

	objects = store->getObjects();
	bool present3[2] = { false, false };

	for (std::set<SessionObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[0])
		{
			present3[0] = true;
		}
		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[2])
		{
			present3[1] = true;
		}
	}

	for (int j = 0; j < 2; j++)
	{
		CPPUNIT_ASSERT(present3[j] == true);
	}

	// Create two more objects for session 7
	SessionObject* obj4 = store->createObject(1, 7);
	CPPUNIT_ASSERT(obj4 != NULL);
	SessionObject* obj5 = store->createObject(1, 7);
	CPPUNIT_ASSERT(obj5 != NULL);

	CPPUNIT_ASSERT(store->getObjects().size() == 4);

	// Close session 1
	store->sessionClosed(1);

	CPPUNIT_ASSERT(store->getObjects().size() == 3);

	objects = store->getObjects();

	CPPUNIT_ASSERT(objects.find(obj1) == objects.end());
	CPPUNIT_ASSERT(objects.find(obj2) == objects.end());
	CPPUNIT_ASSERT(objects.find(obj3) != objects.end());
	CPPUNIT_ASSERT(objects.find(obj4) != objects.end());
	CPPUNIT_ASSERT(objects.find(obj5) != objects.end());

	CPPUNIT_ASSERT(!obj1->isValid());
	CPPUNIT_ASSERT(!obj2->isValid());
	CPPUNIT_ASSERT(obj3->isValid());
	CPPUNIT_ASSERT(obj4->isValid());
	CPPUNIT_ASSERT(obj5->isValid());

	// Close session 7
	store->sessionClosed(7);

	CPPUNIT_ASSERT(store->getObjects().size() == 1);

	objects = store->getObjects();

	CPPUNIT_ASSERT(objects.find(obj1) == objects.end());
	CPPUNIT_ASSERT(objects.find(obj2) == objects.end());
	CPPUNIT_ASSERT(objects.find(obj3) != objects.end());
	CPPUNIT_ASSERT(objects.find(obj4) == objects.end());
	CPPUNIT_ASSERT(objects.find(obj5) == objects.end());

	CPPUNIT_ASSERT(!obj1->isValid());
	CPPUNIT_ASSERT(!obj2->isValid());
	CPPUNIT_ASSERT(obj3->isValid());
	CPPUNIT_ASSERT(!obj4->isValid());
	CPPUNIT_ASSERT(!obj5->isValid());

	delete store;
}

void SessionObjectStoreTests::testWipeStore()
{
	// Get access to the store
	SessionObjectStore* store = new SessionObjectStore();

	// Check that the store is empty
	CPPUNIT_ASSERT(store->getObjects().size() == 0);

	// Create 3 objects in the store for three different sessions
	SessionObject* obj1 = store->createObject(1, 1);
	CPPUNIT_ASSERT(obj1 != NULL);
	SessionObject* obj2 = store->createObject(1, 2);
	CPPUNIT_ASSERT(obj2 != NULL);
	SessionObject* obj3 = store->createObject(1, 3);
	CPPUNIT_ASSERT(obj3 != NULL);

	// Wipe the store
	store->clearStore();

	// Check that the store is empty
	CPPUNIT_ASSERT(store->getObjects().size() == 0);

	delete store;
}

