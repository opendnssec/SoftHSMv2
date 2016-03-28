/*
 * Copyright (c) 2013 SURFnet bv
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
 DBTokenTests.cpp

 Contains test cases to test the database token implementation
 *****************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DBTokenTests.h"
#include "DBToken.h"
#include "DB.h"

#include <cstdio>

#ifndef HAVE_SQLITE3_H
#error expected sqlite3 to be available
#endif

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_dbtoken);

static int dummy_print(const char *, va_list )
{
	return 0;
}

void test_a_dbtoken::setUp()
{
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void test_a_dbtoken::tearDown()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void test_a_dbtoken::should_be_creatable()
{
	ByteString label = "40414243"; // ABCD
	ByteString serial = "0102030405060708";

	ObjectStoreToken* newToken = new DBToken("testdir", "newToken", label, serial);

	CPPUNIT_ASSERT(newToken != NULL);

	CPPUNIT_ASSERT(newToken->isValid());

	delete newToken;
}

void test_a_dbtoken::should_support_pin_setting_getting()
{
	// Create a new token
	ByteString label = "40414243"; // ABCD
	ByteString serial = "0102030405060708";

	ObjectStoreToken* newToken = new DBToken("testdir", "newToken", label, serial);

	CPPUNIT_ASSERT(newToken != NULL);

	CPPUNIT_ASSERT(newToken->isValid());

	// Check the flags
	CK_ULONG flags;
	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT_EQUAL(flags, (CK_ULONG)( CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_SO_PIN_LOCKED | CKF_SO_PIN_TO_BE_CHANGED));

	// Set the SO PIN
	ByteString soPIN = "3132333435363738"; // 12345678

	CPPUNIT_ASSERT(newToken->setSOPIN(soPIN));

	// Set the user PIN
	ByteString userPIN = "31323334"; // 1234

	CPPUNIT_ASSERT(newToken->setUserPIN(userPIN));

	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT_EQUAL(flags, (CK_ULONG)(CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	delete newToken;

	// Now reopen the newly created token
	DBToken reopenedToken("testdir","newToken");

	CPPUNIT_ASSERT(reopenedToken.isValid());

	// Retrieve the flags, user PIN and so PIN
	ByteString retrievedSOPIN, retrievedUserPIN;

	CPPUNIT_ASSERT(reopenedToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(reopenedToken.getUserPIN(retrievedUserPIN));
	CPPUNIT_ASSERT(reopenedToken.getTokenFlags(flags));

	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);
	CPPUNIT_ASSERT(retrievedUserPIN == userPIN);
	CPPUNIT_ASSERT_EQUAL(flags, (CK_ULONG)(CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));
}

void test_a_dbtoken::should_allow_object_enumeration()
{
	ByteString label = "40414243"; // ABCD
	ByteString serial = "0102030405060708";
	ByteString soPIN = "31323334"; // 1234
	ByteString userPIN = "30303030"; // 0000
	ByteString id[3] = { "112233445566", "AABBCCDDEEFF", "ABABABABABAB" };

	{
		// Instantiate a new token
		ObjectStoreToken* newToken = new DBToken("testdir", "existingToken", label, serial);
		CPPUNIT_ASSERT(newToken != NULL);
		CPPUNIT_ASSERT(newToken->isValid());
		CPPUNIT_ASSERT(newToken->setSOPIN(soPIN));
		CPPUNIT_ASSERT(newToken->setUserPIN(userPIN));

		// Test IDs
		OSAttribute idAtt[3] = { id[0], id[1], id[2] };

		// Create 3 objects on the token
		OSObject* obj1 = newToken->createObject();
		CPPUNIT_ASSERT(obj1 != NULL);
		OSObject* obj2 = newToken->createObject();
		CPPUNIT_ASSERT(obj2 != NULL);
		OSObject* obj3 = newToken->createObject();
		CPPUNIT_ASSERT(obj3 != NULL);

		// Now set the IDs of the 3 objects
		obj1->startTransaction(OSObject::ReadWrite);
		CPPUNIT_ASSERT(obj1->setAttribute(CKA_ID, idAtt[0]));
		obj1->commitTransaction();

		obj2->startTransaction(OSObject::ReadWrite);
		CPPUNIT_ASSERT(obj2->setAttribute(CKA_ID, idAtt[1]));
		obj2->commitTransaction();

		obj3->startTransaction(OSObject::ReadWrite);
		CPPUNIT_ASSERT(obj3->setAttribute(CKA_ID, idAtt[2]));
		obj3->commitTransaction();

		delete newToken;
	}

	// Now open the token
	DBToken existingToken("testdir","existingToken");

	CPPUNIT_ASSERT(existingToken.isValid());

	// Retrieve SO PIN, user PIN, label, serial number and flags
	ByteString retrievedSOPIN, retrievedUserPIN, retrievedLabel, retrievedSerial;
	CK_ULONG flags;

	CPPUNIT_ASSERT(existingToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(existingToken.getUserPIN(retrievedUserPIN));
	CPPUNIT_ASSERT(existingToken.getTokenLabel(retrievedLabel));
	CPPUNIT_ASSERT(existingToken.getTokenSerial(retrievedSerial));
	CPPUNIT_ASSERT(existingToken.getTokenFlags(flags));

	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);
	CPPUNIT_ASSERT(retrievedUserPIN == userPIN);
	CPPUNIT_ASSERT(retrievedLabel == label);
	CPPUNIT_ASSERT(retrievedSerial == serial);
	CPPUNIT_ASSERT_EQUAL(flags, (CK_ULONG)(CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	// Check that the token contains 3 objects
	CPPUNIT_ASSERT_EQUAL(existingToken.getObjects().size(), (size_t)3);

	// Check that all the tokens are presented
	bool present[3] = { false, false, false };
	std::set<OSObject*> objects = existingToken.getObjects();

	for (std::set<OSObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[0])
		{
			present[0] = true;
		}
		else if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[1])
		{
			present[1] = true;
		}
		else if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[2])
		{
			present[2] = true;
		}
	}

	CPPUNIT_ASSERT(present[0]);
	CPPUNIT_ASSERT(present[1]);
	CPPUNIT_ASSERT(present[2]);
}

void test_a_dbtoken::should_fail_to_open_nonexistant_tokens()
{
	DBToken doesntExist("testdir","doesntExist");

	CPPUNIT_ASSERT(!doesntExist.isValid());
}

void test_a_dbtoken::support_create_delete_objects()
{
	// Test IDs
	ByteString id[5] = { "112233445566", "AABBCCDDEEFF", "ABABABABABAB", "557788991122", "005500550055" };
	OSAttribute idAtt[5] = { id[0], id[1], id[2], id[3], id[4] };
	ByteString label = "AABBCCDDEEFF";
	ByteString serial = "1234567890";

	// Instantiate a new token
	ObjectStoreToken* testToken = new DBToken("testdir", "testToken", label, serial);
	CPPUNIT_ASSERT(testToken != NULL);
	CPPUNIT_ASSERT(testToken->isValid());

	// Open the same token
	DBToken sameToken("testdir","testToken");
	CPPUNIT_ASSERT(sameToken.isValid());

	// Create 3 objects on the token
	OSObject* obj1 = testToken->createObject();
	CPPUNIT_ASSERT(obj1 != NULL);
	OSObject* obj2 = testToken->createObject();
	CPPUNIT_ASSERT(obj2 != NULL);
	OSObject* obj3 = testToken->createObject();
	CPPUNIT_ASSERT(obj3 != NULL);

	// Now set the IDs of the 3 objects
	obj1->setAttribute(CKA_ID, idAtt[0]);
	obj2->setAttribute(CKA_ID, idAtt[1]);
	obj3->setAttribute(CKA_ID, idAtt[2]);

	// Check that the token contains 3 objects
	CPPUNIT_ASSERT_EQUAL(testToken->getObjects().size(), (size_t)3);

	// Check that all three objects are distinct and present
	std::set<OSObject*> objects = testToken->getObjects();
	bool present1[3] = { false, false, false };

	for (std::set<OSObject*>::iterator i = objects.begin(); i != objects.end(); i++)
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
		CPPUNIT_ASSERT(present1[j]);
	}

	// Now check that the same objects are present in the other instance of the same token
	std::set<OSObject*> otherObjects = sameToken.getObjects();
	CPPUNIT_ASSERT_EQUAL(otherObjects.size(), (size_t)3);

	bool present2[3] = { false, false, false };

	for (std::set<OSObject*>::iterator i = otherObjects.begin(); i != otherObjects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		for (int j = 0; j < 3; j++)
		{
			if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[j])
			{
				present2[j] = true;
			}
		}
	}

	for (int j = 0; j < 3; j++)
	{
		CPPUNIT_ASSERT(present2[j]);
	}

	// Now delete the second object
	for (std::set<OSObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[1])
		{
			CPPUNIT_ASSERT(testToken->deleteObject(*i));
			break;
		}
	}

	// Verify that it was indeed removed
	CPPUNIT_ASSERT_EQUAL(testToken->getObjects().size(),(size_t)2);

	objects = testToken->getObjects();
	bool present3[2] = { false, false };

	for (std::set<OSObject*>::iterator i = objects.begin(); i != objects.end(); i++)
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
		CPPUNIT_ASSERT(present3[j]);
	}

	// Now check the other instance
	CPPUNIT_ASSERT_EQUAL(sameToken.getObjects().size(), (size_t)2);

	otherObjects = sameToken.getObjects();
	bool present4[2] = { false, false };

	for (std::set<OSObject*>::iterator i = otherObjects.begin(); i != otherObjects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[0])
		{
			present4[0] = true;
		}
		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id[2])
		{
			present4[1] = true;
		}
	}

	for (int j = 0; j < 2; j++)
	{
		CPPUNIT_ASSERT(present4[j]);
	}


	// Release the test token
	delete testToken;
}

void test_a_dbtoken::support_clearing_a_token()
{
	// Create a new token
	ByteString label = "40414243"; // ABCD
	ByteString serial = "0102030405060708";

	ObjectStoreToken* newToken = new DBToken("testdir", "newToken", label, serial);

	CPPUNIT_ASSERT(newToken != NULL);
	CPPUNIT_ASSERT(newToken->isValid());

	// Check the flags
	CK_ULONG flags;
	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT_EQUAL(flags, (CK_ULONG)(CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_SO_PIN_LOCKED | CKF_SO_PIN_TO_BE_CHANGED));

	// Set the SO PIN
	ByteString soPIN = "3132333435363738"; // 12345678

	CPPUNIT_ASSERT(newToken->setSOPIN(soPIN));

	// Set the user PIN
	ByteString userPIN = "31323334"; // 1234

	CPPUNIT_ASSERT(newToken->setUserPIN(userPIN));

	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT_EQUAL(flags,  (CK_ULONG)(CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	CPPUNIT_ASSERT(newToken->createObject() != NULL);

	delete newToken;

#if 1
	// Reopen the newly created token and keep a reference around.
	DBToken referencingToken("testdir", "newToken");
	CPPUNIT_ASSERT(referencingToken.isValid());
#endif
	// Now reopen the newly created token
	DBToken reopenedToken("testdir","newToken");

	CPPUNIT_ASSERT(reopenedToken.isValid());

	// Retrieve the flags, user PIN and so PIN
	ByteString retrievedSOPIN, retrievedUserPIN;

	CPPUNIT_ASSERT(reopenedToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(reopenedToken.getUserPIN(retrievedUserPIN));
	CPPUNIT_ASSERT(reopenedToken.getTokenFlags(flags));

	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);
	CPPUNIT_ASSERT(retrievedUserPIN == userPIN);
	CPPUNIT_ASSERT_EQUAL(flags, (CK_ULONG)(CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	// Now reset the token
	CPPUNIT_ASSERT(reopenedToken.resetToken(label));
	CPPUNIT_ASSERT(reopenedToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(!reopenedToken.getUserPIN(retrievedUserPIN));
	CPPUNIT_ASSERT(reopenedToken.getTokenFlags(flags));
	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);
	CPPUNIT_ASSERT_EQUAL(flags, (CK_ULONG)(CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED));
	CPPUNIT_ASSERT(reopenedToken.isValid());

	// Now clear the token
	CPPUNIT_ASSERT(reopenedToken.clearToken());
	CPPUNIT_ASSERT(!reopenedToken.isValid());

	DB::LogErrorHandler eh = DB::setLogErrorHandler(dummy_print);

	// Try to open it once more and make sure it has been deleted.
	DBToken clearedToken("testdir","newToken");
	CPPUNIT_ASSERT(!clearedToken.isValid());

#if 1
	// Verify that it is no longer possible to access the database...
	CPPUNIT_ASSERT(!referencingToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);

	std::set<OSObject *> objects = referencingToken.getObjects();
	CPPUNIT_ASSERT_EQUAL(objects.size(), (size_t)0);

	CPPUNIT_ASSERT(!referencingToken.isValid());
#endif

	DB::setLogErrorHandler(eh);
}
