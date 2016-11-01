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
 OSTokenTests.cpp

 Contains test cases to test the object file implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "OSTokenTests.h"
#include "OSToken.h"
#include "ObjectFile.h"
#include "File.h"
#include "Directory.h"
#include "OSAttribute.h"
#include "OSAttributes.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(OSTokenTests);

// FIXME: all pathnames in this file are *NIX/BSD specific

void OSTokenTests::setUp()
{
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void OSTokenTests::tearDown()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void OSTokenTests::testNewToken()
{
	// Create a new token
	ByteString label = "40414243"; // ABCD
	ByteString serial = "0102030405060708";

#ifndef _WIN32
	OSToken* newToken = OSToken::createToken("./testdir", "newToken", label, serial);
#else
	OSToken* newToken = OSToken::createToken(".\\testdir", "newToken", label, serial);
#endif

	CPPUNIT_ASSERT(newToken != NULL);

	// Check the flags
	CK_ULONG flags;
	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_SO_PIN_LOCKED | CKF_SO_PIN_TO_BE_CHANGED));

	// Set the SO PIN
	ByteString soPIN = "3132333435363738"; // 12345678

	CPPUNIT_ASSERT(newToken->setSOPIN(soPIN));

	// Set the user PIN
	ByteString userPIN = "31323334"; // 1234

	CPPUNIT_ASSERT(newToken->setUserPIN(userPIN));

	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	delete newToken;

	// Now reopen the newly created token
#ifndef _WIN32
	OSToken reopenedToken("./testdir/newToken");
#else
	OSToken reopenedToken(".\\testdir\\newToken");
#endif

	CPPUNIT_ASSERT(reopenedToken.isValid());

	// Retrieve the flags, user PIN and so PIN
	ByteString retrievedSOPIN, retrievedUserPIN;

	CPPUNIT_ASSERT(reopenedToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(reopenedToken.getUserPIN(retrievedUserPIN));
	CPPUNIT_ASSERT(reopenedToken.getTokenFlags(flags));

	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);
	CPPUNIT_ASSERT(retrievedUserPIN == userPIN);
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));
}

void OSTokenTests::testExistingToken()
{
	ByteString label = "40414243"; // ABCD
	ByteString serial = "0102030405060708";
	ByteString soPIN = "31323334"; // 1234
	ByteString userPIN = "30303030"; // 0000
	ByteString id1 = "ABCDEF";
	ByteString id2 = "FEDCBA";
	ByteString id3 = "AABBCC";

	{
		// Create the token dir
#ifndef _WIN32
		CPPUNIT_ASSERT(!system("mkdir testdir/existingToken"));
#else
		CPPUNIT_ASSERT(!system("mkdir testdir\\existingToken"));
#endif

		// Create the token object
#ifndef _WIN32
		ObjectFile tokenObject(NULL, "./testdir/existingToken/token.object", "./testdir/existingToken/token.lock", true);
#else
		ObjectFile tokenObject(NULL, ".\\testdir\\existingToken\\token.object", ".\\testdir\\existingToken\\token.lock", true);
#endif

		OSAttribute labelAtt(label);
		CPPUNIT_ASSERT(tokenObject.setAttribute(CKA_OS_TOKENLABEL, labelAtt));
		OSAttribute serialAtt(serial);
		CPPUNIT_ASSERT(tokenObject.setAttribute(CKA_OS_TOKENSERIAL, serialAtt));
		OSAttribute soPINAtt(soPIN);
		CPPUNIT_ASSERT(tokenObject.setAttribute(CKA_OS_SOPIN, soPINAtt));
		OSAttribute userPINAtt(userPIN);
		CPPUNIT_ASSERT(tokenObject.setAttribute(CKA_OS_USERPIN, userPINAtt));
		CK_ULONG flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED;
 		OSAttribute flagsAtt(flags);
		CPPUNIT_ASSERT(tokenObject.setAttribute(CKA_OS_TOKENFLAGS, flagsAtt));

		// Create 3 objects
#ifndef _WIN32
		ObjectFile obj1(NULL, "./testdir/existingToken/1.object", "./testdir/existingToken/1.lock", true);
		ObjectFile obj2(NULL, "./testdir/existingToken/2.object", "./testdir/existingToken/2.lock", true);
		ObjectFile obj3(NULL, "./testdir/existingToken/3.object", "./testdir/existingToken/3.lock", true);
#else
		ObjectFile obj1(NULL, ".\\testdir\\existingToken\\1.object", ".\\testdir\\existingToken\\1.lock", true);
		ObjectFile obj2(NULL, ".\\testdir\\existingToken\\2.object", ".\\testdir\\existingToken\\2.lock", true);
		ObjectFile obj3(NULL, ".\\testdir\\existingToken\\3.object", ".\\testdir\\existingToken\\3.lock", true);
#endif

		OSAttribute id1Att(id1);
		OSAttribute id2Att(id2);
		OSAttribute id3Att(id3);

		CPPUNIT_ASSERT(obj1.setAttribute(CKA_ID, id1));
		CPPUNIT_ASSERT(obj2.setAttribute(CKA_ID, id2));
		CPPUNIT_ASSERT(obj3.setAttribute(CKA_ID, id3));
	}

	// Now open the token
#ifndef _WIN32
	OSToken existingToken("./testdir/existingToken");
#else
	OSToken existingToken(".\\testdir\\existingToken");
#endif


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
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	// Check that the token contains 3 objects
	CPPUNIT_ASSERT(existingToken.getObjects().size() == 3);

	// Check that all the tokens are presented
	bool present[3] = { false, false, false };
	std::set<OSObject*> objects = existingToken.getObjects();

	for (std::set<OSObject*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		ByteString retrievedId;

		CPPUNIT_ASSERT((*i)->isValid());
		CPPUNIT_ASSERT((*i)->attributeExists(CKA_ID));

		CPPUNIT_ASSERT((*i)->getAttribute(CKA_ID).isByteStringAttribute());

		if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id1)
		{
			present[0] = true;
		}
		else if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id2)
		{
			present[1] = true;
		}
		else if ((*i)->getAttribute(CKA_ID).getByteStringValue() == id3)
		{
			present[2] = true;
		}
	}

	CPPUNIT_ASSERT(present[0] == true);
	CPPUNIT_ASSERT(present[1] == true);
	CPPUNIT_ASSERT(present[2] == true);
}

void OSTokenTests::testNonExistentToken()
{
#ifndef _WIN32
	OSToken doesntExist("./testdir/doesntExist");
#else
	OSToken doesntExist(".\\testdir\\doesntExist");
#endif

	CPPUNIT_ASSERT(!doesntExist.isValid());
}

void OSTokenTests::testCreateDeleteObjects()
{
	// Test IDs
	ByteString id[5] = { "112233445566", "AABBCCDDEEFF", "ABABABABABAB", "557788991122", "005500550055" };
	OSAttribute idAtt[5] = { id[0], id[1], id[2], id[3], id[4] };
	ByteString label = "AABBCCDDEEFF";
	ByteString serial = "1234567890";

	// Instantiate a new token
#ifndef _WIN32
	OSToken* testToken = OSToken::createToken("./testdir", "testToken", label, serial);
#else
	OSToken* testToken = OSToken::createToken(".\\testdir", "testToken", label, serial);
#endif

	CPPUNIT_ASSERT(testToken != NULL);
	CPPUNIT_ASSERT(testToken->isValid());

	// Open the same token
#ifndef _WIN32
	OSToken sameToken("./testdir/testToken");
#else
	OSToken sameToken(".\\testdir\\testToken");
#endif

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
	CPPUNIT_ASSERT(testToken->getObjects().size() == 3);

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
		CPPUNIT_ASSERT(present1[j] == true);
	}

	// Now check that the same objects are present in the other instance of the same token
	std::set<OSObject*> otherObjects = sameToken.getObjects();
	CPPUNIT_ASSERT(otherObjects.size() == 3);

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
		CPPUNIT_ASSERT(present2[j] == true);
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
	CPPUNIT_ASSERT(testToken->getObjects().size() == 2);

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
		CPPUNIT_ASSERT(present3[j] == true);
	}

	// Now check the other instance
	CPPUNIT_ASSERT(sameToken.getObjects().size() == 2);

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
		CPPUNIT_ASSERT(present4[j] == true);
	}


	// Release the test token
	delete testToken;
}

void OSTokenTests::testClearToken()
{
	// Create a new token
	ByteString label = "40414243"; // ABCD
	ByteString serial = "0102030405060708";

#ifndef _WIN32
	OSToken* newToken = OSToken::createToken("./testdir", "newToken", label, serial);
#else
	OSToken* newToken = OSToken::createToken(".\\testdir", "newToken", label, serial);
#endif

	CPPUNIT_ASSERT(newToken != NULL);

	// Check the flags
	CK_ULONG flags;
	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_SO_PIN_LOCKED | CKF_SO_PIN_TO_BE_CHANGED));

	// Set the SO PIN
	ByteString soPIN = "3132333435363738"; // 12345678

	CPPUNIT_ASSERT(newToken->setSOPIN(soPIN));

	// Set the user PIN
	ByteString userPIN = "31323334"; // 1234

	CPPUNIT_ASSERT(newToken->setUserPIN(userPIN));

	CPPUNIT_ASSERT(newToken->getTokenFlags(flags));
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	delete newToken;

	// Now reopen the newly created token
#ifndef _WIN32
	OSToken reopenedToken("./testdir/newToken");
#else
	OSToken reopenedToken(".\\testdir\\newToken");
#endif

	CPPUNIT_ASSERT(reopenedToken.isValid());

	// Retrieve the flags, user PIN and so PIN
	ByteString retrievedSOPIN, retrievedUserPIN;

	CPPUNIT_ASSERT(reopenedToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(reopenedToken.getUserPIN(retrievedUserPIN));
	CPPUNIT_ASSERT(reopenedToken.getTokenFlags(flags));

	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);
	CPPUNIT_ASSERT(retrievedUserPIN == userPIN);
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED));

	// Now reset the token
	CPPUNIT_ASSERT(reopenedToken.resetToken(label));
	CPPUNIT_ASSERT(reopenedToken.getSOPIN(retrievedSOPIN));
	CPPUNIT_ASSERT(!reopenedToken.getUserPIN(retrievedUserPIN));
	CPPUNIT_ASSERT(reopenedToken.getTokenFlags(flags));
	CPPUNIT_ASSERT(retrievedSOPIN == soPIN);
	CPPUNIT_ASSERT(flags == (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED));
	CPPUNIT_ASSERT(reopenedToken.isValid());

	// Now clear the token
	CPPUNIT_ASSERT(reopenedToken.clearToken());
	CPPUNIT_ASSERT(!reopenedToken.isValid());

	// Try to open it once more
#ifndef _WIN32
	OSToken clearedToken("./testdir/newToken");
#else
	OSToken clearedToken(".\\testdir\\newToken");
#endif

	CPPUNIT_ASSERT(!clearedToken.isValid());
}

