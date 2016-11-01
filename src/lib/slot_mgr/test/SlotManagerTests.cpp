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
 SlotManagerTests.cpp

 Contains test cases to test the object store implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "SlotManagerTests.h"
#include "SlotManager.h"
#include "Token.h"
#include "ObjectStore.h"
#include "ObjectFile.h"
#include "File.h"
#include "Directory.h"
#include "OSAttribute.h"
#include "OSAttributes.h"
#include "CryptoFactory.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SlotManagerTests);

void SlotManagerTests::setUp()
{
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void SlotManagerTests::tearDown()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void SlotManagerTests::testNoExistingTokens()
{
	// Create an empty object store
#ifndef _WIN32
	ObjectStore store("./testdir");
#else
	ObjectStore store(".\\testdir");
#endif

	// Create the slot manager
	SlotManager slotManager(&store);

	CPPUNIT_ASSERT(slotManager.getSlots().size() == 1);

	// Test C_GetSlotList
	CK_SLOT_ID testList[10];
	CK_ULONG ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 1);

	ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 1);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotID() == testList[0]);

	// Retrieve slot information about the first slot
	CK_SLOT_INFO slotInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the first slot
	CK_TOKEN_INFO tokenInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != CKF_TOKEN_INITIALIZED);
}

void SlotManagerTests::testExistingTokens()
{
	// Create an empty object store
#ifndef _WIN32
	ObjectStore store("./testdir");
#else
	ObjectStore store(".\\testdir");
#endif

	// Create two tokens
	ByteString label1 = "DEADBEEF";
	ByteString label2 = "DEADC0FFEE";

	CPPUNIT_ASSERT(store.newToken(label1) != NULL);
	CPPUNIT_ASSERT(store.newToken(label2) != NULL);

	// Now attach the slot manager
	SlotManager slotManager(&store);

	CPPUNIT_ASSERT(slotManager.getSlots().size() == 3);

	// Test C_GetSlotList
	CK_SLOT_ID testList[10];
	CK_ULONG ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 3);

	ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 3);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotID() == testList[0]);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getSlotID() == testList[1]);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getSlotID() == testList[2]);

	// Retrieve slot information about the first slot
	CK_SLOT_INFO slotInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the first slot
	CK_TOKEN_INFO tokenInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(!memcmp(tokenInfo.label, &label1[0], label1.size()) || 
	               !memcmp(tokenInfo.label, &label2[0], label2.size()));

	// Retrieve slot information about the second slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the second slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(!memcmp(tokenInfo.label, &label1[0], label1.size()) || 
	               !memcmp(tokenInfo.label, &label2[0], label2.size()));

	// Retrieve slot information about the third slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the third slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != CKF_TOKEN_INITIALIZED);
}

void SlotManagerTests::testInitialiseTokenInLastSlot()
{
	{
		// Create an empty object store
#ifndef _WIN32
		ObjectStore store("./testdir");
#else
		ObjectStore store(".\\testdir");
#endif

		// Create the slot manager
		SlotManager slotManager(&store);

		CPPUNIT_ASSERT(slotManager.getSlots().size() == 1);

		// Test C_GetSlotList
		CK_SLOT_ID testList[10];
		CK_ULONG ulCount = 10;

		CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
		CPPUNIT_ASSERT(ulCount == 1);

		ulCount = 10;

		CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
		CPPUNIT_ASSERT(ulCount == 1);
		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotID() == testList[0]);

		// Retrieve slot information about the first slot
		CK_SLOT_INFO slotInfo;

		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotInfo(&slotInfo) == CKR_OK);

		CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

		// Retrieve token information about the token in the first slot
		CK_TOKEN_INFO tokenInfo;

		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

		CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != CKF_TOKEN_INITIALIZED);

		// Now initialise the token in the first slot
		ByteString soPIN((unsigned char*)"1234", 4);
		CK_UTF8CHAR label[33] = "My test token                   ";

		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->initToken(soPIN, label) == CKR_OK);

		// Retrieve slot information about the first slot
		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotInfo(&slotInfo) == CKR_OK);

		CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

		// Retrieve token information about the token in the first slot
		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
		CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

		CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
		CPPUNIT_ASSERT(!memcmp(tokenInfo.label, label, 32));
	}

	// Attach a fresh slot manager
#ifndef _WIN32
	ObjectStore store("./testdir");
#else
	ObjectStore store(".\\testdir");
#endif
	SlotManager slotManager(&store);

	CPPUNIT_ASSERT(slotManager.getSlots().size() == 2);

	// Test C_GetSlotList
	CK_SLOT_ID testList[10];
	CK_ULONG ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 2);

	ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 2);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotID() == testList[0]);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getSlotID() == testList[1]);

	// Retrieve slot information about the first slot
	CK_SLOT_INFO slotInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the first slot
	CK_TOKEN_INFO tokenInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);

	CK_UTF8CHAR label[33] = "My test token                   ";
	CPPUNIT_ASSERT(!memcmp(tokenInfo.label, label, 32));

	// Retrieve slot information about the second slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the second slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != CKF_TOKEN_INITIALIZED);
}

void SlotManagerTests::testReinitialiseExistingToken()
{
	// Create an empty object store
#ifndef _WIN32
	ObjectStore store("./testdir");
#else
	ObjectStore store(".\\testdir");
#endif

	// Create two tokens
	ByteString label1 = "DEADBEEF";
	ByteString label2 = "DEADC0FFEE";

	CPPUNIT_ASSERT(store.newToken(label1) != NULL);
	CPPUNIT_ASSERT(store.newToken(label2) != NULL);

	// Now attach the slot manager
	SlotManager slotManager(&store);

	CPPUNIT_ASSERT(slotManager.getSlots().size() == 3);

	// Test C_GetSlotList
	CK_SLOT_ID testList[10];
	CK_ULONG ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 3);

	ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 3);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotID() == testList[0]);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getSlotID() == testList[1]);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getSlotID() == testList[2]);

	// Retrieve slot information about the first slot
	CK_SLOT_INFO slotInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the first slot
	CK_TOKEN_INFO tokenInfo;

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(!memcmp(tokenInfo.label, &label1[0], label1.size()) || 
	               !memcmp(tokenInfo.label, &label2[0], label2.size()));

	// Retrieve slot information about the second slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the second slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(!memcmp(tokenInfo.label, &label1[0], label1.size()) || 
	               !memcmp(tokenInfo.label, &label2[0], label2.size()));

	// Retrieve slot information about the third slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the third slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != CKF_TOKEN_INITIALIZED);

	// Now reinitialise the token in the second slot
	ByteString soPIN((unsigned char*)"1234", 4);
	CK_UTF8CHAR label[33] = "My test token                   ";

	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->initToken(soPIN, label) == CKR_OK);

	// Retrieve slot information about the first slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getSlotInfo(&slotInfo) == CKR_OK);

	CPPUNIT_ASSERT((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);

	// Retrieve token information about the token in the first slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(!memcmp(tokenInfo.label, label, 32));
}

void SlotManagerTests::testUninitialisedToken()
{
	// Create an empty object store
#ifndef _WIN32
	ObjectStore store("./testdir");
#else
	ObjectStore store(".\\testdir");
#endif

	// Now attach the slot manager
	SlotManager slotManager(&store);

	CPPUNIT_ASSERT(slotManager.getSlots().size() == 1);

	// Test C_GetSlotList
	CK_SLOT_ID testList[10];
	CK_ULONG ulCount = 10;

	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 1);
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 1);

	// Initialise the token in the first slot
	ByteString soPIN((unsigned char*)"1234", 4);
	CK_UTF8CHAR label[33] = "My test token                   ";
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->initToken(soPIN, label) == CKR_OK);

	// Check if a new slot is added
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 1);
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 1);
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, NULL_PTR, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 2);
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, NULL_PTR, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 2);

	// get new list
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 2);

	// Retrieve token information about the tokens
	CK_TOKEN_INFO tokenInfo;
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);
	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);
	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != CKF_TOKEN_INITIALIZED);

	// Initialise the token in the second slot
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->initToken(soPIN, label) == CKR_OK);

	// Check if a new slot is added
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 2);
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 2);
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_FALSE, NULL_PTR, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 3);
	ulCount = 10;
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, NULL_PTR, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 3);

	// get new list
	CPPUNIT_ASSERT(slotManager.getSlotList(&store, CK_TRUE, testList, &ulCount) == CKR_OK);
	CPPUNIT_ASSERT(ulCount == 3);

	// Retrieve token information about the tokens
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[0]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);
	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[1]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);
	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getToken() != NULL);
	CPPUNIT_ASSERT(slotManager.getSlots()[testList[2]]->getToken()->getTokenInfo(&tokenInfo) == CKR_OK);
	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != CKF_TOKEN_INITIALIZED);
}

