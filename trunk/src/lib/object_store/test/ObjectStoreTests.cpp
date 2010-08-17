/* $Id$ */

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
 ObjectStoreTests.cpp

 Contains test cases to test the object store implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "ObjectStoreTests.h"
#include "ObjectStore.h"
#include "OSToken.h"
#include "ObjectFile.h"
#include "File.h"
#include "Directory.h"
#include "OSAttribute.h"
#include "OSAttributes.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ObjectStoreTests);

// FIXME: all pathnames in this file are *NIX/BSD specific

void ObjectStoreTests::setUp()
{
	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void ObjectStoreTests::tearDown()
{
	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
}

void ObjectStoreTests::testEmptyStore()
{
	// Create the store for an empty dir
	ObjectStore store("./testdir");

	CPPUNIT_ASSERT(store.getTokenCount() == 0);
}

void ObjectStoreTests::testNewTokens()
{
	ByteString label1 = "DEADC0FFEE";
	ByteString label2 = "DEADBEEF";

	{
		// Create an empty store
		ObjectStore store("./testdir");

		CPPUNIT_ASSERT(store.getTokenCount() == 0);

		// Create a new token
		OSToken* token1 = store.newToken(label1);

		CPPUNIT_ASSERT(token1 != NULL);

		CPPUNIT_ASSERT(store.getTokenCount() == 1);

		// Create another new token
		OSToken* token2 = store.newToken(label2);

		CPPUNIT_ASSERT(token2 != NULL);

		CPPUNIT_ASSERT(store.getTokenCount() == 2);
	}

	// Now reopen that same store
	ObjectStore store("./testdir");

	CPPUNIT_ASSERT(store.getTokenCount() == 2);

	// Retrieve both tokens and check that both are present
	OSToken* token1 = store.getToken(0);
	OSToken* token2 = store.getToken(1);

	ByteString retrieveLabel1, retrieveLabel2;

	CPPUNIT_ASSERT(token1->getTokenLabel(retrieveLabel1));
	CPPUNIT_ASSERT(token2->getTokenLabel(retrieveLabel2));

	CPPUNIT_ASSERT((retrieveLabel1 == label1) || (retrieveLabel2 == label1));
	CPPUNIT_ASSERT((retrieveLabel2 == label1) || (retrieveLabel2 == label2));

	ByteString retrieveSerial1, retrieveSerial2;

	CPPUNIT_ASSERT(token1->getTokenSerial(retrieveSerial1));
	CPPUNIT_ASSERT(token2->getTokenSerial(retrieveSerial2));

	CPPUNIT_ASSERT(retrieveSerial1 != retrieveSerial2);
}

void ObjectStoreTests::testExistingTokens()
{
	// Create some tokens
	ByteString label1 = "DEADC0FFEE";
	ByteString label2 = "DEADBEEF";
	ByteString serial1 = "0011001100110011";
	ByteString serial2 = "2233223322332233";

	OSToken* token1 = OSToken::createToken("./testdir", "token1", label1, serial1);
	OSToken* token2 = OSToken::createToken("./testdir", "token2", label2, serial2);

	CPPUNIT_ASSERT((token1 != NULL) && (token2 != NULL));

	delete token1;
	delete token2;

	// Now associate a store with the test directory
	ObjectStore store("./testdir");

	CPPUNIT_ASSERT(store.getTokenCount() == 2);

	// Retrieve both tokens and check that both are present
	OSToken* retrieveToken1 = store.getToken(0);
	OSToken* retrieveToken2 = store.getToken(1);

	ByteString retrieveLabel1, retrieveLabel2, retrieveSerial1, retrieveSerial2;

	CPPUNIT_ASSERT(retrieveToken1 != NULL);
	CPPUNIT_ASSERT(retrieveToken2 != NULL);

	CPPUNIT_ASSERT(retrieveToken1->getTokenLabel(retrieveLabel1));
	CPPUNIT_ASSERT(retrieveToken2->getTokenLabel(retrieveLabel2));
	CPPUNIT_ASSERT(retrieveToken1->getTokenSerial(retrieveSerial1));
	CPPUNIT_ASSERT(retrieveToken2->getTokenSerial(retrieveSerial2));

	CPPUNIT_ASSERT((retrieveLabel1 == label1) || (retrieveLabel1 == label2));
	CPPUNIT_ASSERT((retrieveLabel2 == label1) || (retrieveLabel2 == label2));
	CPPUNIT_ASSERT(retrieveLabel1 != retrieveLabel2);
	CPPUNIT_ASSERT((retrieveSerial1 == serial1) || (retrieveSerial1 == serial2));
	CPPUNIT_ASSERT((retrieveSerial2 == serial1) || (retrieveSerial2 == serial2));
	CPPUNIT_ASSERT(retrieveSerial1 != retrieveSerial2);
}

