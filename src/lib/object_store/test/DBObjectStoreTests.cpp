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
 DBObjectStoreTests.cpp

 Contains test cases to test the object store implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DBObjectStoreTests.h"

#include <cstdio>

#ifndef HAVE_SQLITE3_H
#error expected sqlite3 to be available
#endif

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_newly_created_object_store);

void test_a_newly_created_object_store::setUp()
{
	CPPUNIT_ASSERT(!system("mkdir testdir"));

	ObjectStoreToken::selectBackend("db");

	store = new ObjectStore("testdir");
	nulltoken = NULL;
}

void test_a_newly_created_object_store::tearDown()
{
	delete store;

	ObjectStoreToken::selectBackend("file");

#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}


void test_a_newly_created_object_store::contains_no_items()
{
	CPPUNIT_ASSERT_EQUAL(store->getTokenCount(), (size_t)0);
}

void test_a_newly_created_object_store::can_create_a_new_token()
{
	ByteString label1 = "DEADC0FFEE";

	ObjectStoreToken *token1 = store->newToken(label1);
	CPPUNIT_ASSERT(token1 != nulltoken);
	CPPUNIT_ASSERT_EQUAL(store->getTokenCount(), (size_t)1);
}

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_newly_created_object_store_containing_two_tokens);


void test_a_newly_created_object_store_containing_two_tokens::setUp()
{
	test_a_newly_created_object_store::setUp();

	ByteString label1 = "DEADC0FFEE";
	ByteString label2 = "DEADBEEF";

	ObjectStoreToken* token1 = store->newToken(label1);
	CPPUNIT_ASSERT(token1 != nulltoken);
	CPPUNIT_ASSERT_EQUAL(store->getTokenCount(), (size_t)1);

	ObjectStoreToken* token2 = store->newToken(label2);
	CPPUNIT_ASSERT(token2 != nulltoken);
	CPPUNIT_ASSERT_EQUAL(store->getTokenCount(), (size_t)2);
}

void test_a_newly_created_object_store_containing_two_tokens::tearDown()
{
	ObjectStoreToken* token1 = store->getToken(0);
	ObjectStoreToken* token2 = store->getToken(1);
	CPPUNIT_ASSERT(store->destroyToken(token1));
	CPPUNIT_ASSERT(store->destroyToken(token2));

	test_a_newly_created_object_store::tearDown();
}

void test_a_newly_created_object_store_containing_two_tokens::has_two_tokens()
{
	CPPUNIT_ASSERT_EQUAL(store->getTokenCount(), (size_t)2);
}

void test_a_newly_created_object_store_containing_two_tokens::can_access_both_tokens()
{
	// Retrieve both tokens and check that both are present
	ObjectStoreToken* token1 = store->getToken(0);
	ObjectStoreToken* token2 = store->getToken(1);

	CPPUNIT_ASSERT(token1 != nulltoken);
	CPPUNIT_ASSERT(token2 != nulltoken);
}

void test_a_newly_created_object_store_containing_two_tokens::assigned_labels_correctly_to_tokens()
{
	ByteString label1 = "DEADC0FFEE";
	ByteString label2 = "DEADBEEF";

	// Retrieve both tokens and check that both are present
	ObjectStoreToken* token1 = store->getToken(0);
	ObjectStoreToken* token2 = store->getToken(1);

	ByteString retrieveLabel1, retrieveLabel2;

	CPPUNIT_ASSERT(token1->getTokenLabel(retrieveLabel1));
	CPPUNIT_ASSERT(token2->getTokenLabel(retrieveLabel2));

	CPPUNIT_ASSERT(label1 == retrieveLabel1 || label1 == retrieveLabel2);
	CPPUNIT_ASSERT(label2 == retrieveLabel1 || label2 == retrieveLabel2);
	CPPUNIT_ASSERT(label1 != label2);
}

void test_a_newly_created_object_store_containing_two_tokens::assigned_a_unique_serial_number_to_each_token()
{
	// Retrieve both tokens and check that both are present
	ObjectStoreToken* token1 = store->getToken(0);
	ObjectStoreToken* token2 = store->getToken(1);

	ByteString retrieveSerial1, retrieveSerial2;

	CPPUNIT_ASSERT(token1->getTokenSerial(retrieveSerial1));
	CPPUNIT_ASSERT(token2->getTokenSerial(retrieveSerial2));

	CPPUNIT_ASSERT(retrieveSerial1 != retrieveSerial2);
}
