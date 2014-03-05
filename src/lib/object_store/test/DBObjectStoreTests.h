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
 DBObjectStoreTests.h

 Contains test cases to test the object store implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DBOBJECTSTORETESTS_H
#define _SOFTHSM_V2_DBOBJECTSTORETESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "ObjectStore.h"
#include "ObjectStoreToken.h"

class test_a_newly_created_object_store : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(test_a_newly_created_object_store);
	CPPUNIT_TEST(contains_no_items);
	CPPUNIT_TEST(can_create_a_new_token);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp();
	void tearDown();

	void contains_no_items();
	void can_create_a_new_token();
protected:
	ObjectStore *store;
	ObjectStoreToken *nulltoken;

private:
};

class test_a_newly_created_object_store_containing_two_tokens : public test_a_newly_created_object_store
{
	CPPUNIT_TEST_SUITE(test_a_newly_created_object_store_containing_two_tokens);
	CPPUNIT_TEST(has_two_tokens);
	CPPUNIT_TEST(can_access_both_tokens);
	CPPUNIT_TEST(assigned_labels_correctly_to_tokens);
	CPPUNIT_TEST(assigned_a_unique_serial_number_to_each_token);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp();
	void tearDown();

	void has_two_tokens();
	void can_access_both_tokens();
	void assigned_labels_correctly_to_tokens();
	void assigned_a_unique_serial_number_to_each_token();
};

#endif // !_SOFTHSM_V2_DBOBJECTSTORETESTS_H
