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
 DBObjectTests.h

 Contains test cases to test the database token object implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DBOBJECTTESTS_H
#define _SOFTHSM_V2_DBOBJECTTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "DB.h"

class test_a_dbobject : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(test_a_dbobject);
	CPPUNIT_TEST(should_be_insertable);
	CPPUNIT_TEST(should_be_selectable);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp();
	void tearDown();

	void should_be_insertable();
	void should_be_selectable();

protected:
	DB::Connection *connection;
	DB::Connection *connection2;

private:
};

class test_a_dbobject_with_an_object : public test_a_dbobject
{
	CPPUNIT_TEST_SUITE(test_a_dbobject_with_an_object);
	CPPUNIT_TEST(should_store_boolean_attributes);
	CPPUNIT_TEST(should_store_unsigned_long_attributes);
	CPPUNIT_TEST(should_store_binary_attributes);
	CPPUNIT_TEST(should_store_mechtypeset_attributes);
	CPPUNIT_TEST(should_store_attrmap_attributes);
	CPPUNIT_TEST(should_store_mixed_attributes);
	CPPUNIT_TEST(should_store_double_attributes);
	CPPUNIT_TEST(can_refresh_attributes);
	CPPUNIT_TEST(should_cleanup_statements_during_transactions);
	CPPUNIT_TEST(should_use_transactions);
	CPPUNIT_TEST(should_fail_to_delete);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp();
	void tearDown();

	void should_store_boolean_attributes();
	void should_store_unsigned_long_attributes();
	void should_store_binary_attributes();
    void should_store_mechtypeset_attributes();
	void should_store_attrmap_attributes();
	void should_store_mixed_attributes();
	void should_store_double_attributes();
	void can_refresh_attributes();
	void should_cleanup_statements_during_transactions();
	void should_use_transactions();
	void should_fail_to_delete();
};

#endif // !_SOFTHSM_V2_DBOBJECTTESTS_H
