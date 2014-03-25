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
 DBTests.h

 Contains lowest level test cases for the database backend implementation.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DBTESTS_H
#define _SOFTHSM_V2_DBTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "DB.h"

class test_a_db : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(test_a_db);
	CPPUNIT_TEST(checks_for_empty_connection_parameters);
	CPPUNIT_TEST(can_be_connected_to_database);
	CPPUNIT_TEST_SUITE_END();

public:
	void checks_for_empty_connection_parameters();
	void can_be_connected_to_database();

	void setUp();
	void tearDown();

protected:
	DB::Connection *null;

private:
};

class test_a_db_with_a_connection : public test_a_db
{
	CPPUNIT_TEST_SUITE(test_a_db_with_a_connection);
	CPPUNIT_TEST(can_prepare_statements);
	CPPUNIT_TEST(can_perform_statements);
	CPPUNIT_TEST(maintains_correct_refcounts);
	CPPUNIT_TEST(can_create_tables);
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void can_prepare_statements();
	void can_perform_statements();
	void maintains_correct_refcounts();
	void can_create_tables();
protected:
	DB::Connection *connection;

private:
};

class test_a_db_with_a_connection_with_tables : public test_a_db_with_a_connection
{
	CPPUNIT_TEST_SUITE(test_a_db_with_a_connection_with_tables);
	CPPUNIT_TEST(can_insert_records);
	CPPUNIT_TEST(can_retrieve_records);
	CPPUNIT_TEST(can_cascade_delete_objects_and_attributes);
	CPPUNIT_TEST(can_update_text_attribute);
	CPPUNIT_TEST(can_update_text_attribute_bound_value);
	CPPUNIT_TEST(can_update_integer_attribute_bound_value);
	CPPUNIT_TEST(can_update_blob_attribute_bound_value);
	CPPUNIT_TEST(will_not_insert_non_existing_attribute_on_update);
	CPPUNIT_TEST(can_update_boolean_attribute_bound_value);
	CPPUNIT_TEST(can_update_real_attribute_bound_value);
	CPPUNIT_TEST(supports_transactions);
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void can_insert_records();
	void can_retrieve_records();
	void can_cascade_delete_objects_and_attributes();
	void can_update_text_attribute();
	void can_update_text_attribute_bound_value();
	void can_update_integer_attribute_bound_value();
	void can_update_blob_attribute_bound_value();
	void will_not_insert_non_existing_attribute_on_update();
	void can_update_boolean_attribute_bound_value();
	void can_update_real_attribute_bound_value();
	void supports_transactions();
protected:

private:
};

class test_a_db_with_a_connection_with_tables_with_a_second_connection_open : public test_a_db_with_a_connection_with_tables
{
	CPPUNIT_TEST_SUITE(test_a_db_with_a_connection_with_tables_with_a_second_connection_open);
	CPPUNIT_TEST(handles_nested_transactions);
	CPPUNIT_TEST(supports_transactions_with_other_connections_open);
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void handles_nested_transactions();
	void supports_transactions_with_other_connections_open();
protected:
	DB::Connection *connection2;

private:
};

#endif // !_SOFTHSM_V2_DBTESTS_H
