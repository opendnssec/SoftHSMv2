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
 DBTests.cpp

 Contains lowest level test cases for the database backend implementation.
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DBTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_db);

static int dummy_print(const char *, va_list )
{
	return 0;
}

void test_a_db::setUp()
{
	CPPUNIT_ASSERT(!system("mkdir testdir"));
	null = NULL;
}

void test_a_db::tearDown()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void test_a_db::checks_for_empty_connection_parameters()
{
	DB::LogErrorHandler eh = DB::setLogErrorHandler(dummy_print);

	DB::Connection *connection = DB::Connection::Create("","TestToken");
	CPPUNIT_ASSERT_EQUAL(connection, null);

	connection = DB::Connection::Create("testdir","");
	CPPUNIT_ASSERT_EQUAL(connection, null);

	connection = DB::Connection::Create("","");
	CPPUNIT_ASSERT_EQUAL(connection, null);

	DB::setLogErrorHandler(eh);
}

void test_a_db::can_be_connected_to_database()
{

	DB::Connection *connection = DB::Connection::Create("testdir","TestToken");
	CPPUNIT_ASSERT(connection != null);
	bool isConnected = connection->connect();
	delete connection;
	CPPUNIT_ASSERT(isConnected);
#ifndef _WIN32
	CPPUNIT_ASSERT_EQUAL(system("test -f ./testdir/TestToken"), 0);
#else
	CPPUNIT_ASSERT(GetFileAttributes("testdir\\TestToken") != INVALID_FILE_ATTRIBUTES);
#endif
}

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_db_with_a_connection);

void test_a_db_with_a_connection::setUp()
{
	test_a_db::setUp();
	connection = DB::Connection::Create("testdir","TestToken");
	CPPUNIT_ASSERT(connection != null);
	CPPUNIT_ASSERT(connection->connect());
}

void test_a_db_with_a_connection::tearDown()
{
	CPPUNIT_ASSERT(connection != null);
	connection->close();
	delete connection;
	test_a_db::tearDown();
}

void test_a_db_with_a_connection::can_prepare_statements()
{
	DB::Statement statement = connection->prepare("PRAGMA database_list;");
	CPPUNIT_ASSERT(statement.isValid());
}

void test_a_db_with_a_connection::can_perform_statements()
{
	DB::Statement statement = connection->prepare("PRAGMA database_list;");
	CPPUNIT_ASSERT(statement.isValid());
	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());
	// only expect a single row in the result, so nextRow should now fail
	CPPUNIT_ASSERT(!result.nextRow());
}

void test_a_db_with_a_connection::maintains_correct_refcounts()
{
	DB::Statement statement = connection->prepare("PRAGMA database_list;");
	CPPUNIT_ASSERT_EQUAL(statement.refcount(), 1);
	{
		DB::Statement statement1 = statement;
		DB::Statement statement2 = statement;
		CPPUNIT_ASSERT_EQUAL(statement.refcount(), 3);
		CPPUNIT_ASSERT(statement1.isValid());
		CPPUNIT_ASSERT(statement2.isValid());
	}
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT_EQUAL(statement.refcount(), 1);

	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	// Statement is referenced by the result because it provides the query record cursor state.
	CPPUNIT_ASSERT_EQUAL(statement.refcount(), 2);

	result = DB::Result();
	CPPUNIT_ASSERT_EQUAL(statement.refcount(), 1);
}
void test_a_db_with_a_connection::can_create_tables()
{
	CPPUNIT_ASSERT(!connection->tableExists("object"));
	DB::Statement cr_object = connection->prepare("create table object (id integer primary key autoincrement);");
	CPPUNIT_ASSERT(connection->execute(cr_object));
	CPPUNIT_ASSERT(connection->tableExists("object"));
}

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_db_with_a_connection_with_tables);

void test_a_db_with_a_connection_with_tables::setUp()
{
	test_a_db_with_a_connection::setUp();
	can_create_tables();

	// attribute_text
	CPPUNIT_ASSERT(!connection->tableExists("attribute_text"));
	DB::Statement cr_attr_text = connection->prepare(
		"create table attribute_text ("
		"value text,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	CPPUNIT_ASSERT(connection->execute(cr_attr_text));
	CPPUNIT_ASSERT(connection->tableExists("attribute_text"));

	// attribute_integer
	CPPUNIT_ASSERT(!connection->tableExists("attribute_integer"));
	DB::Statement cr_attr_integer = connection->prepare(
		"create table attribute_integer ("
		"value integer,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	CPPUNIT_ASSERT(connection->execute(cr_attr_integer));
	CPPUNIT_ASSERT(connection->tableExists("attribute_integer"));

	// attribute_blob
	CPPUNIT_ASSERT(!connection->tableExists("attribute_blob"));
	DB::Statement cr_attr_blob = connection->prepare(
		"create table attribute_blob ("
		"value blob,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	CPPUNIT_ASSERT(connection->execute(cr_attr_blob));
	CPPUNIT_ASSERT(connection->tableExists("attribute_blob"));

	// attribute_boolean
	CPPUNIT_ASSERT(!connection->tableExists("attribute_boolean"));
	DB::Statement cr_attr_boolean = connection->prepare(
		"create table attribute_boolean ("
		"value boolean,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	CPPUNIT_ASSERT(connection->execute(cr_attr_boolean));
	CPPUNIT_ASSERT(connection->tableExists("attribute_boolean"));

	// attribute_datetime
	CPPUNIT_ASSERT(!connection->tableExists("attribute_datetime"));
	DB::Statement cr_attr_datetime = connection->prepare(
		"create table attribute_datetime ("
		"value datetime,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	CPPUNIT_ASSERT(connection->execute(cr_attr_datetime));
	CPPUNIT_ASSERT(connection->tableExists("attribute_datetime"));

	// attribute_real
	CPPUNIT_ASSERT(!connection->tableExists("attribute_real"));
	DB::Statement cr_attr_real = connection->prepare(
		"create table attribute_real ("
		"value real,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	CPPUNIT_ASSERT(connection->execute(cr_attr_real));
	CPPUNIT_ASSERT(connection->tableExists("attribute_real"));
}

void test_a_db_with_a_connection_with_tables::tearDown()
{
	test_a_db_with_a_connection::tearDown();
}

void test_a_db_with_a_connection_with_tables::can_insert_records()
{
	DB::Statement statement = connection->prepare("insert into object default values");
	CPPUNIT_ASSERT(connection->execute(statement));
	long long object_id = connection->lastInsertRowId();
	CPPUNIT_ASSERT(object_id != 0);

	statement = connection->prepare(
				"insert into attribute_text (value,type,object_id) values ('%s',%d,%lld)",
				"testing testing testing",
				1234,
				object_id);
	CPPUNIT_ASSERT(connection->execute(statement));
}

void test_a_db_with_a_connection_with_tables::can_retrieve_records()
{
	can_insert_records();

	DB::Statement statement = connection->prepare(
				"select value from attribute_text as t where t.type=%d",
				1234);
	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT_EQUAL(std::string(result.getString(1)), std::string("testing testing testing"));
}

void test_a_db_with_a_connection_with_tables::can_cascade_delete_objects_and_attributes()
{
	can_insert_records();

	DB::Statement statement = connection->prepare("select id from object");
	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	long long object_id = result.getLongLong(1);

	statement = connection->prepare("delete from object where id=%lld",object_id);
	CPPUNIT_ASSERT(connection->execute(statement));

	statement = connection->prepare("select * from attribute_text where object_id=%lld",object_id);
	result = connection->perform(statement);

	// Check cascade delete was successful.
	CPPUNIT_ASSERT(!result.isValid());
}


void test_a_db_with_a_connection_with_tables::can_update_text_attribute()
{
	can_insert_records();

	// query all objects
	DB::Statement statement = connection->prepare("select id from object");
	CPPUNIT_ASSERT(statement.isValid());
	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	long long object_id = result.getLongLong(1); // field indices start at 1

	statement = connection->prepare(
				"update attribute_text set value='test test test' where type=%d and object_id=%lld",
				1234,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));
}

void test_a_db_with_a_connection_with_tables::can_update_text_attribute_bound_value()
{
	can_insert_records();

	// query all objects
	DB::Statement statement = connection->prepare("select id from object");
	CPPUNIT_ASSERT(statement.isValid());
	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	long long object_id = result.getLongLong(1); // field indices start at 1

	statement = connection->prepare(
				"update attribute_text set value=? where type=%d and object_id=%lld",
				1234,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());

	std::string msg("testing quote ' and accents é.");

	CPPUNIT_ASSERT(DB::Bindings(statement).bindText(1,msg.c_str(),msg.size(),NULL));
	CPPUNIT_ASSERT(connection->execute(statement));

	statement = connection->prepare(
				"select value from attribute_text as t where t.type=%d and t.object_id=%lld",
				1234,
				object_id);
	result = connection->perform(statement);
	CPPUNIT_ASSERT_EQUAL(std::string(result.getString(1)), msg);
}

void test_a_db_with_a_connection_with_tables::can_update_integer_attribute_bound_value()
{
	// insert new object
	DB::Statement statement = connection->prepare(
				"insert into object default values");
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));
	long long object_id = connection->lastInsertRowId();
	CPPUNIT_ASSERT(object_id != 0);

	// insert integer attribute
	statement = connection->prepare(
				"insert into attribute_integer (value,type,object_id) values (%d,%d,%lld)",
				1111,
				1235,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));

	// prepare update integer attribute statement
	statement = connection->prepare(
				"update attribute_integer set value=? where type=%d and object_id=%lld",
				1235,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());

	// bind long long value to the parameter an update the record
	CPPUNIT_ASSERT(DB::Bindings(statement).bindInt64(1,2222));
	CPPUNIT_ASSERT(connection->execute(statement));

	// Retrieve the value from the record
	DB::Statement retrieveStmt = connection->prepare(
				"select value from attribute_integer as t where t.type=%d and t.object_id=%lld",
				1235,
				object_id);
	CPPUNIT_ASSERT(retrieveStmt.isValid());
	DB::Result result = connection->perform(retrieveStmt);
	CPPUNIT_ASSERT_EQUAL(result.getLongLong(1), (long long)2222);

	// verify that binding to a parameter before resetting the statement will fail.
	DB::LogErrorHandler eh = DB::setLogErrorHandler(dummy_print);
	DB::Bindings bindings(statement);
	CPPUNIT_ASSERT(!bindings.bindInt(1,3333));
	DB::setLogErrorHandler(eh);

	// reset statement and bind another value to the statement
	CPPUNIT_ASSERT(bindings.reset());
	CPPUNIT_ASSERT(bindings.bindInt(1,3333));

	// perform the update statement again with the newly bound value
	CPPUNIT_ASSERT(connection->execute(statement));

	// reset the retrieve statement and perform it again to get the latest value of the integer attribute
	CPPUNIT_ASSERT(retrieveStmt.reset());
	result = connection->perform(retrieveStmt);
	CPPUNIT_ASSERT(result.isValid());
	CPPUNIT_ASSERT_EQUAL(result.getLongLong(1), (long long)3333);
}

void test_a_db_with_a_connection_with_tables::can_update_blob_attribute_bound_value()
{
	// insert new object
	DB::Statement statement = connection->prepare(
				"insert into object default values");
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));
	long long object_id = connection->lastInsertRowId();
	CPPUNIT_ASSERT(object_id != 0);

	// insert blob attribute
	statement = connection->prepare(
				"insert into attribute_blob (value,type,object_id) values (X'012345',%d,%lld)",
				1236,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));

	// prepare update blob attribute statement
	statement = connection->prepare(
				"update attribute_blob set value=? where type=%d and object_id=%lld",
				1236,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());

	// bind blob (with embedded zero!) to the parameter
	const char data[] = {10,11,0,12,13,14,15,16};
	std::string msg(data,sizeof(data));
	CPPUNIT_ASSERT(DB::Bindings(statement).bindBlob(1,msg.data(),msg.size(),NULL));

	// update the blob value of the attribute
	CPPUNIT_ASSERT(connection->execute(statement));

	// retrieve the blob value from the attribute
	statement = connection->prepare(
				"select value from attribute_blob as t where t.type=%d and t.object_id=%lld",
				1236,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	// check that the retrieved blob value matches the original data.
	CPPUNIT_ASSERT_EQUAL(result.getFieldLength(1), sizeof(data));
	std::string msgstored((const char *)result.getBinary(1),result.getFieldLength(1));
	CPPUNIT_ASSERT_EQUAL(msg, msgstored);
}


void test_a_db_with_a_connection_with_tables::will_not_insert_non_existing_attribute_on_update()
{
	DB::Statement statement;
	DB::Result result;

	// Insert new object
	statement = connection->prepare(
				"insert into object default values");
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));
	long long object_id = connection->lastInsertRowId();
	CPPUNIT_ASSERT(object_id != 0);

	// Updating an attribute before it is created will succeed, but will not insert an attribute.
	statement = connection->prepare(
				"update attribute_boolean set value=1 where type=%d and object_id=%lld",
				1237,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));

	// Retrieve the boolean value from the attribute should fail
	statement = connection->prepare(
				"select value from attribute_boolean as t where t.type=%d and t.object_id=%lld",
				1237,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	result = connection->perform(statement);
	CPPUNIT_ASSERT(!result.isValid());
}


void test_a_db_with_a_connection_with_tables::can_update_boolean_attribute_bound_value()
{
	//SQLite doesn't have a boolean data type, use 0 (false) and 1 (true)

	DB::Statement statement;
	DB::Result result;

	// Insert new object
	statement = connection->prepare(
				"insert into object default values");
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));
	long long object_id = connection->lastInsertRowId();
	CPPUNIT_ASSERT(object_id != 0);

	// insert boolean attribute
	statement = connection->prepare(
				"insert into attribute_boolean (value,type,object_id) values (1,%d,%lld)",
				1237,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));

	// prepare update boolean attribute statement
	statement = connection->prepare(
				"update attribute_boolean set value=? where type=%d and object_id=%lld",
				1237,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());

	// Bind 0 (false) to the first parameter
	CPPUNIT_ASSERT(DB::Bindings(statement).bindInt(1,0));

	// Execute the statement to update the attribute value.
	CPPUNIT_ASSERT(connection->execute(statement));

	// Retrieve the boolean value from the attribute
	statement = connection->prepare(
				"select value from attribute_boolean as t where t.type=%d and t.object_id=%lld",
				1237,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	// check that the retrieved value matches the original value
	CPPUNIT_ASSERT_EQUAL(result.getInt(1), 0);
}


void test_a_db_with_a_connection_with_tables::can_update_real_attribute_bound_value()
{
	// insert new object
	DB::Statement statement = connection->prepare(
				"insert into object default values");
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));
	long long object_id = connection->lastInsertRowId();
	CPPUNIT_ASSERT(object_id != 0);

	// insert real value
	statement = connection->prepare(
				"insert into attribute_real (value,type,object_id) values(%f,%d,%lld)",
				1.238,
				1238,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	CPPUNIT_ASSERT(connection->execute(statement));

	// prepare update real attribute statement
	statement = connection->prepare(
				"update attribute_real set value=? where type=%d and object_id=%lld",
				1238,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());

	// Bind 3333.3333 to the first parameter
	CPPUNIT_ASSERT(DB::Bindings(statement).bindDouble(1,3333.3333));

	// Execute the statement to update the attribute value
	CPPUNIT_ASSERT(connection->execute(statement));

	// Retrieve the double value from the attribute
	statement = connection->prepare(
				"select value from attribute_real as t where t.type=%d and t.object_id=%lld",
				1238,
				object_id);
	CPPUNIT_ASSERT(statement.isValid());
	DB::Result result = connection->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	// check that the retrieved value matches the original value.
	CPPUNIT_ASSERT_DOUBLES_EQUAL(result.getDouble(1), 3333.3333, 0.00001);
}

void test_a_db_with_a_connection_with_tables::supports_transactions()
{
	DB::LogErrorHandler eh = DB::setLogErrorHandler(dummy_print);
	CPPUNIT_ASSERT(!connection->rollbackTransaction());
	DB::setLogErrorHandler(eh);

	CPPUNIT_ASSERT(connection->beginTransactionRW());
	CPPUNIT_ASSERT(connection->rollbackTransaction());

	eh = DB::setLogErrorHandler(dummy_print);
	CPPUNIT_ASSERT(!connection->commitTransaction());
	DB::setLogErrorHandler(eh);

	CPPUNIT_ASSERT(connection->beginTransactionRW());
	can_update_real_attribute_bound_value();
	CPPUNIT_ASSERT(connection->commitTransaction());
}

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_db_with_a_connection_with_tables_with_a_second_connection_open);

void test_a_db_with_a_connection_with_tables_with_a_second_connection_open::setUp()
{
	test_a_db_with_a_connection_with_tables::setUp();
	connection2 = DB::Connection::Create("testdir","TestToken");
	CPPUNIT_ASSERT(connection2 != null);
	CPPUNIT_ASSERT(connection2->connect());
	connection2->setBusyTimeout(10);
}

void test_a_db_with_a_connection_with_tables_with_a_second_connection_open::tearDown()
{
	CPPUNIT_ASSERT(connection2 != null);
	connection2->close();
	delete connection2;
	test_a_db_with_a_connection_with_tables::tearDown();
}

void test_a_db_with_a_connection_with_tables_with_a_second_connection_open::handles_nested_transactions()
{
	DB::LogErrorHandler eh = DB::setLogErrorHandler(dummy_print);

	DB::Connection *connection1 = connection;

	CPPUNIT_ASSERT(connection1->beginTransactionRW());

	CPPUNIT_ASSERT(connection2->beginTransactionRO());
	CPPUNIT_ASSERT(connection2->rollbackTransaction());
	CPPUNIT_ASSERT(!connection2->beginTransactionRW());

	CPPUNIT_ASSERT(connection1->commitTransaction());

	DB::setLogErrorHandler(eh);
}


void test_a_db_with_a_connection_with_tables_with_a_second_connection_open::supports_transactions_with_other_connections_open()
{
	CPPUNIT_ASSERT(connection2->beginTransactionRO());

	supports_transactions();

	// Retrieve the double value from the attribute
	DB::Statement statement = connection2->prepare(
				"select value from attribute_real as t where t.type=%d and t.object_id=%lld",
				1238,
				connection->lastInsertRowId());
	CPPUNIT_ASSERT(statement.isValid());
	DB::Result result = connection2->perform(statement);
	CPPUNIT_ASSERT(result.isValid());

	// check that the retrieved value matches the original value.
	CPPUNIT_ASSERT_DOUBLES_EQUAL(result.getDouble(1), 3333.3333, 0.00001);

	CPPUNIT_ASSERT(connection2->commitTransaction());
}
