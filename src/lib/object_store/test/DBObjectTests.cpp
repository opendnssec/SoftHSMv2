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
 DBObjectTests.cpp

 Contains test cases to test the database token object implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DBObjectTests.h"
#include "DBObject.h"

#include <cstdio>

#ifndef HAVE_SQLITE3_H
#error expected sqlite3 to be available
#endif

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_dbobject);

void test_a_dbobject::setUp()
{
	CPPUNIT_ASSERT(!system("mkdir testdir"));
	connection = DB::Connection::Create("testdir","TestToken");
	CPPUNIT_ASSERT(connection != NULL);
	CPPUNIT_ASSERT(connection->connect("<1>"));
	connection->setBusyTimeout(10);

	DBObject testObject(connection);
	CPPUNIT_ASSERT(testObject.startTransaction(DBObject::ReadWrite));
	CPPUNIT_ASSERT(testObject.createTables());
	CPPUNIT_ASSERT(testObject.commitTransaction());

	connection2 = DB::Connection::Create("testdir","TestToken");
	CPPUNIT_ASSERT(connection2 != NULL);
	CPPUNIT_ASSERT(connection2->connect("<2>"));
	connection2->setBusyTimeout(10);
}

void test_a_dbobject::tearDown()
{
	CPPUNIT_ASSERT(connection != NULL);
	connection->close();
	delete connection;

	CPPUNIT_ASSERT(connection2 != NULL);
	connection2->close();
	delete connection2;

#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void test_a_dbobject::should_be_insertable()
{
	DBObject tokenObject(connection);
	CPPUNIT_ASSERT(!tokenObject.isValid());
	CPPUNIT_ASSERT(tokenObject.insert());
	CPPUNIT_ASSERT(tokenObject.isValid());
	CPPUNIT_ASSERT_EQUAL(tokenObject.objectId(), (long long)1);
}

void test_a_dbobject::should_be_selectable()
{
	should_be_insertable();

	DBObject tokenObject(connection);
	CPPUNIT_ASSERT(tokenObject.find(1));
	CPPUNIT_ASSERT(tokenObject.isValid());
}

CPPUNIT_TEST_SUITE_REGISTRATION(test_a_dbobject_with_an_object);

void test_a_dbobject_with_an_object::setUp()
{
	test_a_dbobject::setUp();
	DBObject tokenObject(connection);
	CPPUNIT_ASSERT(tokenObject.startTransaction(DBObject::ReadWrite));
	CPPUNIT_ASSERT(!tokenObject.isValid());
	CPPUNIT_ASSERT(tokenObject.insert());
	CPPUNIT_ASSERT(tokenObject.isValid());
	CPPUNIT_ASSERT_EQUAL(tokenObject.objectId(), (long long)1);
	CPPUNIT_ASSERT(tokenObject.commitTransaction());

}

void test_a_dbobject_with_an_object::tearDown()
{
	test_a_dbobject::tearDown();
}

void test_a_dbobject_with_an_object::should_store_boolean_attributes()
{
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		bool value1 = true;
		bool value2 = false;
		bool value3 = true;
		bool value4 = true;
		bool value5 = false;

		OSAttribute attr1(value1);
		OSAttribute attr2(value2);
		OSAttribute attr3(value3);
		OSAttribute attr4(value4);
		OSAttribute attr5(value5);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SENSITIVE, attr2));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_EXTRACTABLE, attr3));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_NEVER_EXTRACTABLE, attr4));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SIGN, attr5));
	}

	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_TOKEN));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SENSITIVE));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_EXTRACTABLE));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_NEVER_EXTRACTABLE));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SIGN));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SENSITIVE).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_EXTRACTABLE).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_NEVER_EXTRACTABLE).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).isBooleanAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue());
		CPPUNIT_ASSERT(!testObject.getAttribute(CKA_SENSITIVE).getBooleanValue());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_EXTRACTABLE).getBooleanValue());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_NEVER_EXTRACTABLE).getBooleanValue());
		CPPUNIT_ASSERT(!testObject.getAttribute(CKA_SIGN).getBooleanValue());

		bool value6 = true;
		OSAttribute attr6(value6);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_VERIFY, attr6));
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_VERIFY).isBooleanAttribute());
		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_VERIFY).getBooleanValue(), value6);
		CPPUNIT_ASSERT_EQUAL(testObject.getBooleanValue(CKA_VERIFY, false), value6);
	}
}


void test_a_dbobject_with_an_object::should_store_unsigned_long_attributes()
{
	// Add unsigned long attributes to the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		unsigned long value1 = 0x12345678;
		unsigned long value2 = 0x87654321;
		unsigned long value3 = 0x01010101;
		unsigned long value4 = 0x10101010;
		unsigned long value5 = 0xABCDEF;

		OSAttribute attr1(value1);
		OSAttribute attr2(value2);
		OSAttribute attr3(value3);
		OSAttribute attr4(value4);
		OSAttribute attr5(value5);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_MODULUS_BITS, attr1));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_AUTH_PIN_FLAGS, attr3));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SUB_PRIME_BITS, attr4));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_KEY_TYPE, attr5));
	}

	// Now read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_MODULUS_BITS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_PRIME_BITS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_AUTH_PIN_FLAGS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SUB_PRIME_BITS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_KEY_TYPE));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_MODULUS_BITS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_AUTH_PIN_FLAGS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUB_PRIME_BITS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_KEY_TYPE).isUnsignedLongAttribute());

		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_MODULUS_BITS).getUnsignedLongValue(), (unsigned long)0x12345678);
		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue(), (unsigned long)0x87654321);
		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_AUTH_PIN_FLAGS).getUnsignedLongValue(), (unsigned long)0x01010101);
		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_SUB_PRIME_BITS).getUnsignedLongValue(), (unsigned long)0x10101010);
		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_KEY_TYPE).getUnsignedLongValue(), (unsigned long)0xABCDEF);

		unsigned long value6 = 0x90909090;
		OSAttribute attr6(value6);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_CLASS, attr6));
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_CLASS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_CLASS).getUnsignedLongValue(), value6);
		CPPUNIT_ASSERT_EQUAL(testObject.getUnsignedLongValue(CKA_CLASS, 0x0), value6);
	}
}

void test_a_dbobject_with_an_object::should_store_binary_attributes()
{
	ByteString value1 = "010203040506070809";
	ByteString value2 = "ABABABABABABABABABABABABABABABABAB";
	unsigned long value3 = 0xBDED;
	ByteString value4 = "98A7E5D798A7E5D798A7E5D798A7E5D798A7E5D798A7E5D7";
	ByteString value5 = "ABCDABCDABCDABCDABCDABCDABCDABCD";

	// Create the test object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		OSAttribute attr1(value1);
		OSAttribute attr2(value2);
		OSAttribute attr3(value3);
		OSAttribute attr4(value4);
		OSAttribute attr5(value5);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_MODULUS, attr1));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_COEFFICIENT, attr2));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_PUBLIC_EXPONENT, attr4));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SUBJECT, attr5));
	}

	// Now read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_MODULUS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_COEFFICIENT));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_VALUE_BITS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_PUBLIC_EXPONENT));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SUBJECT));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_MODULUS).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_COEFFICIENT).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_PUBLIC_EXPONENT).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).isByteStringAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_MODULUS).getByteStringValue() == value1);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_COEFFICIENT).getByteStringValue() == value2);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_PUBLIC_EXPONENT).getByteStringValue() == value4);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).getByteStringValue() == value5);

		ByteString value6 = "909090908080808080807070707070FF";
		OSAttribute attr6(value6);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_ISSUER, attr6));
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ISSUER).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject.getByteStringValue(CKA_ISSUER) == value6);
	}
}

void test_a_dbobject_with_an_object::should_store_mechtypeset_attributes()
{

	// Create the test object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		std::set<CK_MECHANISM_TYPE> set;
		set.insert(CKM_SHA256);
		set.insert(CKM_SHA512);
		OSAttribute attr(set);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr));
	}

	// Now read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_ALLOWED_MECHANISMS));
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

		std::set<CK_MECHANISM_TYPE> retrieved =
				testObject.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue();

		CPPUNIT_ASSERT(retrieved.size() == 2);
		CPPUNIT_ASSERT(retrieved.find(CKM_SHA256) != retrieved.end());
		CPPUNIT_ASSERT(retrieved.find(CKM_SHA384) == retrieved.end());
		CPPUNIT_ASSERT(retrieved.find(CKM_SHA512) != retrieved.end());
	}
}

void test_a_dbobject_with_an_object::should_store_attrmap_attributes()
{
	bool value1 = true;
	unsigned long value2 = 0x87654321;
	ByteString value3 = "BDEBDBEDBBDBEBDEBE792759537328";
	std::set<CK_MECHANISM_TYPE> value4;
	value4.insert(CKM_SHA256);
	value4.insert(CKM_SHA512);

	// Create the test object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		OSAttribute attr1(value1);
		OSAttribute attr2(value2);
		OSAttribute attr3(value3);
		OSAttribute attr4(value4);

		std::map<CK_ATTRIBUTE_TYPE,OSAttribute> mattr;
		mattr.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (CKA_TOKEN, attr1));
		mattr.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (CKA_PRIME_BITS, attr2));
		mattr.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (CKA_VALUE, attr3));
		mattr.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (CKA_ALLOWED_MECHANISMS, attr4));
		OSAttribute attra(mattr);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_WRAP_TEMPLATE, attra));
	}

	// Now read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_WRAP_TEMPLATE));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_UNWRAP_TEMPLATE));

		std::map<CK_ATTRIBUTE_TYPE,OSAttribute> mattrb =
				testObject.getAttribute(CKA_WRAP_TEMPLATE).getAttributeMapValue();
		CPPUNIT_ASSERT(mattrb.size() == 4);
		CPPUNIT_ASSERT(mattrb.find(CKA_TOKEN) != mattrb.end());
		CPPUNIT_ASSERT(mattrb.at(CKA_TOKEN).isBooleanAttribute());
		CPPUNIT_ASSERT(mattrb.at(CKA_TOKEN).getBooleanValue() == true);
		CPPUNIT_ASSERT(mattrb.find(CKA_PRIME_BITS) != mattrb.end());
		CPPUNIT_ASSERT(mattrb.at(CKA_PRIME_BITS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(mattrb.at(CKA_PRIME_BITS).getUnsignedLongValue() == 0x87654321);
		CPPUNIT_ASSERT(mattrb.find(CKA_VALUE) != mattrb.end());
		CPPUNIT_ASSERT(mattrb.at(CKA_VALUE).isByteStringAttribute());
		CPPUNIT_ASSERT(mattrb.at(CKA_VALUE).getByteStringValue() == value3);
		CPPUNIT_ASSERT(mattrb.find(CKA_ALLOWED_MECHANISMS) != mattrb.end());
		CPPUNIT_ASSERT(mattrb.at(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());
		CPPUNIT_ASSERT(mattrb.at(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value4);
	}
}

void test_a_dbobject_with_an_object::should_store_mixed_attributes()
{
	bool value1 = true;
	unsigned long value2 = 0x87654321;
	unsigned long value3 = 0xBDEBDBED;
	std::set<CK_MECHANISM_TYPE> value4;
	value4.insert(CKM_SHA256);
	value4.insert(CKM_SHA512);

	// Create the test object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		OSAttribute attr1(value1);
		OSAttribute attr2(value2);
		OSAttribute attr3(value3);
		OSAttribute attr4(value4);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr4));
	}

	// Now read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_TOKEN));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_PRIME_BITS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_VALUE_BITS));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_ALLOWED_MECHANISMS));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue());
		CPPUNIT_ASSERT_EQUAL(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue(), value2);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value4);
	}
}

void test_a_dbobject_with_an_object::should_store_double_attributes()
{
	bool value1 = true;
	bool value1a = false;

	// Create the test object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		OSAttribute attr1(value1);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SIGN, attr1));
	}

	// Now read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SIGN));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).isBooleanAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).getBooleanValue());

		OSAttribute attr1(value1a);

		// Change the attributes
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SIGN, attr1));

		// Check the attributes
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).isBooleanAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).getBooleanValue() == value1a);
	}

	// Now re-read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SIGN));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).isBooleanAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).getBooleanValue() == value1a);
	}
}

void test_a_dbobject_with_an_object::can_refresh_attributes()
{
	bool value1 = true;
	bool value1a = false;
	ByteString value2 = "BDEBDBEDBBDBEBDEBE792759537328";
	ByteString value2a = "466487346943785684957634";
	ByteString value3 = "0102010201020102010201020102010201020102";
	std::set<CK_MECHANISM_TYPE> value4;
	value4.insert(CKM_SHA256);
	value4.insert(CKM_SHA512);
	std::set<CK_MECHANISM_TYPE> value4a;
	value4a.insert(CKM_SHA384);
	value4a.insert(CKM_SHA512);

	// Create the test object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		OSAttribute attr1(value1);
		OSAttribute attr2(value2);
		OSAttribute attr4(value4);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SIGN, attr1));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SUBJECT, attr2));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr4));
	}

	// Now read back the object
	{
		DBObject testObject(connection);
		CPPUNIT_ASSERT(testObject.find(1));
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SIGN));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_SUBJECT));
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_ALLOWED_MECHANISMS));
		CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).getBooleanValue());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).getByteStringValue() == value2);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value4);

		OSAttribute attr1(value1a);
		OSAttribute attr2(value2a);
		OSAttribute attr4(value4a);

		// Change the attributes
		CPPUNIT_ASSERT(testObject.isValid());

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SIGN, attr1));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_SUBJECT, attr2));
		CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr4));

		// Check the attributes
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).getBooleanValue() == value1a);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).getByteStringValue() == value2a);
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value4a);

		// Open the object a second time
		DBObject testObject2(connection);
		CPPUNIT_ASSERT(testObject2.find(1));
		CPPUNIT_ASSERT(testObject2.isValid());

		// Check the attributes on the second instance
		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_SIGN).isBooleanAttribute());
		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_SUBJECT).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_SIGN).getBooleanValue() == value1a);
		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_SUBJECT).getByteStringValue() == value2a);
		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value4a);

		// Add an attribute on the second object
		OSAttribute attr3(value3);

		CPPUNIT_ASSERT(testObject.setAttribute(CKA_ID, attr3));

		// Check the attribute
		CPPUNIT_ASSERT(testObject2.attributeExists(CKA_ID));
		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).getByteStringValue() == value3);

		// Now check that the first instance also knows about it
		CPPUNIT_ASSERT(testObject.attributeExists(CKA_ID));
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).isByteStringAttribute());
		CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).getByteStringValue() == value3);
	}
}

void test_a_dbobject_with_an_object::should_cleanup_statements_during_transactions()
{
	// Create an object for accessing object 1 on the first connection.
	DBObject testObject(connection);
	// check transaction start(ro)/abort sequence
	CPPUNIT_ASSERT(testObject.startTransaction(OSObject::ReadOnly));
	CPPUNIT_ASSERT(testObject.find(1));
	CPPUNIT_ASSERT(testObject.isValid());
	CPPUNIT_ASSERT(testObject.abortTransaction());
}

void test_a_dbobject_with_an_object::should_use_transactions()
{
	DBObject testObject(connection);
	CPPUNIT_ASSERT(testObject.find(1));
	CPPUNIT_ASSERT(testObject.isValid());

	bool value1 = true;
	unsigned long value2 = 0x87654321;
	unsigned long value3 = 0xBDEBDBED;
	ByteString value4 = "AAAAAAAAAAAAAAAFFFFFFFFFFFFFFF";
	std::set<CK_MECHANISM_TYPE> value5;
	value5.insert(CKM_SHA256);
	value5.insert(CKM_SHA512);

	OSAttribute attr1(value1);
	OSAttribute attr2(value2);
	OSAttribute attr3(value3);
	OSAttribute attr4(value4);
	OSAttribute attr5(value5);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ID, attr4));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr5));

	// Create secondary instance for the same object.
	// This needs to have a different connection to the database to simulate
	// another process accessing the data.
	DBObject testObject2(connection2);
	CPPUNIT_ASSERT(testObject2.find(1));
	CPPUNIT_ASSERT(testObject2.isValid());

	// Check that it has the same attributes
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	// Check that the attributes have the same values as set on testObject.
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_TOKEN).getBooleanValue() == value1);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).getByteStringValue() == value4);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value5);

	// New values
	bool value1a = false;
	unsigned long value2a = 0x12345678;
	unsigned long value3a = 0xABABABAB;
	ByteString value4a = "EDEDEDEDEDEDEDEDEDEDEDEDEDEDED";
	std::set<CK_MECHANISM_TYPE> value5a;
	value5a.insert(CKM_SHA384);
	value5a.insert(CKM_SHA512);

	OSAttribute attr1a(value1a);
	OSAttribute attr2a(value2a);
	OSAttribute attr3a(value3a);
	OSAttribute attr4a(value4a);
	OSAttribute attr5a(value5a);

	// Start transaction on object
	CPPUNIT_ASSERT(testObject.startTransaction(DBObject::ReadWrite));

	// Change the attributes
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1a));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2a));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3a));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ID, attr4a));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr5a));

	// Verify that the attributes were set
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == value1a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).getByteStringValue() == value4a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value5a);

	// Verify that they are unchanged on the other instance
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_TOKEN).getBooleanValue() == value1);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).getByteStringValue() == value4);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value5);

	// Commit the transaction
	CPPUNIT_ASSERT(testObject.commitTransaction());

	// Verify that non-modifiable attributes did not propagate but modifiable attributes
	// have now changed on the other instance
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	// NOTE: 3 attributes below cannot be modified after creation and therefore are not required to propagate.
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_TOKEN).getBooleanValue() != value1a);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() != value2a);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() != value3a);
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() != value5a);

	// CKA_ID attribute can be modified after creation and therefore should have propagated.
	CPPUNIT_ASSERT(testObject2.getAttribute(CKA_ID).getByteStringValue() == value4a);

	// Start transaction on object
	CPPUNIT_ASSERT(testObject.startTransaction(DBObject::ReadWrite));

	// Change the attributes
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ID, attr4));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr5));

	// Verify that the attributes were set
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == value1);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).getByteStringValue() == value4);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value5);

	// Create a fresh third instance for the same object to force the data to be retrieved from the database.
	DBObject testObject3(connection2);
	CPPUNIT_ASSERT(testObject3.find(1));
	CPPUNIT_ASSERT(testObject3.isValid());

	// Verify that they are unchanged on the other instance, while the transaction is still in progress.
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	// Verify that the attributes from the database are still hodling the same value as when the transaction started.
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_TOKEN).getBooleanValue() == value1a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ID).getByteStringValue() == value4a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value5a);

	// Abort the transaction
	CPPUNIT_ASSERT(testObject.abortTransaction());

	// Verify that after aborting the transaction the values in testObject have reverted back to their
	// original state.
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	// After aborting a transaction the testObject should be back to pre transaction state.
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == value1a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ID).getByteStringValue() == value4a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value5a);

	// Verify that testObject3 still has the original values.
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_VALUE_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ID).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ALLOWED_MECHANISMS).isMechanismTypeSetAttribute());

	// Verify that testObject3 still has the original values.
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_TOKEN).getBooleanValue() == value1a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_VALUE_BITS).getUnsignedLongValue() == value3a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ID).getByteStringValue() == value4a);
	CPPUNIT_ASSERT(testObject3.getAttribute(CKA_ALLOWED_MECHANISMS).getMechanismTypeSetValue() == value5a);
}

void test_a_dbobject_with_an_object::should_fail_to_delete()
{
	DBObject testObject(connection);
	CPPUNIT_ASSERT(testObject.find(1));
	CPPUNIT_ASSERT(testObject.isValid());
	// We don't attach the object to a token, and therefore should not be able to destroy it.
	CPPUNIT_ASSERT(!testObject.destroyObject());
}

