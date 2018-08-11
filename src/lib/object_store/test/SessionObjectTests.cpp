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
 SessionObjectTests.cpp

 Contains test cases to test the session object implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "SessionObjectTests.h"
#include "SessionObject.h"
#include "File.h"
#include "Directory.h"
#include "OSAttribute.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SessionObjectTests);

void SessionObjectTests::setUp()
{
}

void SessionObjectTests::tearDown()
{
}

void SessionObjectTests::testBoolAttr()
{
	SessionObject testObject(NULL, 1, 1);

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

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == true);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_SENSITIVE).getBooleanValue() == false);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_EXTRACTABLE).getBooleanValue() == true);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_NEVER_EXTRACTABLE).getBooleanValue() == true);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_SIGN).getBooleanValue() == false);

	bool value6 = true;
	OSAttribute attr6(value6);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VERIFY, attr6));
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VERIFY).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VERIFY).getBooleanValue() == value6);
	CPPUNIT_ASSERT(testObject.getBooleanValue(CKA_VERIFY, false) == value6);
}

void SessionObjectTests::testULongAttr()
{
	SessionObject testObject(NULL, 1, 1);

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

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_MODULUS_BITS).getUnsignedLongValue() == 0x12345678);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == 0x87654321);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_AUTH_PIN_FLAGS).getUnsignedLongValue() == 0x01010101);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUB_PRIME_BITS).getUnsignedLongValue() == 0x10101010);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_KEY_TYPE).getUnsignedLongValue() == 0xABCDEF);

	unsigned long value6 = 0x90909090;
	OSAttribute attr6(value6);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_CLASS, attr6));
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_CLASS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_CLASS).getUnsignedLongValue() == value6);
	CPPUNIT_ASSERT(testObject.getUnsignedLongValue(CKA_CLASS, 0x0) == value6);
}

void SessionObjectTests::testByteStrAttr()
{
	ByteString value1 = "010203040506070809";
	ByteString value2 = "ABABABABABABABABABABABABABABABABAB";
	ByteString value3 = "BDEBDBEDBBDBEBDEBE792759537328";
	ByteString value4 = "98A7E5D798A7E5D798A7E5D798A7E5D798A7E5D798A7E5D7";
	ByteString value5 = "ABCDABCDABCDABCDABCDABCDABCDABCD";

	SessionObject testObject(NULL, 1, 1);

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

	CPPUNIT_ASSERT(testObject.isValid());

	CPPUNIT_ASSERT(testObject.attributeExists(CKA_MODULUS));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_COEFFICIENT));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_VALUE_BITS));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_PUBLIC_EXPONENT));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_SUBJECT));
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_MODULUS).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_COEFFICIENT).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PUBLIC_EXPONENT).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).isByteStringAttribute());

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_MODULUS).getByteStringValue() == value1);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_COEFFICIENT).getByteStringValue() == value2);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getByteStringValue() == value3);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PUBLIC_EXPONENT).getByteStringValue() == value4);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_SUBJECT).getByteStringValue() == value5);

	ByteString value6 = "909090908080808080807070707070FF";
	OSAttribute attr6(value6);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ISSUER, attr6));
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_ISSUER).isByteStringAttribute());
	CPPUNIT_ASSERT(testObject.getByteStringValue(CKA_ISSUER) == value6);
}

void SessionObjectTests::testMechTypeSetAttr()
{
	SessionObject testObject(NULL, 1, 1);

	CPPUNIT_ASSERT(testObject.isValid());

	std::set<CK_MECHANISM_TYPE> set;
	set.insert(CKM_SHA256);
	set.insert(CKM_SHA512);

	OSAttribute attr(set);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_ALLOWED_MECHANISMS, attr));
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

void SessionObjectTests::testAttrMapAttr()
{
	SessionObject testObject(NULL, 1, 1);

	CPPUNIT_ASSERT(testObject.isValid());

	bool value1 = true;
	unsigned long value2 = 0x87654321;
	ByteString value3 = "BDEBDBEDBBDBEBDEBE792759537328";

	OSAttribute attr1(value1);
	OSAttribute attr2(value2);
	OSAttribute attr3(value3);

	std::map<CK_ATTRIBUTE_TYPE,OSAttribute> mattr;
	mattr.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (CKA_TOKEN, attr1));
	mattr.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (CKA_PRIME_BITS, attr2));
	mattr.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (CKA_VALUE_BITS, attr3));
	OSAttribute attra(mattr);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_WRAP_TEMPLATE, attra));

	CPPUNIT_ASSERT(testObject.isValid());

	CPPUNIT_ASSERT(testObject.attributeExists(CKA_WRAP_TEMPLATE));
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_UNWRAP_TEMPLATE));

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_WRAP_TEMPLATE).isAttributeMapAttribute());

	std::map<CK_ATTRIBUTE_TYPE,OSAttribute> mattrb =
			testObject.getAttribute(CKA_WRAP_TEMPLATE).getAttributeMapValue();
	CPPUNIT_ASSERT(mattrb.size() == 3);
	CPPUNIT_ASSERT(mattrb.find(CKA_TOKEN) != mattrb.end());
	CPPUNIT_ASSERT(mattrb.at(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(mattrb.at(CKA_TOKEN).getBooleanValue() == true);
	CPPUNIT_ASSERT(mattrb.find(CKA_PRIME_BITS) != mattrb.end());
	CPPUNIT_ASSERT(mattrb.at(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(mattrb.at(CKA_PRIME_BITS).getUnsignedLongValue() == 0x87654321);
	CPPUNIT_ASSERT(mattrb.find(CKA_VALUE_BITS) != mattrb.end());
	CPPUNIT_ASSERT(mattrb.at(CKA_VALUE_BITS).isByteStringAttribute());
	CPPUNIT_ASSERT(mattrb.at(CKA_VALUE_BITS).getByteStringValue() == value3);

}

void SessionObjectTests::testMixedAttr()
{
	ByteString value3 = "BDEBDBEDBBDBEBDEBE792759537328";

	SessionObject testObject(NULL, 1, 1);

	CPPUNIT_ASSERT(testObject.isValid());

	bool value1 = true;
	unsigned long value2 = 0x87654321;

	OSAttribute attr1(value1);
	OSAttribute attr2(value2);
	OSAttribute attr3(value3);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3));

	CPPUNIT_ASSERT(testObject.isValid());

	CPPUNIT_ASSERT(testObject.attributeExists(CKA_TOKEN));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_PRIME_BITS));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_VALUE_BITS));
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isByteStringAttribute());

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == true);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == 0x87654321);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getByteStringValue() == value3);
}

void SessionObjectTests::testDoubleAttr()
{
	ByteString value3 = "BDEBDBEDBBDBEBDEBE792759537328";
	ByteString value3a = "466487346943785684957634";

	SessionObject testObject(NULL, 1, 1);

	CPPUNIT_ASSERT(testObject.isValid());

	bool value1 = true;
	unsigned long value2 = 0x87654321;

	OSAttribute attr1(value1);
	OSAttribute attr2(value2);
	OSAttribute attr3(value3);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3));

	CPPUNIT_ASSERT(testObject.isValid());

	CPPUNIT_ASSERT(testObject.attributeExists(CKA_TOKEN));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_PRIME_BITS));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_VALUE_BITS));
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isByteStringAttribute());

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == true);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == 0x87654321);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getByteStringValue() == value3);

	bool value1a = false;
	unsigned long value2a = 0x76767676;

	OSAttribute attr1a(value1a);
	OSAttribute attr2a(value2a);
	OSAttribute attr3a(value3a);

	// Change the attributes
	CPPUNIT_ASSERT(testObject.isValid());

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1a));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2a));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3a));

	// Check the attributes
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isByteStringAttribute());

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == value1a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == value2a);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getByteStringValue() == value3a);

	CPPUNIT_ASSERT(testObject.isValid());
}

void SessionObjectTests::testCloseSession()
{
	ByteString value3 = "BDEBDBEDBBDBEBDEBE792759537328";

	SessionObject testObject(NULL, 1, 1);

	CPPUNIT_ASSERT(testObject.isValid());

	bool value1 = true;
	unsigned long value2 = 0x87654321;

	OSAttribute attr1(value1);
	OSAttribute attr2(value2);
	OSAttribute attr3(value3);

	CPPUNIT_ASSERT(testObject.setAttribute(CKA_TOKEN, attr1));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_PRIME_BITS, attr2));
	CPPUNIT_ASSERT(testObject.setAttribute(CKA_VALUE_BITS, attr3));

	CPPUNIT_ASSERT(testObject.isValid());

	CPPUNIT_ASSERT(testObject.attributeExists(CKA_TOKEN));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_PRIME_BITS));
	CPPUNIT_ASSERT(testObject.attributeExists(CKA_VALUE_BITS));
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_ID));

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).isBooleanAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).isUnsignedLongAttribute());
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).isByteStringAttribute());

	CPPUNIT_ASSERT(testObject.getAttribute(CKA_TOKEN).getBooleanValue() == true);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_PRIME_BITS).getUnsignedLongValue() == 0x87654321);
	CPPUNIT_ASSERT(testObject.getAttribute(CKA_VALUE_BITS).getByteStringValue() == value3);

	// Now close the session
	testObject.removeOnSessionClose(1);

	CPPUNIT_ASSERT(!testObject.isValid());
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_TOKEN));
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_PRIME_BITS));
	CPPUNIT_ASSERT(!testObject.attributeExists(CKA_VALUE_BITS));
}

void SessionObjectTests::testDestroyObjectFails()
{
	// Create test object instance
	SessionObject testObject(NULL, 1, 1);

	CPPUNIT_ASSERT(testObject.isValid());

	OSObject* testIF = (OSObject*) &testObject;

	CPPUNIT_ASSERT(!testIF->destroyObject());
}

