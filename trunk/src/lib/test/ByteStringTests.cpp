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
 ByteStringTests.cpp

 Contains test cases to test the ByteString class
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include "ByteStringTests.h"
#include "ByteString.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ByteStringTests);

void ByteStringTests::setUp()
{
}

void ByteStringTests::tearDown()
{
}

void ByteStringTests::testIntegrity()
{
	unsigned char testData[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

	ByteString b(testData, sizeof(testData));

	// Test if the right data is returned
	CPPUNIT_ASSERT(memcmp(testData, b.byte_str(), sizeof(testData)) == 0);

	// Test size
	CPPUNIT_ASSERT(b.size() == sizeof(testData));

	// Test the copy constructor
	ByteString b2(b);

	// Test using comparison operator
	CPPUNIT_ASSERT(b == b2);

	// Test using memcmp
	CPPUNIT_ASSERT(memcmp(b.byte_str(), b2.byte_str(), b.size()) == 0);

	// Modify the copied version and test again
	b2[1] = 0x20;

	// Test using comparison operator
	CPPUNIT_ASSERT(b != b2);

	// Test using memcmp directly
	CPPUNIT_ASSERT(memcmp(b.byte_str(), b2.byte_str(), b.size()) != 0);

	// Verify that b was not affected
	CPPUNIT_ASSERT(memcmp(b.byte_str(), testData, sizeof(testData)) == 0);

	// Modify the source data and check if the array operator has functioned correctly
	testData[1] = 0x20;

	// Test if the right data is in b2
	CPPUNIT_ASSERT(memcmp(b2.byte_str(), testData, sizeof(testData)) == 0);
}

void ByteStringTests::testAppend()
{
	unsigned char testData[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

	ByteString b;
	ByteString b1(testData, sizeof(testData));

	// Test that b is empty and b1 is not
	CPPUNIT_ASSERT((b.size() == 0) && (b1.size() == sizeof(testData)));

	// Append 1 byte to b
	b += 0x01;

	// Check the contents of b
	CPPUNIT_ASSERT(b.size() == 1);
	CPPUNIT_ASSERT(b[0] == 0x01);

	// Append another byte to b
	b += 0x02;

	// Check the contents of b
	CPPUNIT_ASSERT(b.size() == 2);
	CPPUNIT_ASSERT((b[0] == 0x01) && (b[1] == 0x02));

	// Append b1 to b
	b += b1;

	// Check the contents of b
	CPPUNIT_ASSERT(b.size() == 2 + sizeof(testData));
	CPPUNIT_ASSERT((b[0] == 0x01) && (b[1] == 0x02));
	CPPUNIT_ASSERT(memcmp(&b[2], testData, sizeof(testData)) == 0);

	// Append b to b
	b += b;

	// Check the contents of b
	CPPUNIT_ASSERT(b.size() == 2 * (2 + sizeof(testData)));
	CPPUNIT_ASSERT((b[0] == 0x01) && (b[1] == 0x02) && 
	               (b[(2 + sizeof(testData)) + 0] == 0x01) &&
		       (b[(2 + sizeof(testData)) + 1] == 0x02));
	CPPUNIT_ASSERT((memcmp(&b[2], testData, sizeof(testData)) == 0) &&
	               (memcmp(&b[2 + 2 + sizeof(testData)], testData, sizeof(testData)) == 0));
}

void ByteStringTests::testSubstr()
{
	unsigned char testData[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

	ByteString b;
	ByteString b1(testData, sizeof(testData));

	// Take a substring
	b = b1.substr(8, 4);
	
	// Check b
	CPPUNIT_ASSERT(b.size() == 4);
	CPPUNIT_ASSERT(memcmp(b.byte_str(), &testData[8], 4) == 0);

	// Take another substring
	b = b1.substr(8);

	// Check b
	CPPUNIT_ASSERT(b.size() == 8);
	CPPUNIT_ASSERT(memcmp(b.byte_str(), &testData[8], 8) == 0);

	// Two substrings added should yield the original string
	b = b1.substr(0, 8) + b1.substr(8);

	// Check b
	CPPUNIT_ASSERT(b.size() == sizeof(testData));
	CPPUNIT_ASSERT(memcmp(b.byte_str(), testData, sizeof(testData)) == 0);
}

void ByteStringTests::testFromHexStr()
{
	unsigned char testData[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

	ByteString b("0102030405060708090a0b0c0d0e0f10");
	ByteString b1("0102030405060708090A0B0C0D0E0F10");

	CPPUNIT_ASSERT(memcmp(b.byte_str(), testData, sizeof(testData)) == 0);
	CPPUNIT_ASSERT(memcmp(b1.byte_str(), testData, sizeof(testData)) == 0);
}

void ByteStringTests::testXOR()
{
	unsigned char left[]	= { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char right[]	= { 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };
	unsigned char xorred[]	= { 0x81, 0x72, 0x63, 0x54, 0x45, 0x36, 0x27, 0x18 };

	ByteString l(left, 8);
	ByteString r(right, 8);
	ByteString x(xorred, 8);
	ByteString xed;

	xed = l ^ r;

	CPPUNIT_ASSERT(xed == x);
}

void ByteStringTests::testToHexStr()
{
	ByteString b("0102030405060708090A0B0C0D0E0F");
	ByteString b1("DEADBEEF");
	ByteString b2("deadC0FFEE");

	std::string s = b.hex_str();
	std::string s1 = b1.hex_str();
	std::string s2 = b2.hex_str();

	CPPUNIT_ASSERT(s.compare("0102030405060708090A0B0C0D0E0F") == 0);
	CPPUNIT_ASSERT(s1.compare("DEADBEEF") == 0);
	CPPUNIT_ASSERT(s2.compare("DEADC0FFEE") == 0);
}

