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
 FileTests.cpp

 Contains test cases to test the file implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "FileTests.h"
#include "File.h"
#include "Directory.h"
#include "CryptoFactory.h"
#include "RNG.h"

CPPUNIT_TEST_SUITE_REGISTRATION(FileTests);

// FIXME: all pathnames in this file are *NIX/BSD specific

void FileTests::setUp()
{
#ifndef _WIN32
	int rv = system("rm -rf testdir");
#else
	int rv = system("rmdir /s /q testdir 2> nul");
#endif
	(void) rv;

	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void FileTests::tearDown()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void FileTests::testExistNotExist()
{
	// Test pre-condition
	CPPUNIT_ASSERT(!exists("nonExistentFile"));

	// Attempt to open a file known not to exist
#ifndef _WIN32
	File doesntExist("testdir/nonExistentFile");
#else
	File doesntExist("testdir\\nonExistentFile");
#endif

	CPPUNIT_ASSERT(!doesntExist.isValid());

	// Attempt to open a file known to exist
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("echo someStuff > testdir/existingFile"));
#else
	CPPUNIT_ASSERT(!system("echo someStuff > testdir\\existingFile"));
#endif
	CPPUNIT_ASSERT(exists("existingFile"));

#ifndef _WIN32
	File exists("testdir/existingFile");
#else
	File exists("testdir\\existingFile");
#endif

	CPPUNIT_ASSERT(exists.isValid());
}

void FileTests::testCreateNotCreate()
{
	// Test pre-condition
	CPPUNIT_ASSERT(!exists("nonExistentFile"));
	CPPUNIT_ASSERT(!exists("nonExistentFile2"));

	// Attempt to open a file known not to exist
#ifndef _WIN32
	File doesntExist("testdir/nonExistentFile", true, true, false);
#else
	File doesntExist("testdir\\nonExistentFile", true, true, false);
#endif

	CPPUNIT_ASSERT(!doesntExist.isValid());
	CPPUNIT_ASSERT(!exists("nonExistentFile"));

	// Attempt to open a file known not to exist in create mode
#ifndef _WIN32
	File willBeCreated("testdir/nonExistentFile2", true, true, true);
#else
	File willBeCreated("testdir\\nonExistentFile2", true, true, true);
#endif

	CPPUNIT_ASSERT(willBeCreated.isValid());
	CPPUNIT_ASSERT(exists("nonExistentFile2"));
}

void FileTests::testLockUnlock()
{
	// Create pre-condition
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("echo someStuff > testdir/existingFile"));
#else
	CPPUNIT_ASSERT(!system("echo someStuff > testdir\\existingFile"));
#endif
	CPPUNIT_ASSERT(exists("existingFile"));

#ifndef _WIN32
	File file1("testdir/existingFile");
	File file2("testdir/existingFile");
#else
	File file1("testdir\\existingFile");
	File file2("testdir\\existingFile");
#endif

	CPPUNIT_ASSERT(file1.lock(false));
	CPPUNIT_ASSERT(!file1.lock(false));
	CPPUNIT_ASSERT(file2.lock(false));
	CPPUNIT_ASSERT(file2.unlock());
	CPPUNIT_ASSERT(file1.unlock());
	CPPUNIT_ASSERT(file1.lock());
	CPPUNIT_ASSERT(file2.lock());
	CPPUNIT_ASSERT(file2.unlock());
	CPPUNIT_ASSERT(file1.unlock());
}

void FileTests::testWriteRead()
{
	// Generate some test data
	RNG* rng = CryptoFactory::i()->getRNG();

	ByteString testData1;

	CPPUNIT_ASSERT(rng->generateRandom(testData1, 187));

	// More test data
	std::string testString = "This is a test of the File class";
	std::set<CK_MECHANISM_TYPE> testSet;
	testSet.insert(CKM_RSA_PKCS);
	testSet.insert(CKM_SHA256_RSA_PKCS);

	// Create a file for writing
	{
#ifndef _WIN32
		File newFile("testdir/newFile", false, true);
#else
		File newFile("testdir\\newFile", false, true);
#endif

		CPPUNIT_ASSERT(newFile.isValid());

		// Write two booleans into the file
		CPPUNIT_ASSERT(newFile.writeBool(true));
		CPPUNIT_ASSERT(newFile.writeBool(false));

		// Write an ulong into the file
		CPPUNIT_ASSERT(newFile.writeULong(0x12345678));

		// Write a ByteString into the file
		CPPUNIT_ASSERT(newFile.writeByteString(testData1));

		// Write a string into the file
		CPPUNIT_ASSERT(newFile.writeString(testString));

		// Write a set into the file
		CPPUNIT_ASSERT(newFile.writeMechanismTypeSet(testSet));
	}

	CPPUNIT_ASSERT(exists("newFile"));

	// Read the created file back
	{
#ifndef _WIN32
		File newFile("testdir/newFile");
#else
		File newFile("testdir\\newFile");
#endif

		CPPUNIT_ASSERT(newFile.isValid());

		// Read back the two booleans
		bool b1, b2;

		CPPUNIT_ASSERT(newFile.readBool(b1) && newFile.readBool(b2));
		CPPUNIT_ASSERT(b1 && !b2);

		// Read back the ulong
		unsigned long ulongValue;

		CPPUNIT_ASSERT(newFile.readULong(ulongValue));
		CPPUNIT_ASSERT(ulongValue == 0x12345678);

		// Read back the byte string
		ByteString bsValue;

		CPPUNIT_ASSERT(newFile.readByteString(bsValue));
		CPPUNIT_ASSERT(bsValue == testData1);

		// Read back the string value
		std::string stringVal;

		CPPUNIT_ASSERT(newFile.readString(stringVal));
		CPPUNIT_ASSERT(!testString.compare(stringVal));

		// Read back the set value
		std::set<CK_MECHANISM_TYPE> setVal;

		CPPUNIT_ASSERT(newFile.readMechanismTypeSet(setVal));
		CPPUNIT_ASSERT(setVal == testSet);

		// Check for EOF
		CPPUNIT_ASSERT(!newFile.readBool(b1));
		CPPUNIT_ASSERT(newFile.isEOF());
	}
}

void FileTests::testSeek()
{
	ByteString t1 = "112233445566778899";       // 9 long
	ByteString t2 = "AABBCCDDEEFFAABBCCDDEEFF"; // 12 long

	{
		// Create the test file
#ifndef _WIN32
		File testFile("testdir/testFile", false, true, true);
#else
		File testFile("testdir\\testFile", false, true, true);
#endif

		CPPUNIT_ASSERT(testFile.isValid());

		// Write the test data to the test file
		CPPUNIT_ASSERT(testFile.writeByteString(t1) && testFile.writeByteString(t2));
	}

	// Open the test file for reading
#ifndef _WIN32
	File testFile("testdir/testFile");
#else
	File testFile("testdir\\testFile");
#endif

	CPPUNIT_ASSERT(testFile.isValid());

	// First, read back the test data
	ByteString tr1, tr2;

	CPPUNIT_ASSERT(testFile.readByteString(tr1) && testFile.readByteString(tr2));
	CPPUNIT_ASSERT(tr1 == t1);
	CPPUNIT_ASSERT(tr2 == t2);

	// Seek to the length field of the second byte string
	CPPUNIT_ASSERT(testFile.seek(8+9));

	// Read back the size as an ulong value
	unsigned long value;
	unsigned long expectedValue = (unsigned long)0x1122334455667788ULL;

	CPPUNIT_ASSERT(testFile.readULong(value));
	CPPUNIT_ASSERT(value == 12);

	// Seek to the start of the first byte string's data
	CPPUNIT_ASSERT(testFile.seek(8));

	// Read back the ulong value stored there
	CPPUNIT_ASSERT(testFile.readULong(value));

	CPPUNIT_ASSERT(value == expectedValue);

	// Seek to the start of second byte string
	CPPUNIT_ASSERT(testFile.seek(8+9));

	// Read it
	ByteString trr2;

	CPPUNIT_ASSERT(testFile.readByteString(trr2));
	CPPUNIT_ASSERT(trr2 == t2);

	// Rewind the file
	CPPUNIT_ASSERT(testFile.rewind());

	// Read back both byte strings
	ByteString trrr1, trrr2;

	CPPUNIT_ASSERT(testFile.readByteString(trrr1) && testFile.readByteString(trrr2));
	CPPUNIT_ASSERT(trrr1 == t1);
	CPPUNIT_ASSERT(trrr2 == t2);
}

bool FileTests::exists(std::string name)
{
#ifndef _WIN32
	Directory dir("./testdir");
#else
	Directory dir(".\\testdir");
#endif


	CPPUNIT_ASSERT(dir.isValid());

	std::vector<std::string> files = dir.getFiles();

	for (std::vector<std::string>::iterator i = files.begin(); i != files.end(); i++)
	{
		if (!i->compare(name))
		{
			return true;
		}
	}

	return false;
}

