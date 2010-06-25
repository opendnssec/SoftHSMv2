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
 FileTests.cpp

 Contains test cases to test the directory implementation
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
	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void FileTests::tearDown()
{
	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
}

void FileTests::testExistNotExist()
{
	// Test pre-condition
	CPPUNIT_ASSERT(!exists("nonExistentFile"));

	// Attempt to open a file known not to exist
	File doesntExist("testdir/nonExistentFile");

	CPPUNIT_ASSERT(!doesntExist.isValid());

	// Attempt to open a file known to exist
	CPPUNIT_ASSERT(!system("echo someStuff > testdir/existingFile"));
	CPPUNIT_ASSERT(exists("existingFile"));

	File exists("testdir/existingFile");

	CPPUNIT_ASSERT(exists.isValid());
}

void FileTests::testCreateNotCreate()
{
	// Test pre-condition
	CPPUNIT_ASSERT(!exists("nonExistentFile"));
	CPPUNIT_ASSERT(!exists("nonExistentFile2"));
	
	// Attempt to open a file known not to exist
	File doesntExist("testdir/nonExistentFile", true, true, false);

	CPPUNIT_ASSERT(!doesntExist.isValid());
	CPPUNIT_ASSERT(!exists("nonExistentFile"));

	// Attempt to open a file known not to exist in create mode
	File willBeCreated("testdir/nonExistentFile2", true, true, true);

	CPPUNIT_ASSERT(willBeCreated.isValid());
	CPPUNIT_ASSERT(exists("nonExistentFile2"));
}

void FileTests::testLockUnlock()
{
	// Create pre-condition
	CPPUNIT_ASSERT(!system("echo someStuff > testdir/existingFile"));
	CPPUNIT_ASSERT(exists("existingFile"));

	File file1("testdir/existingFile");
	File file2("testdir/existingFile");

	CPPUNIT_ASSERT(file1.lock(false));
	CPPUNIT_ASSERT(!file2.lock(false));
	CPPUNIT_ASSERT(!file2.unlock());
	CPPUNIT_ASSERT(file1.unlock());
	CPPUNIT_ASSERT(file2.lock(false));
	CPPUNIT_ASSERT(file2.unlock());
	CPPUNIT_ASSERT(file1.lock());
	CPPUNIT_ASSERT(!file2.lock(false));
	CPPUNIT_ASSERT(!file2.unlock());
	CPPUNIT_ASSERT(file1.unlock());
}

void FileTests::testWriteRead()
{
	// Generate some test data
	RNG* rng = CryptoFactory::i()->getRNG();

	ByteString testData1;

	CPPUNIT_ASSERT(rng->generateRandom(testData1, 187));

	CryptoFactory::i()->recycleRNG(rng);

	// More test data
	std::string testString = "This is a test of the File class";

	// Create a file for writing
	{
		File newFile("testdir/newFile", false, true);

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
	}

	CPPUNIT_ASSERT(exists("newFile"));

	// Read the created file back
	{
		File newFile("testdir/newFile");

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

		// Check for EOF
		CPPUNIT_ASSERT(!newFile.readBool(b1));
		CPPUNIT_ASSERT(newFile.isEOF());
	}
}

void FileTests::testSeek()
{
}

bool FileTests::exists(std::string name)
{
	Directory dir("./testdir");

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

