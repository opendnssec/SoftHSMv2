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
 DirectoryTests.cpp

 Contains test cases to test the directory implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DirectoryTests.h"
#include "Directory.h"

CPPUNIT_TEST_SUITE_REGISTRATION(DirectoryTests);

void DirectoryTests::setUp()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("mkdir testdir"));
	CPPUNIT_ASSERT(!system("mkdir testdir/anotherdir"));
	CPPUNIT_ASSERT(!system("mkdir testdir/anotherdir2"));
	CPPUNIT_ASSERT(!system("mkdir testdir/anotherdir3"));
	CPPUNIT_ASSERT(!system("echo someStuff > testdir/afile"));
	CPPUNIT_ASSERT(!system("echo someOtherStuff > testdir/anotherFile"));
	CPPUNIT_ASSERT(!system("echo justStuff > testdir/justaFile"));
#else
	CPPUNIT_ASSERT(!system("mkdir testdir"));
	CPPUNIT_ASSERT(!system("mkdir testdir\\anotherdir"));
	CPPUNIT_ASSERT(!system("mkdir testdir\\anotherdir2"));
	CPPUNIT_ASSERT(!system("mkdir testdir\\anotherdir3"));
	CPPUNIT_ASSERT(!system("echo someStuff > testdir\\afile"));
	CPPUNIT_ASSERT(!system("echo someOtherStuff > testdir\\anotherFile"));
	CPPUNIT_ASSERT(!system("echo justStuff > testdir\\justaFile"));
#endif
}

void DirectoryTests::tearDown()
{
#ifndef _WIN32
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
#else
	CPPUNIT_ASSERT(!system("rmdir /s /q testdir 2> nul"));
#endif
}

void DirectoryTests::testDirectory()
{
#ifndef _WIN32
	Directory testdir("./testdir");
#else
	Directory testdir(".\\testdir");
#endif

	CPPUNIT_ASSERT(testdir.isValid());

	std::vector<std::string> files = testdir.getFiles();
	std::vector<std::string> subDirs = testdir.getSubDirs();

	CPPUNIT_ASSERT(files.size() == 3);
	CPPUNIT_ASSERT(subDirs.size() == 3);

	CPPUNIT_ASSERT(testdir.refresh());

	CPPUNIT_ASSERT(files.size() == 3);
	CPPUNIT_ASSERT(subDirs.size() == 3);

	bool fileSeen[3] = { false, false, false };

	for (std::vector<std::string>::iterator i = files.begin(); i != files.end(); i++)
	{
		if (!i->compare("afile"))
		{
			fileSeen[0] = true;
		}
		else if (!i->compare("anotherFile"))
		{
			fileSeen[1] = true;
		}
		else if (!i->compare("justaFile"))
		{
			fileSeen[2] = true;
		}
		else
		{
			CPPUNIT_ASSERT(false);
		}
	}

	CPPUNIT_ASSERT(fileSeen[0] && fileSeen[1] && fileSeen[2]);

	bool dirSeen[3] = { false, false, false };

	for (std::vector<std::string>::iterator i = subDirs.begin(); i != subDirs.end(); i++)
	{
		if (!i->compare("anotherdir"))
		{
			dirSeen[0] = true;
		}
		else if (!i->compare("anotherdir2"))
		{
			dirSeen[1] = true;
		}
		else if (!i->compare("anotherdir3"))
		{
			dirSeen[2] = true;
		}
		else
		{
			CPPUNIT_ASSERT(false);
		}
	}

	CPPUNIT_ASSERT(dirSeen[0] && dirSeen[1] && dirSeen[2]);

	// Create a directory
	CPPUNIT_ASSERT(testdir.mkdir("newDir"));

	subDirs = testdir.getSubDirs();

	bool dirSeen2[4] = { false, false, false, false };

	for (std::vector<std::string>::iterator i = subDirs.begin(); i != subDirs.end(); i++)
	{
		if (!i->compare("anotherdir"))
		{
			dirSeen2[0] = true;
		}
		else if (!i->compare("anotherdir2"))
		{
			dirSeen2[1] = true;
		}
		else if (!i->compare("anotherdir3"))
		{
			dirSeen2[2] = true;
		}
		else if (!i->compare("newDir"))
		{
			dirSeen2[3] = true;
		}
		else
		{
			CPPUNIT_ASSERT(false);
		}
	}

	CPPUNIT_ASSERT(dirSeen2[0] && dirSeen2[1] && dirSeen2[2] && dirSeen2[3]);

	// Remove a directory
	CPPUNIT_ASSERT(testdir.rmdir("anotherdir2", true));

	subDirs = testdir.getSubDirs();

	bool dirSeen3[3] = { false, false, false };

	for (std::vector<std::string>::iterator i = subDirs.begin(); i != subDirs.end(); i++)
	{
		if (!i->compare("anotherdir"))
		{
			dirSeen3[0] = true;
		}
		else if (!i->compare("newDir"))
		{
			dirSeen3[1] = true;
		}
		else if (!i->compare("anotherdir3"))
		{
			dirSeen3[2] = true;
		}
		else
		{
			CPPUNIT_ASSERT(false);
		}
	}

	CPPUNIT_ASSERT(dirSeen3[0] && dirSeen3[1] && dirSeen3[2]);

	// Remove a file
	CPPUNIT_ASSERT(testdir.remove("anotherFile"));

	files = testdir.getFiles();

	bool fileSeen2[2] = { false, false };

	for (std::vector<std::string>::iterator i = files.begin(); i != files.end(); i++)
	{
		if (!i->compare("afile"))
		{
			fileSeen2[0] = true;
		}
		else if (!i->compare("justaFile"))
		{
			fileSeen2[1] = true;
		}
		else
		{
			CPPUNIT_ASSERT(false);
		}
	}

	CPPUNIT_ASSERT(fileSeen2[0] && fileSeen2[1]);
}

