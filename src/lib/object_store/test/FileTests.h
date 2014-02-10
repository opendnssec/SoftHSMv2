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
 FileTests.h

 Contains test cases to test the File implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FILETESTS_H
#define _SOFTHSM_V2_FILETESTS_H

#include <cppunit/extensions/HelperMacros.h>

class FileTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(FileTests);
	CPPUNIT_TEST(testExistNotExist);
	CPPUNIT_TEST(testCreateNotCreate);
	CPPUNIT_TEST(testLockUnlock);
	CPPUNIT_TEST(testWriteRead);
	CPPUNIT_TEST(testSeek);
	CPPUNIT_TEST_SUITE_END();

public:
	void testExistNotExist();
	void testCreateNotCreate();
	void testLockUnlock();
	void testWriteRead();
	void testSeek();

	void setUp();
	void tearDown();

private:
	bool exists(std::string path);
};

#endif // !_SOFTHSM_V2_FILETESTS_H

