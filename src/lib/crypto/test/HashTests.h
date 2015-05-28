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
 HashTests.h

 Contains test cases to test the hash implementations
 *****************************************************************************/

#ifndef _SOFTHSM_V2_HASHTESTS_H
#define _SOFTHSM_V2_HASHTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "HashAlgorithm.h"
#include "RNG.h"

class HashTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(HashTests);
#ifndef WITH_FIPS
	CPPUNIT_TEST(testMD5);
#endif
	CPPUNIT_TEST(testSHA1);
	CPPUNIT_TEST(testSHA224);
	CPPUNIT_TEST(testSHA256);
	CPPUNIT_TEST(testSHA384);
	CPPUNIT_TEST(testSHA512);
	CPPUNIT_TEST_SUITE_END();

public:
#ifndef WITH_FIPS
	void testMD5();
#endif
	void testSHA1();
	void testSHA224();
	void testSHA256();
	void testSHA384();
	void testSHA512();

	void setUp();
	void tearDown();

private:
	HashAlgorithm* hash;

	RNG* rng;
};

#endif // !_SOFTHSM_V2_HASHTESTS_H

