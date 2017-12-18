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
 MacTests.h

 Contains test cases to test the MAC implementations
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MACTESTS_H
#define _SOFTHSM_V2_MACTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "MacAlgorithm.h"
#include "RNG.h"

class MacTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(MacTests);
#ifndef WITH_FIPS
	CPPUNIT_TEST(testHMACMD5);
#endif
	CPPUNIT_TEST(testHMACSHA1);
	CPPUNIT_TEST(testHMACSHA224);
	CPPUNIT_TEST(testHMACSHA256);
	CPPUNIT_TEST(testHMACSHA384);
	CPPUNIT_TEST(testHMACSHA512);
	CPPUNIT_TEST(testCMACDES2);
	CPPUNIT_TEST(testCMACDES3);
	CPPUNIT_TEST(testCMACAES128);
	CPPUNIT_TEST(testCMACAES192);
	CPPUNIT_TEST(testCMACAES256);
	CPPUNIT_TEST_SUITE_END();

public:
#ifndef WITH_FIPS
	void testHMACMD5();
#endif
	void testHMACSHA1();
	void testHMACSHA224();
	void testHMACSHA256();
	void testHMACSHA384();
	void testHMACSHA512();
	void testCMACDES2();
	void testCMACDES3();
	void testCMACAES128();
	void testCMACAES192();
	void testCMACAES256();

	void setUp();
	void tearDown();

private:
	MacAlgorithm* mac;

	RNG* rng;
};

#endif // !_SOFTHSM_V2_MACTESTS_H

