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
 AESTests.h

 Contains test cases to test the AES implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_AESTESTS_H
#define _SOFTHSM_V2_AESTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "SymmetricAlgorithm.h"

class AESTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(AESTests);
	CPPUNIT_TEST(testBlockSize);
	CPPUNIT_TEST(testCBC);
	CPPUNIT_TEST(testECB);
	CPPUNIT_TEST(testCTR);
#ifdef WITH_AES_GCM
	CPPUNIT_TEST(testGCM);
#endif
#ifdef HAVE_AES_KEY_WRAP
	CPPUNIT_TEST(testWrapWoPad);
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
	CPPUNIT_TEST(testWrapPad);
#endif
	CPPUNIT_TEST_SUITE_END();

public:
	void testBlockSize();
	void testCBC();
	void testECB();
	void testCTR();
#ifdef WITH_AES_GCM
	void testGCM();
#endif
	void testWrapWoPad();
	void testWrapPad();

	void setUp();
	void tearDown();

private:
	// AES instance
	SymmetricAlgorithm* aes;
	void testWrap(const char testKeK[][128], const char testKey[][128], const char testCt[][128], const int testCnt, SymWrap::Type mode);
};

#endif // !_SOFTHSM_V2_AESTESTS_H

