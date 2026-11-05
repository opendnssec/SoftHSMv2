/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 ChaChaTests.h

 Contains test cases to test the ChaCha20-Poly1305 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CHACHATESTS_H
#define _SOFTHSM_V2_CHACHATESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "SymmetricAlgorithm.h"

class ChaChaTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(ChaChaTests);
	CPPUNIT_TEST(testBlockSize);
	CPPUNIT_TEST(testRFC8439);
	CPPUNIT_TEST(testRFC8439MultiPart);
	CPPUNIT_TEST(testRFC8439Tampered);
	CPPUNIT_TEST_SUITE_END();

public:
	void testBlockSize();
	void testRFC8439();
	void testRFC8439MultiPart();
	void testRFC8439Tampered();

	void setUp();
	void tearDown();

private:
	// ChaCha20-Poly1305 instance
	SymmetricAlgorithm* chacha;
};

#endif // !_SOFTHSM_V2_CHACHATESTS_H
