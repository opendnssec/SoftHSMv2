/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 XWingTests.h

 Contains test cases to test the X-Wing class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_XWINGTESTS_H
#define _SOFTHSM_V2_XWINGTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class XWingTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(XWingTests);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testEncapsulation);
	CPPUNIT_TEST(testEncapsulationDecapsulation);
	CPPUNIT_TEST(testEncapsulationInvalidInputs);
	CPPUNIT_TEST(testKeyGenerationTestVector);
	CPPUNIT_TEST(testEncapsulationTestVector);
	CPPUNIT_TEST(testDecapsulationTestVector);
	CPPUNIT_TEST_SUITE_END();

public:
	XWingTests() : xWing(NULL) {}
	void testSerialisation();
	void testPKCS8();
	void testEncapsulation();
	void testEncapsulationDecapsulation();
	void testEncapsulationInvalidInputs();
	void testKeyGenerationTestVector();
	void testEncapsulationTestVector();
	void testDecapsulationTestVector();

	void setUp();
	void tearDown();

private:
	// X-Wing instance
	AsymmetricAlgorithm* xWing;
};

#endif // !_SOFTHSM_V2_XWINGTESTS_H
