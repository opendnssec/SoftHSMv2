/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 FalconTests.h

 Contains test cases to test the Falcon class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FALCONTESTS_H
#define _SOFTHSM_V2_FALCONTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class FalconTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(FalconTests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testSigning);
	CPPUNIT_TEST(testSigningWithReconstructedPrivateKey);
	CPPUNIT_TEST(testVerification);
	CPPUNIT_TEST(testSignVerifyKnownVector);
	CPPUNIT_TEST(testInvalidInputs);
	CPPUNIT_TEST_SUITE_END();

public:
	FalconTests() : falcon(NULL) {}

	void setUp();
	void tearDown();

	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testSigning();
	void testSigningWithReconstructedPrivateKey();
	void testVerification();
	void testSignVerifyKnownVector();
	void testInvalidInputs();

private:
	AsymmetricAlgorithm* falcon;
};

#endif // !_SOFTHSM_V2_FALCONTESTS_H
