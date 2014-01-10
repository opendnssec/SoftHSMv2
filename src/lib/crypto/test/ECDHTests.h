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
 ECDHTests.h

 Contains test cases to test the ECDH class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ECDHTESTS_H
#define _SOFTHSM_V2_ECDHTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class ECDHTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(ECDHTests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testDerivation);
	CPPUNIT_TEST(testDeriveKnownVector);
	CPPUNIT_TEST_SUITE_END();

public:
	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testDerivation();
	void testDeriveKnownVector();

	void setUp();
	void tearDown();

private:
	// ECDH instance
	AsymmetricAlgorithm* ecdh;
};

#endif // !_SOFTHSM_V2_ECDHTESTS_H

