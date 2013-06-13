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
 RNGTests.cpp

 Contains test cases to test the RNG class
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "RNGTests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "ent.h"
#include <stdio.h>

CPPUNIT_TEST_SUITE_REGISTRATION(RNGTests);

void RNGTests::setUp()
{
	rng = NULL;

	rng = CryptoFactory::i()->getRNG();

	// Check the RNG
	CPPUNIT_ASSERT(rng != NULL);
}

void RNGTests::tearDown()
{
	fflush(stdout);
}

void RNGTests::testSimpleComparison()
{
	ByteString a,b;

	CPPUNIT_ASSERT(rng->generateRandom(a, 256));
	CPPUNIT_ASSERT(rng->generateRandom(b, 256));
	CPPUNIT_ASSERT(a.size() == 256);
	CPPUNIT_ASSERT(b.size() == 256);
	CPPUNIT_ASSERT(a != b);
}

void RNGTests::testEnt()
{
	ByteString a;
	double entropy, chiProbability, arithMean, montePi, serialCorrelation;

	// Generate 10MB of random data
	CPPUNIT_ASSERT(rng->generateRandom(a, 10*1024*1024));

	// Perform entropy tests
	doEnt(a.byte_str(), a.size(), &entropy, &chiProbability, &arithMean, &montePi, &serialCorrelation);

	// Check entropy
	CPPUNIT_ASSERT(entropy >= 7.999);
	CPPUNIT_ASSERT((arithMean >= 127.4) && (arithMean <= 127.6));
	CPPUNIT_ASSERT(serialCorrelation <= 0.001);
}

