/* $Id$ */

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
 AESTests.cpp

 Contains test cases to test the AES implementation
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "AESTests.h"
#include "CryptoFactory.h"
#include "AESKey.h"
#include <stdio.h>

CPPUNIT_TEST_SUITE_REGISTRATION(AESTests);

void AESTests::setUp()
{
	aes = NULL;

	aes = CryptoFactory::i()->getSymmetricAlgorithm("aes");

	// Check the return value
	CPPUNIT_ASSERT(aes != NULL);
}

void AESTests::tearDown()
{
	if (aes != NULL)
	{
		delete aes;
	}
}

void AESTests::testCBCDecrypt()
{
	// Load test vectors
	#include "aes_cbc_d_tv.h"

	// Perform the test with the NIST test vectors for 128 bit keys
	ByteString blankKey;
	blankKey.wipe(16);

	AESKey aes128Key(128);
	aes128Key.setKeyBits(blankKey);

	ByteString IV, prevCT, CT, CV;
	IV.wipe(16);
	CT.wipe(16);

	for (int i = 0; i < 400; i++)
	{
		for (int j = 0; j < 9999; j++)
		{
			
		}


	}
}

