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
 RFC4880Tests.cpp

 Contains test cases to test the RFC4880 implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "RFC4880Tests.h"
#include "RFC4880.h"
#include "ByteString.h"
#include "CryptoFactory.h"
#include "AESKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(RFC4880Tests);

void RFC4880Tests::setUp()
{
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
}

void RFC4880Tests::tearDown()
{
}

void RFC4880Tests::testRFC4880()
{
	const unsigned char* pwd1String = (const unsigned char*) "monkey";
	const unsigned char* pwd2String = (const unsigned char*) "bicycle";
	ByteString pwd1(pwd1String, strlen("monkey"));
	ByteString pwd2(pwd2String, strlen("bicycle"));

	// Generate salt and make sure that two different salt values are generated and
	// that the last byte is also different (resulting in a different iteration jitter
	// when computing a PBE key using both salt values)
	ByteString salt1, salt2;

	do
	{
		CPPUNIT_ASSERT(rng->generateRandom(salt1, 8) && rng->generateRandom(salt2, 8));
	}
	while ((salt1 == salt2) || (salt1[salt1.size() - 1] == salt2[salt2.size() - 1]));

	// Create a password-based encryption key from the first and second password
	AESKey* key1;
	AESKey* key2;

	CPPUNIT_ASSERT(RFC4880::PBEDeriveKey(pwd1, salt1, &key1));
	CPPUNIT_ASSERT(RFC4880::PBEDeriveKey(pwd2, salt2, &key2));

	// Check that the output keys differ and have the correct length
	CPPUNIT_ASSERT(key1->getKeyBits().size() == 32);
	CPPUNIT_ASSERT(key2->getKeyBits().size() == 32);
	CPPUNIT_ASSERT(key1->getKeyBits() != key2->getKeyBits());

	// Rederive the keys to check that the same output is generated every time
	AESKey* key1_;
	AESKey* key2_;

	CPPUNIT_ASSERT(RFC4880::PBEDeriveKey(pwd1, salt1, &key1_));
	CPPUNIT_ASSERT(RFC4880::PBEDeriveKey(pwd2, salt2, &key2_));

	CPPUNIT_ASSERT(key1->getKeyBits() == key1_->getKeyBits());
	CPPUNIT_ASSERT(key2->getKeyBits() == key2_->getKeyBits());

	// Now reverse the salts and derive new keys
	AESKey* key3;
	AESKey* key4;

	CPPUNIT_ASSERT(RFC4880::PBEDeriveKey(pwd1, salt2, &key3));
	CPPUNIT_ASSERT(RFC4880::PBEDeriveKey(pwd2, salt1, &key4));

	// Check that the keys are different and that they differ from the
	// original keys (because different salts were used)
	CPPUNIT_ASSERT(key3->getKeyBits() != key4->getKeyBits());
	CPPUNIT_ASSERT(key1->getKeyBits() != key3->getKeyBits());
	CPPUNIT_ASSERT(key1->getKeyBits() != key4->getKeyBits());
	CPPUNIT_ASSERT(key2->getKeyBits() != key3->getKeyBits());
	CPPUNIT_ASSERT(key2->getKeyBits() != key4->getKeyBits());

	// Clean up
	delete key1;
	delete key2;
	delete key1_;
	delete key2_;
	delete key3;
	delete key4;
}

