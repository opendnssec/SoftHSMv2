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
 HashTests.cpp

 Contains test cases to test the hash implementations
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "HashTests.h"
#include "CryptoFactory.h"
#include <stdio.h>
#include "HashAlgorithm.h"
#include "RNG.h"

CPPUNIT_TEST_SUITE_REGISTRATION(HashTests);

void HashTests::setUp()
{
	hash = NULL;
	rng = NULL;
}

void HashTests::tearDown()
{
	if (hash != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
	}

	if (rng != NULL)
	{
		CryptoFactory::i()->recycleRNG(rng);
	}

	fflush(stdout);
}

void HashTests::testMD5()
{
	// Get an RNG and MD5 hash instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("md5")) != NULL);

	// Generate some random input data
	ByteString b;
	ByteString osslHash, shsmHash;

	CPPUNIT_ASSERT(rng->generateRandom(b, 52237));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to hash it
	CPPUNIT_ASSERT(system("cat shsmv2-hashtest.tmp | openssl md5 -binary > shsmv2-hashtest-out.tmp") == 0);

	// Read the hash from file
	readTmpFile(osslHash);

	// Now recreate the hash using our implementation in a single operation
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	// Now recreate the hash in a single part operation
	shsmHash.wipe();

	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	CryptoFactory::i()->recycleHashAlgorithm(hash);
	CryptoFactory::i()->recycleRNG(rng);

	hash = NULL;
	rng = NULL;
}

void HashTests::testSHA1()
{
	// Get an RNG and SHA1 hash instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("sha1")) != NULL);

	// Generate some random input data
	ByteString b;
	ByteString osslHash, shsmHash;

	CPPUNIT_ASSERT(rng->generateRandom(b, 32598));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to hash it
	CPPUNIT_ASSERT(system("cat shsmv2-hashtest.tmp | openssl sha1 -binary > shsmv2-hashtest-out.tmp") == 0);

	// Read the hash from file
	readTmpFile(osslHash);

	// Now recreate the hash using our implementation in a single operation
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	// Now recreate the hash in a single part operation
	shsmHash.wipe();

	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	CryptoFactory::i()->recycleHashAlgorithm(hash);
	CryptoFactory::i()->recycleRNG(rng);

	hash = NULL;
	rng = NULL;
}

void HashTests::testSHA256()
{
	// Get an RNG and SHA256 hash instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("sha256")) != NULL);

	// Generate some random input data
	ByteString b;
	ByteString osslHash, shsmHash;

	CPPUNIT_ASSERT(rng->generateRandom(b, 53287));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to hash it
	CPPUNIT_ASSERT(system("cat shsmv2-hashtest.tmp | openssl sha -sha256 -binary > shsmv2-hashtest-out.tmp") == 0);

	// Read the hash from file
	readTmpFile(osslHash);

	// Now recreate the hash using our implementation in a single operation
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	// Now recreate the hash in a single part operation
	shsmHash.wipe();

	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	CryptoFactory::i()->recycleHashAlgorithm(hash);
	CryptoFactory::i()->recycleRNG(rng);

	hash = NULL;
	rng = NULL;
}

void HashTests::testSHA512()
{
	// Get an RNG and SHA512 hash instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("sha512")) != NULL);

	// Generate some random input data
	ByteString b;
	ByteString osslHash, shsmHash;

	CPPUNIT_ASSERT(rng->generateRandom(b, 35298));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to hash it
	CPPUNIT_ASSERT(system("cat shsmv2-hashtest.tmp | openssl sha -sha512 -binary > shsmv2-hashtest-out.tmp") == 0);

	// Read the hash from file
	readTmpFile(osslHash);

	// Now recreate the hash using our implementation in a single operation
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	// Now recreate the hash in a single part operation
	shsmHash.wipe();

	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(hash->hashFinal(shsmHash));

	CPPUNIT_ASSERT(osslHash == shsmHash);

	CryptoFactory::i()->recycleHashAlgorithm(hash);
	CryptoFactory::i()->recycleRNG(rng);

	hash = NULL;
	rng = NULL;
}

void HashTests::writeTmpFile(ByteString& data)
{
	FILE* out = fopen("shsmv2-hashtest.tmp", "w");
	CPPUNIT_ASSERT(out != NULL);

	CPPUNIT_ASSERT(fwrite(&data[0], 1, data.size(), out) == data.size());
	CPPUNIT_ASSERT(!fclose(out));
}

void HashTests::readTmpFile(ByteString& data)
{
	unsigned char buf[256];

	data.wipe();

	FILE* in = fopen("shsmv2-hashtest-out.tmp", "r");
	CPPUNIT_ASSERT(in != NULL);

	int read = 0;

	do
	{
		read = fread(buf, 1, 256, in);

		data += ByteString(buf, read);
	}
	while (read > 0);

	CPPUNIT_ASSERT(read == 0);
	CPPUNIT_ASSERT(!fclose(in));
}

