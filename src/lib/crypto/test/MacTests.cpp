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
 MacTests.cpp

 Contains test cases to test the MAC implementations
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "MacTests.h"
#include "CryptoFactory.h"
#include <stdio.h>
#include "MacAlgorithm.h"
#include "RNG.h"

CPPUNIT_TEST_SUITE_REGISTRATION(MacTests);

void MacTests::setUp()
{
	mac = NULL;
	rng = NULL;
}

void MacTests::tearDown()
{
	if (mac != NULL)
	{
		CryptoFactory::i()->recycleMacAlgorithm(mac);
	}

	fflush(stdout);
}

void MacTests::testHMACMD5()
{
	// Get an RNG and HMAC-MD5 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-md5")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-MD5_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;
	ByteString osslMac, shsmMac;

	CPPUNIT_ASSERT(rng->generateRandom(b, 52237));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to mac it
	char commandLine[2048];
	sprintf(commandLine, "cat shsmv2-mactest.tmp | openssl dgst -hmac %s -md5 -binary > shsmv2-mactest-out.tmp", pk);
	CPPUNIT_ASSERT(system(commandLine) == 0);

	// Read the MAC from file
	readTmpFile(osslMac);

	// Now recreate the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac == shsmMac);

	// Now recreate the MAC in a multiple part operation
	shsmMac.wipe();

	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac == shsmMac);

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void MacTests::testHMACSHA1()
{
	// Get an RNG and HMAC-SHA1 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha1")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-SHA1_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;
	ByteString osslMac, shsmMac;

	CPPUNIT_ASSERT(rng->generateRandom(b, 32598));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally mac hash it
	char commandLine[2048];
	sprintf(commandLine, "cat shsmv2-mactest.tmp | openssl dgst -hmac %s -sha1 -binary > shsmv2-mactest-out.tmp", pk);
	CPPUNIT_ASSERT(system(commandLine) == 0);

	// Read the MAC from file
	readTmpFile(osslMac);

	// Now verify the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(mac->verifyFinal(osslMac));

	// Now recreate the MAC in a multiple part operation
	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac == shsmMac);

	// Now recreate a wrong MAC
	b[5] ^= 0x28;
	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac != shsmMac);

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void MacTests::testHMACSHA224()
{
	// Get an RNG and HMAC-SHA224 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha224")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-SHA224_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;
	ByteString osslMac, shsmMac;

	CPPUNIT_ASSERT(rng->generateRandom(b, 53287));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to mac it
	char commandLine[2048];
	sprintf(commandLine, "cat shsmv2-mactest.tmp | openssl dgst -hmac %s -sha224 -binary > shsmv2-mactest-out.tmp", pk);
	CPPUNIT_ASSERT(system(commandLine) == 0);

	// Read the MAC from file
	readTmpFile(osslMac);

	// Now recreate the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac == shsmMac);

	// Now verify the MAC in a multiple part operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->verifyFinal(osslMac));

	// Now don't verify a MAC with different input
	b[600] ^= 0xff;
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(!mac->verifyFinal(osslMac));

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void MacTests::testHMACSHA256()
{
	// Get an RNG and HMAC-SHA256 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha256")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-SHA256_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;
	ByteString osslMac;

	CPPUNIT_ASSERT(rng->generateRandom(b, 53287));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to mac it
	char commandLine[2048];
	sprintf(commandLine, "cat shsmv2-mactest.tmp | openssl dgst -hmac %s -sha256 -binary > shsmv2-mactest-out.tmp", pk);
	CPPUNIT_ASSERT(system(commandLine) == 0);

	// Read the MAC from file
	readTmpFile(osslMac);

	// Now verify the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(mac->verifyFinal(osslMac));

	// Now verify the MAC in a multiple part operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->verifyFinal(osslMac));

	// Check if bad key is refused
	osslMac[10] ^= 0x11;
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(!mac->verifyFinal(osslMac));

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void MacTests::testHMACSHA384()
{
	// Get an RNG and HMAC-SHA384 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha384")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-SHA384_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;
	ByteString osslMac, shsmMac;

	CPPUNIT_ASSERT(rng->generateRandom(b, 53287));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to mac it
	char commandLine[2048];
	sprintf(commandLine, "cat shsmv2-mactest.tmp | openssl dgst -hmac %s -sha384 -binary > shsmv2-mactest-out.tmp", pk);
	CPPUNIT_ASSERT(system(commandLine) == 0);

	// Read the MAC from file
	readTmpFile(osslMac);

	// Now recreate the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac == shsmMac);

	// Now recreate the MAC in a multiple part operation
	shsmMac.wipe();

	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac == shsmMac);

	// Now recreate a different MAC
	b[100] ^= 0x42;
	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b));
	CPPUNIT_ASSERT(mac->signFinal(shsmMac));

	CPPUNIT_ASSERT(osslMac != shsmMac);

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void MacTests::testHMACSHA512()
{
	// Get an RNG and HMAC-SHA512 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha512")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-SHA512_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;
	ByteString osslMac;

	CPPUNIT_ASSERT(rng->generateRandom(b, 35298));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to mac it
	char commandLine[2048];
	sprintf(commandLine, "cat shsmv2-mactest.tmp | openssl dgst -hmac %s -sha512 -binary > shsmv2-mactest-out.tmp", pk);
	CPPUNIT_ASSERT(system(commandLine) == 0);

	// Read the MAC from file
	readTmpFile(osslMac);

	// Now verify the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(mac->verifyFinal(osslMac));

	// Now verify the MAC in a multiple part operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->verifyFinal(osslMac));

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void MacTests::writeTmpFile(ByteString& data)
{
	FILE* out = fopen("shsmv2-mactest.tmp", "w");
	CPPUNIT_ASSERT(out != NULL);

	CPPUNIT_ASSERT(fwrite(&data[0], 1, data.size(), out) == data.size());
	CPPUNIT_ASSERT(!fclose(out));
}

void MacTests::readTmpFile(ByteString& data)
{
	unsigned char buf[256];

	data.wipe();

	FILE* in = fopen("shsmv2-mactest-out.tmp", "r");
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

