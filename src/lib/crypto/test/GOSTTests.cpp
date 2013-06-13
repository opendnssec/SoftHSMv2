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
 GOSTTests.cpp

 Contains test cases to test the GOST implementations
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "GOSTTests.h"
#include "CryptoFactory.h"
#include <stdio.h>
#include "AsymmetricAlgorithm.h"
#include "AsymmetricKeyPair.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "RNG.h"
#ifdef WITH_GOST
#include "ECParameters.h"
#include "GOSTPublicKey.h"
#include "GOSTPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(GOSTTests);

void GOSTTests::setUp()
{
	hash = NULL;
	mac = NULL;
	gost = NULL;
	rng = NULL;
}

void GOSTTests::tearDown()
{
	if (hash != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
	}

	if (mac != NULL)
	{
		CryptoFactory::i()->recycleMacAlgorithm(mac);
	}

	if (gost != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
	}

	fflush(stdout);
}

void GOSTTests::testHash()
{
	// Get an RNG and GOST R 34.11-94 hash instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("gost")) != NULL);

	// Generate some random input data
	ByteString b;
	ByteString osslHash, gostHash;

	CPPUNIT_ASSERT(rng->generateRandom(b, 53287));

	// Write it to file
	writeTmpFile(b);

	// Use OpenSSL externally to hash it
	CPPUNIT_ASSERT(system("cat gost-hashtest.tmp | openssl dgst -engine gost -md_gost94 -binary > gost-hashtest-out.tmp 2> /dev/null") == 0);

	// Read the hash from file
	readTmpFile(osslHash);

	// Now recreate the hash using our implementation in a single operation
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b));
	CPPUNIT_ASSERT(hash->hashFinal(gostHash));

	CPPUNIT_ASSERT(osslHash == gostHash);

	// Now recreate the hash in a single part operation
	gostHash.wipe();

	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(hash->hashFinal(gostHash));

	CPPUNIT_ASSERT(osslHash == gostHash);

	CryptoFactory::i()->recycleHashAlgorithm(hash);

	hash = NULL;
	rng = NULL;
}

void GOSTTests::writeTmpFile(ByteString& data)
{
	FILE* out = fopen("gost-hashtest.tmp", "w");
	CPPUNIT_ASSERT(out != NULL);

	CPPUNIT_ASSERT(fwrite(&data[0], 1, data.size(), out) == data.size());
	CPPUNIT_ASSERT(!fclose(out));
}

void GOSTTests::readTmpFile(ByteString& data)
{
	unsigned char buf[256];

	data.wipe();

	FILE* in = fopen("gost-hashtest-out.tmp", "r");
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

void GOSTTests::testHmac()
{
	// Get an RNG and HMAC GOST R34.11-94 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-gost")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-GOST_R-34.11-94_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;

	CPPUNIT_ASSERT(rng->generateRandom(b, 53287));

	// Sign the MAC using our implementation in a single operation
	ByteString mResult1;

	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b));
	CPPUNIT_ASSERT(mac->signFinal(mResult1));

	// Sign the MAC in a multiple part operation
	ByteString mResult2;

	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->signFinal(mResult2));

	// Now verify the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(mac->verifyFinal(mResult2));

	// Now verify the MAC in a multiple part operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->verifyFinal(mResult1));

	// Check if bad key is refused
	mResult1[10] ^= 0x11;
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(!mac->verifyFinal(mResult1));

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void GOSTTests::testHashKnownVector()
{
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("gost")) != NULL);

	// Message to hash for test #1
	ByteString msg = "6d65737361676520646967657374"; // "message digest"
	ByteString expected = "bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0";
	ByteString result;

	// Test #1
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(msg));
	CPPUNIT_ASSERT(hash->hashFinal(result));

	CPPUNIT_ASSERT(result == expected);

	CryptoFactory::i()->recycleHashAlgorithm(hash);
	hash = NULL;
}

void GOSTTests::testKeyGeneration()
{
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT((gost = CryptoFactory::i()->getAsymmetricAlgorithm("gost")));

	// Set domain parameters
	ByteString curve = "06072a850302022301";
	ECParameters* p = new ECParameters;
	p->setEC(curve);

	// Generate key-pair
	CPPUNIT_ASSERT(gost->generateKeyPair(&kp, p));

	GOSTPublicKey* pub = (GOSTPublicKey*) kp->getPublicKey();
	GOSTPrivateKey* priv = (GOSTPrivateKey*) kp->getPrivateKey();

	CPPUNIT_ASSERT(pub->getQ().size() == 64);
	CPPUNIT_ASSERT(priv->getD().size() == 32);

	gost->recycleParameters(p);
	gost->recycleKeyPair(kp);

	CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
	gost = NULL;
}

void GOSTTests::testSerialisation()
{
	CPPUNIT_ASSERT((gost = CryptoFactory::i()->getAsymmetricAlgorithm("gost")));

	// Get GOST R 34.10-2001 params-A domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06072a850302022301"));

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dEC;

	CPPUNIT_ASSERT(gost->reconstructParameters(&dEC, serialisedParams));

	CPPUNIT_ASSERT(dEC->areOfType(ECParameters::type));

	ECParameters* ddEC = (ECParameters*) dEC;

	CPPUNIT_ASSERT(p->getEC() == ddEC->getEC());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(gost->generateKeyPair(&kp, dEC));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(gost->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	GOSTPrivateKey* privKey = (GOSTPrivateKey*) kp->getPrivateKey();
	GOSTPublicKey* pubKey = (GOSTPublicKey*) kp->getPublicKey();

	GOSTPrivateKey* dPrivKey = (GOSTPrivateKey*) dKP->getPrivateKey();
	GOSTPublicKey* dPubKey = (GOSTPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getD() == dPrivKey->getD());
	CPPUNIT_ASSERT(pubKey->getQ() == dPubKey->getQ());

	gost->recycleParameters(p);
	gost->recycleParameters(dEC);
	gost->recycleKeyPair(kp);
	gost->recycleKeyPair(dKP);

	CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
	gost = NULL;
}

void GOSTTests::testSigningVerifying()
{
	AsymmetricKeyPair* kp;
	ECParameters *p;
	ByteString curve = "06072a850302022301";

	CPPUNIT_ASSERT((gost = CryptoFactory::i()->getAsymmetricAlgorithm("gost")));

	// Get parameters
	p = new ECParameters;
	CPPUNIT_ASSERT(p != NULL);
	p->setEC(curve);

	// Generate key-pair
	CPPUNIT_ASSERT(gost->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG* rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(gost->sign(kp->getPrivateKey(), dataToSign, sig, "gost"));

	// And verify it
	CPPUNIT_ASSERT(gost->verify(kp->getPublicKey(), dataToSign, sig, "gost"));

	gost->recycleKeyPair(kp);
	gost->recycleParameters(p);

	CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
	gost = NULL;
}

void GOSTTests::testSignVerifyKnownVector()
{
	// TODO
}
#endif
