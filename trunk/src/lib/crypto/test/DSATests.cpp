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
 DSATests.cpp

 Contains test cases to test the RNG class
 *****************************************************************************/

#include <stdlib.h>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "DSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#include "DSAParameters.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(DSATests);

void DSATests::setUp()
{
	dsa = NULL;

	dsa = CryptoFactory::i()->getAsymmetricAlgorithm("DSA");

	// Check the DSA object
	CPPUNIT_ASSERT(dsa != NULL);
}

void DSATests::tearDown()
{
	if (dsa != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
	}

	fflush(stdout);
}

void DSATests::testKeyGeneration()
{
	AsymmetricKeyPair* kp;

	// Key sizes to test
	std::vector<size_t> keySizes;
	keySizes.push_back(512);
	keySizes.push_back(768);
	keySizes.push_back(1024);

	for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
	{
		// Generate parameters
		DSAParameters* p;
		AsymmetricParameters** ap = (AsymmetricParameters**) &p;

		CPPUNIT_ASSERT(dsa->generateParameters(ap, (void*) *k));
	
		// Generate key-pair
		CPPUNIT_ASSERT(dsa->generateKeyPair(&kp, p));
	
		dsa->recycleParameters(p);
		dsa->recycleKeyPair(kp);
	}
}

void DSATests::testSerialisation()
{
	// Generate 1024-bit parameters for testing
	DSAParameters* p;
	AsymmetricParameters** ap = (AsymmetricParameters**) &p;

	CPPUNIT_ASSERT(dsa->generateParameters(ap, (void*) 1024));

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dP;

	CPPUNIT_ASSERT(dsa->reconstructParameters(&dP, serialisedParams));

	CPPUNIT_ASSERT(dP->areOfType(DSAParameters::type));

	DSAParameters* ddP = (DSAParameters*) dP;

	CPPUNIT_ASSERT(p->getP() == ddP->getP());
	CPPUNIT_ASSERT(p->getQ() == ddP->getQ());
	CPPUNIT_ASSERT(p->getG() == ddP->getG());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(dsa->generateKeyPair(&kp, dP));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(dsa->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	DSAPrivateKey* privKey = (DSAPrivateKey*) kp->getPrivateKey();
	DSAPublicKey* pubKey = (DSAPublicKey*) kp->getPublicKey();

	DSAPrivateKey* dPrivKey = (DSAPrivateKey*) dKP->getPrivateKey();
	DSAPublicKey* dPubKey = (DSAPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getP() == dPrivKey->getP());
	CPPUNIT_ASSERT(privKey->getQ() == dPrivKey->getQ());
	CPPUNIT_ASSERT(privKey->getG() == dPrivKey->getG());
	CPPUNIT_ASSERT(privKey->getX() == dPrivKey->getX());
	CPPUNIT_ASSERT(privKey->getY() == dPrivKey->getY());

	CPPUNIT_ASSERT(pubKey->getP() == dPubKey->getP());
	CPPUNIT_ASSERT(pubKey->getQ() == dPubKey->getQ());
	CPPUNIT_ASSERT(pubKey->getG() == dPubKey->getG());
	CPPUNIT_ASSERT(pubKey->getY() == dPubKey->getY());

	dsa->recycleParameters(p);
	dsa->recycleParameters(dP);
	dsa->recycleKeyPair(kp);
	dsa->recycleKeyPair(dKP);
}

void DSATests::testSigningVerifying()
{
	AsymmetricKeyPair* kp;

	// Key sizes to test
	std::vector<size_t> keySizes;
	keySizes.push_back(512);
	keySizes.push_back(768);
	keySizes.push_back(1024);

	// Mechanisms to test
	std::vector<const char*> mechanisms;
	mechanisms.push_back("dsa-sha1");

	for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
	{
		// Generate parameters
		AsymmetricParameters* p;

		CPPUNIT_ASSERT(dsa->generateParameters(&p, (void*) *k));

		// Generate key-pair
		CPPUNIT_ASSERT(dsa->generateKeyPair(&kp, p));

		// Generate some data to sign
		ByteString dataToSign;

		RNG* rng = CryptoFactory::i()->getRNG();

		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

		for (std::vector<const char*>::iterator m = mechanisms.begin(); m != mechanisms.end(); m++)
		{
			ByteString blockSignature, singlePartSignature;

			// Sign the data in blocks
			CPPUNIT_ASSERT(dsa->signInit(kp->getPrivateKey(), *m));
			CPPUNIT_ASSERT(dsa->signUpdate(dataToSign.substr(0, 134)));
			CPPUNIT_ASSERT(dsa->signUpdate(dataToSign.substr(134, 289)));
			CPPUNIT_ASSERT(dsa->signUpdate(dataToSign.substr(134 + 289)));
			CPPUNIT_ASSERT(dsa->signFinal(blockSignature));

			// Sign the data in one pass
			CPPUNIT_ASSERT(dsa->sign(kp->getPrivateKey(), dataToSign, singlePartSignature, *m));

			// Now perform multi-pass verification
			CPPUNIT_ASSERT(dsa->verifyInit(kp->getPublicKey(), *m));
			CPPUNIT_ASSERT(dsa->verifyUpdate(dataToSign.substr(0, 125)));
			CPPUNIT_ASSERT(dsa->verifyUpdate(dataToSign.substr(125, 247)));
			CPPUNIT_ASSERT(dsa->verifyUpdate(dataToSign.substr(125 + 247)));
			CPPUNIT_ASSERT(dsa->verifyFinal(blockSignature));

			// And single-pass verification
			CPPUNIT_ASSERT(dsa->verify(kp->getPublicKey(), dataToSign, singlePartSignature, *m));
		}

		CryptoFactory::i()->recycleRNG(rng);
		dsa->recycleKeyPair(kp);
		dsa->recycleParameters(p);
	}
}

void DSATests::testSignVerifyKnownVector()
{
	// TODO
}

