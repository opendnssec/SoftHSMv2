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
 DHTests.cpp

 Contains test cases to test the DH class
 *****************************************************************************/

#include <stdlib.h>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "DHTests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#include "DHParameters.h"
#include "DHPublicKey.h"
#include "DHPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(DHTests);

void DHTests::setUp()
{
	dh = NULL;

	dh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DH);

	// Check the DH object
	CPPUNIT_ASSERT(dh != NULL);
}

void DHTests::tearDown()
{
	if (dh != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
	}

	fflush(stdout);
}

void DHTests::testKeyGeneration()
{
	AsymmetricKeyPair* kp;

	// Key sizes to test
	std::vector<size_t> keySizes;
	keySizes.push_back(1024);

	for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
	{
		// Generate parameters
		DHParameters* p;
		AsymmetricParameters** ap = (AsymmetricParameters**) &p;

		CPPUNIT_ASSERT(dh->generateParameters(ap, (void*) *k));

		// Generate key-pair
		CPPUNIT_ASSERT(dh->generateKeyPair(&kp, p));

		DHPublicKey* pub = (DHPublicKey*) kp->getPublicKey();
		DHPrivateKey* priv = (DHPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getBitLength() == *k);
		CPPUNIT_ASSERT(priv->getBitLength() == *k);

		dh->recycleKeyPair(kp);

		// Generate key-pair with a fixed private value length
		p->setXBitLength(128);
		CPPUNIT_ASSERT(dh->generateKeyPair(&kp, p));

		priv = (DHPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(priv->getX().bits() == 128);

		dh->recycleParameters(p);
		dh->recycleKeyPair(kp);
	}
}

void DHTests::testSerialisation()
{
	// Generate 1024-bit parameters for testing
	DHParameters* p;
	AsymmetricParameters** ap = (AsymmetricParameters**) &p;

	CPPUNIT_ASSERT(dh->generateParameters(ap, (void*) 1024));

	// Set a fixed private value length
	p->setXBitLength(128);

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dP;

	CPPUNIT_ASSERT(dh->reconstructParameters(&dP, serialisedParams));

	CPPUNIT_ASSERT(dP->areOfType(DHParameters::type));

	DHParameters* ddP = (DHParameters*) dP;

	CPPUNIT_ASSERT(p->getP() == ddP->getP());
	CPPUNIT_ASSERT(p->getG() == ddP->getG());
	CPPUNIT_ASSERT(p->getXBitLength() == ddP->getXBitLength());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(dh->generateKeyPair(&kp, dP));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(dh->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	DHPrivateKey* privKey = (DHPrivateKey*) kp->getPrivateKey();
	DHPublicKey* pubKey = (DHPublicKey*) kp->getPublicKey();

	DHPrivateKey* dPrivKey = (DHPrivateKey*) dKP->getPrivateKey();
	DHPublicKey* dPubKey = (DHPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getP() == dPrivKey->getP());
	CPPUNIT_ASSERT(privKey->getG() == dPrivKey->getG());
	CPPUNIT_ASSERT(privKey->getX() == dPrivKey->getX());

	CPPUNIT_ASSERT(pubKey->getP() == dPubKey->getP());
	CPPUNIT_ASSERT(pubKey->getG() == dPubKey->getG());
	CPPUNIT_ASSERT(pubKey->getY() == dPubKey->getY());

	dh->recycleParameters(p);
	dh->recycleParameters(dP);
	dh->recycleKeyPair(kp);
	dh->recycleKeyPair(dKP);
}

void DHTests::testPKCS8()
{
	// Generate 1024-bit parameters for testing
	AsymmetricParameters* p;

	CPPUNIT_ASSERT(dh->generateParameters(&p, (void*) 1024));

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(dh->generateKeyPair(&kp, p));
	CPPUNIT_ASSERT(kp != NULL);

	DHPrivateKey* priv = (DHPrivateKey*) kp->getPrivateKey();
	CPPUNIT_ASSERT(priv != NULL);

	// Encode and decode the private key
	ByteString pkcs8 = priv->PKCS8Encode();
	CPPUNIT_ASSERT(pkcs8.size() != 0);

	DHPrivateKey* dPriv = (DHPrivateKey*) dh->newPrivateKey();
	CPPUNIT_ASSERT(dPriv != NULL);

	CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));


	CPPUNIT_ASSERT(priv->getP() == dPriv->getP());
	CPPUNIT_ASSERT(priv->getG() == dPriv->getG());
	CPPUNIT_ASSERT(priv->getX() == dPriv->getX());

	dh->recycleParameters(p);
	dh->recycleKeyPair(kp);
	dh->recyclePrivateKey(dPriv);
}

void DHTests::testDerivation()
{
	AsymmetricKeyPair* kpa;
	AsymmetricKeyPair* kpb;

	// Key sizes to test
	std::vector<size_t> keySizes;
	keySizes.push_back(1024);

	for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
	{
		// Generate parameters
		AsymmetricParameters* p;

		CPPUNIT_ASSERT(dh->generateParameters(&p, (void*) *k));

		// Generate key-pairs
		CPPUNIT_ASSERT(dh->generateKeyPair(&kpa, p));
		CPPUNIT_ASSERT(dh->generateKeyPair(&kpb, p));

		// Derive secrets
		SymmetricKey* sa;
		CPPUNIT_ASSERT(dh->deriveKey(&sa, kpb->getPublicKey(), kpa->getPrivateKey()));
		SymmetricKey* sb;
		CPPUNIT_ASSERT(dh->deriveKey(&sb, kpa->getPublicKey(), kpb->getPrivateKey()));

		// Must be the same
		CPPUNIT_ASSERT(sa->getKeyBits() == sb->getKeyBits());

		// Clean up
		dh->recycleSymmetricKey(sa);
		dh->recycleSymmetricKey(sb);
		dh->recycleKeyPair(kpa);
		dh->recycleKeyPair(kpb);
		dh->recycleParameters(p);
	}
}

void DHTests::testDeriveKnownVector()
{
	// TODO
}

