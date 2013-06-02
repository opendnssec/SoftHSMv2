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
 ECDHTests.cpp

 Contains test cases to test the ECDH class
 *****************************************************************************/

#include <stdlib.h>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "ECDHTests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#include "ECParameters.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ECDHTests);

void ECDHTests::setUp()
{
	ecdh = NULL;

	ecdh = CryptoFactory::i()->getAsymmetricAlgorithm("ECDH");

	// Check the ECDH object
	CPPUNIT_ASSERT(ecdh != NULL);
}

void ECDHTests::tearDown()
{
	if (ecdh != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
	}

	fflush(stdout);
}

void ECDHTests::testKeyGeneration()
{
	AsymmetricKeyPair* kp;

	// Curves to test
	std::vector<ByteString> curves;
	// Add X9.62 prime256v1
	curves.push_back(ByteString("06082a8648ce3d030107"));
	// Add secp384r1
	curves.push_back(ByteString("06052b81040022"));

	for (std::vector<ByteString>::iterator c = curves.begin(); c != curves.end(); c++)
	{
		// Set domain parameters
		ECParameters* p = new ECParameters;
		p->setEC(*c);

		// Generate key-pair
		CPPUNIT_ASSERT(ecdh->generateKeyPair(&kp, p));

		ECPublicKey* pub = (ECPublicKey*) kp->getPublicKey();
		ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getEC() == *c);
		CPPUNIT_ASSERT(priv->getEC() == *c);

		ecdh->recycleParameters(p);
		ecdh->recycleKeyPair(kp);
	}
}

void ECDHTests::testSerialisation()
{
	// Get prime256v1 domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06082a8648ce3d030107"));

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dEC;

	CPPUNIT_ASSERT(ecdh->reconstructParameters(&dEC, serialisedParams));

	CPPUNIT_ASSERT(dEC->areOfType(ECParameters::type));

	ECParameters* ddEC = (ECParameters*) dEC;

	CPPUNIT_ASSERT(p->getEC() == ddEC->getEC());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(ecdh->generateKeyPair(&kp, dEC));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(ecdh->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	ECPrivateKey* privKey = (ECPrivateKey*) kp->getPrivateKey();
	ECPublicKey* pubKey = (ECPublicKey*) kp->getPublicKey();

	ECPrivateKey* dPrivKey = (ECPrivateKey*) dKP->getPrivateKey();
	ECPublicKey* dPubKey = (ECPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getEC() == dPrivKey->getEC());
	CPPUNIT_ASSERT(privKey->getD() == dPrivKey->getD());

	CPPUNIT_ASSERT(pubKey->getEC() == dPubKey->getEC());
	CPPUNIT_ASSERT(pubKey->getQ() == dPubKey->getQ());

	ecdh->recycleParameters(p);
	ecdh->recycleParameters(dEC);
	ecdh->recycleKeyPair(kp);
	ecdh->recycleKeyPair(dKP);
}

void ECDHTests::testDerivation()
{
	AsymmetricKeyPair* kpa;
	AsymmetricKeyPair* kpb;
	ECParameters* p;

	// Curves to test
	std::vector<ByteString> curves;
	// Add X9.62 prime256v1
	curves.push_back(ByteString("06082a8648ce3d030107"));
	// Add secp384r1
	curves.push_back(ByteString("06052b81040022"));

	for (std::vector<ByteString>::iterator c = curves.begin(); c != curves.end(); c++)
	{
		// Get parameters
		p = new ECParameters;
		CPPUNIT_ASSERT(p != NULL);
		p->setEC(*c);

		// Generate key-pairs
		CPPUNIT_ASSERT(ecdh->generateKeyPair(&kpa, p));
		CPPUNIT_ASSERT(ecdh->generateKeyPair(&kpb, p));

		// Derive secrets
		SymmetricKey* sa;
		CPPUNIT_ASSERT(ecdh->deriveKey(&sa, kpb->getPublicKey(), kpa->getPrivateKey()));
		SymmetricKey* sb;
		CPPUNIT_ASSERT(ecdh->deriveKey(&sb, kpa->getPublicKey(), kpb->getPrivateKey()));

		// Must be the same
		CPPUNIT_ASSERT(sa->getKeyBits() == sb->getKeyBits());

		// Clean up
		ecdh->recycleSymmetricKey(sa);
		ecdh->recycleSymmetricKey(sb);
		ecdh->recycleKeyPair(kpa);
		ecdh->recycleKeyPair(kpb);
		ecdh->recycleParameters(p);
	}
}

void ECDHTests::testDeriveKnownVector()
{
	// TODO
}

