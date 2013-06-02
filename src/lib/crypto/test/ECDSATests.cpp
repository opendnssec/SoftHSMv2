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
 ECDSATests.cpp

 Contains test cases to test the ECDSA class
 *****************************************************************************/

#include <stdlib.h>
#include <utility>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "ECDSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#ifdef WITH_ECC
#include "ECParameters.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ECDSATests);

void ECDSATests::setUp()
{
	ecdsa = NULL;

	ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm("ECDSA");

	// Check the ECDSA object
	CPPUNIT_ASSERT(ecdsa != NULL);
}

void ECDSATests::tearDown()
{
	if (ecdsa != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);
	}

	fflush(stdout);
}

void ECDSATests::testKeyGeneration()
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
		CPPUNIT_ASSERT(ecdsa->generateKeyPair(&kp, p));

		ECPublicKey* pub = (ECPublicKey*) kp->getPublicKey();
		ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getEC() == *c);
		CPPUNIT_ASSERT(priv->getEC() == *c);

		ecdsa->recycleParameters(p);
		ecdsa->recycleKeyPair(kp);
	}
}

void ECDSATests::testSerialisation()
{
	// Get prime256v1 domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06082a8648ce3d030107"));

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dEC;

	CPPUNIT_ASSERT(ecdsa->reconstructParameters(&dEC, serialisedParams));

	CPPUNIT_ASSERT(dEC->areOfType(ECParameters::type));

	ECParameters* ddEC = (ECParameters*) dEC;

	CPPUNIT_ASSERT(p->getEC() == ddEC->getEC());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(ecdsa->generateKeyPair(&kp, dEC));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(ecdsa->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	ECPrivateKey* privKey = (ECPrivateKey*) kp->getPrivateKey();
	ECPublicKey* pubKey = (ECPublicKey*) kp->getPublicKey();

	ECPrivateKey* dPrivKey = (ECPrivateKey*) dKP->getPrivateKey();
	ECPublicKey* dPubKey = (ECPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getEC() == dPrivKey->getEC());
	CPPUNIT_ASSERT(privKey->getD() == dPrivKey->getD());

	CPPUNIT_ASSERT(pubKey->getEC() == dPubKey->getEC());
	CPPUNIT_ASSERT(pubKey->getQ() == dPubKey->getQ());

	ecdsa->recycleParameters(p);
	ecdsa->recycleParameters(dEC);
	ecdsa->recycleKeyPair(kp);
	ecdsa->recycleKeyPair(dKP);
}

void ECDSATests::testSigningVerifying()
{
	AsymmetricKeyPair* kp;
	ECParameters *p;

	// Curves/Hashes to test
	std::vector<std::pair<ByteString, const char*> > totest;
	// Add X9.62 prime256v1
	totest.push_back(std::make_pair(ByteString("06082a8648ce3d030107"), "sha256"));
	// Add secp384r1
	totest.push_back(std::make_pair(ByteString("06052b81040022"), "sha384"));


	for (std::vector<std::pair<ByteString, const char*> >::iterator k = totest.begin(); k != totest.end(); k++)
	{
		// Get parameters
		p = new ECParameters;
		CPPUNIT_ASSERT(p != NULL);
		p->setEC(k->first);
		HashAlgorithm *hash;
		hash = CryptoFactory::i()->getHashAlgorithm(k->second);
		CPPUNIT_ASSERT(hash != NULL);

		// Generate key-pair
		CPPUNIT_ASSERT(ecdsa->generateKeyPair(&kp, p));

		// Generate some data to sign
		ByteString dataToSign;

		RNG* rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

		// Sign the data
		CPPUNIT_ASSERT(hash->hashInit());
		CPPUNIT_ASSERT(hash->hashUpdate(dataToSign));
		ByteString hResult;
		CPPUNIT_ASSERT(hash->hashFinal(hResult));
		ByteString sig;
		CPPUNIT_ASSERT(ecdsa->sign(kp->getPrivateKey(), hResult, sig, "ECDSA"));

		// And verify it
		CPPUNIT_ASSERT(ecdsa->verify(kp->getPublicKey(), hResult, sig, "ECDSA"));

		ecdsa->recycleKeyPair(kp);
		ecdsa->recycleParameters(p);
	}
}

void ECDSATests::testSignVerifyKnownVector()
{
	// TODO
}
#endif
