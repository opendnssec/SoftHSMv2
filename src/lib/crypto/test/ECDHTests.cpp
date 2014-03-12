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
#ifdef WITH_ECC
#include "ECParameters.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ECDHTests);

void ECDHTests::setUp()
{
	ecdh = NULL;

	ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);

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

void ECDHTests::testPKCS8()
{
	// Get prime256v1 domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06082a8648ce3d030107"));

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(ecdh->generateKeyPair(&kp, p));
	CPPUNIT_ASSERT(kp != NULL);

	ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();
	CPPUNIT_ASSERT(priv != NULL);

	// Encode and decode the private key
	ByteString pkcs8 = priv->PKCS8Encode();
	CPPUNIT_ASSERT(pkcs8.size() != 0);

	ECPrivateKey* dPriv = (ECPrivateKey*) ecdh->newPrivateKey();
	CPPUNIT_ASSERT(dPriv != NULL);

	CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

	CPPUNIT_ASSERT(priv->getEC() == dPriv->getEC());
	CPPUNIT_ASSERT(priv->getD() == dPriv->getD());

	ecdh->recycleParameters(p);
	ecdh->recycleKeyPair(kp);
	ecdh->recyclePrivateKey(dPriv);
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
	ECPublicKey* pubKeya = (ECPublicKey*) ecdh->newPublicKey();
	ECPublicKey* pubKeyb = (ECPublicKey*) ecdh->newPublicKey();
	ECPrivateKey* privKeya = (ECPrivateKey*) ecdh->newPrivateKey();
	ECPrivateKey* privKeyb = (ECPrivateKey*) ecdh->newPrivateKey();

	// Reconstruct public and private key for Alice
	ByteString ec = "06082a8648ce3d030107"; // X9.62 prime256v1
	ByteString da = "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433";
	// add 04 (ASN_String) <len+1> 04 (UNCOMPRESSED) in front!
	ByteString qa = "044104dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3";

	pubKeya->setEC(ec);
	pubKeya->setQ(qa);
	privKeya->setEC(ec);
	privKeya->setD(da);

	// Reconstruct public and private key for Bob
	ByteString db = "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53";
	ByteString qb = "044104d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab";

	pubKeyb->setEC(ec);
	pubKeyb->setQ(qb);
	privKeyb->setEC(ec);
	privKeyb->setD(db);

	// Test
	ByteString expected = "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de";
	SymmetricKey* sa;
	CPPUNIT_ASSERT(ecdh->deriveKey(&sa, pubKeya, privKeyb));
	CPPUNIT_ASSERT(sa->getKeyBits() == expected);
	SymmetricKey* sb;
	CPPUNIT_ASSERT(ecdh->deriveKey(&sb, pubKeyb, privKeya));
	CPPUNIT_ASSERT(sb->getKeyBits() == expected);

	ecdh->recyclePublicKey(pubKeya);
	ecdh->recyclePublicKey(pubKeyb);
	ecdh->recyclePrivateKey(privKeya);
	ecdh->recyclePrivateKey(privKeyb);
	ecdh->recycleSymmetricKey(sa);
	ecdh->recycleSymmetricKey(sb);
}
#endif
