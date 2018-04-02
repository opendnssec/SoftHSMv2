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
 EDDSATests.cpp

 Contains test cases to test the EDDSA class
 *****************************************************************************/

#include <stdlib.h>
#include <utility>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "EDDSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#ifdef WITH_EDDSA
#include "ECParameters.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(EDDSATests);

void EDDSATests::setUp()
{
	eddsa = NULL;

	eddsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);

	// Check the EDDSA object
	CPPUNIT_ASSERT(eddsa != NULL);
}

void EDDSATests::tearDown()
{
	if (eddsa != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
	}

	fflush(stdout);
}

void EDDSATests::testKeyGeneration()
{
	AsymmetricKeyPair* kp;

	// Curves to test
	std::vector<ByteString> curves;
	// Add x25519
	curves.push_back(ByteString("06032b656e"));
	// Add ed25519
	curves.push_back(ByteString("06032b6570"));

	for (std::vector<ByteString>::iterator c = curves.begin(); c != curves.end(); c++)
	{
		// Set domain parameters
		ECParameters* p = new ECParameters;
		p->setEC(*c);

		// Generate key-pair
		CPPUNIT_ASSERT(eddsa->generateKeyPair(&kp, p));

		EDPublicKey* pub = (EDPublicKey*) kp->getPublicKey();
		EDPrivateKey* priv = (EDPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getEC() == *c);
		CPPUNIT_ASSERT(priv->getEC() == *c);

		eddsa->recycleParameters(p);
		eddsa->recycleKeyPair(kp);
	}
}

void EDDSATests::testSerialisation()
{
	// Get ed25519 domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06032b6570"));

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dEC;

	CPPUNIT_ASSERT(eddsa->reconstructParameters(&dEC, serialisedParams));

	CPPUNIT_ASSERT(dEC->areOfType(ECParameters::type));

	ECParameters* ddEC = (ECParameters*) dEC;

	CPPUNIT_ASSERT(p->getEC() == ddEC->getEC());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(eddsa->generateKeyPair(&kp, dEC));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(eddsa->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	EDPrivateKey* privKey = (EDPrivateKey*) kp->getPrivateKey();
	EDPublicKey* pubKey = (EDPublicKey*) kp->getPublicKey();

	EDPrivateKey* dPrivKey = (EDPrivateKey*) dKP->getPrivateKey();
	EDPublicKey* dPubKey = (EDPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getEC() == dPrivKey->getEC());
	CPPUNIT_ASSERT(privKey->getK() == dPrivKey->getK());

	CPPUNIT_ASSERT(pubKey->getEC() == dPubKey->getEC());
	CPPUNIT_ASSERT(pubKey->getA() == dPubKey->getA());

	eddsa->recycleParameters(p);
	eddsa->recycleParameters(dEC);
	eddsa->recycleKeyPair(kp);
	eddsa->recycleKeyPair(dKP);
}

void EDDSATests::testPKCS8()
{
	// Get ed25519 domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06032b6570"));

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(eddsa->generateKeyPair(&kp, p));
	CPPUNIT_ASSERT(kp != NULL);

	EDPrivateKey* priv = (EDPrivateKey*) kp->getPrivateKey();
	CPPUNIT_ASSERT(priv != NULL);

	// Encode and decode the private key
	ByteString pkcs8 = priv->PKCS8Encode();
	CPPUNIT_ASSERT(pkcs8.size() != 0);

	EDPrivateKey* dPriv = (EDPrivateKey*) eddsa->newPrivateKey();
	CPPUNIT_ASSERT(dPriv != NULL);

	CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

	CPPUNIT_ASSERT(priv->getEC() == dPriv->getEC());
	CPPUNIT_ASSERT(priv->getK() == dPriv->getK());

	eddsa->recycleParameters(p);
	eddsa->recycleKeyPair(kp);
	eddsa->recyclePrivateKey(dPriv);
}

void EDDSATests::testSigningVerifying()
{
	AsymmetricKeyPair* kp;
	ECParameters *p;

	// Curves to test
	std::vector<ByteString> curves;
	// Add ed25519
	curves.push_back(ByteString("06032b6570"));

	for (std::vector<ByteString>::iterator c = curves.begin(); c != curves.end(); c++)
	{
		// Get parameters
		p = new ECParameters;
		CPPUNIT_ASSERT(p != NULL);
		p->setEC(*c);

		// Generate key-pair
		CPPUNIT_ASSERT(eddsa->generateKeyPair(&kp, p));

		// Generate some data to sign
		ByteString dataToSign;

		RNG* rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

		// Sign the data
		ByteString sig;
		CPPUNIT_ASSERT(eddsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::EDDSA));

		// And verify it
		CPPUNIT_ASSERT(eddsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::EDDSA));

		eddsa->recycleKeyPair(kp);
		eddsa->recycleParameters(p);
	}
}

void EDDSATests::testSignVerifyKnownVector()
{
	EDPublicKey* pubKey1 = (EDPublicKey*) eddsa->newPublicKey();
	EDPublicKey* pubKey2 = (EDPublicKey*) eddsa->newPublicKey();
	EDPrivateKey* privKey1 = (EDPrivateKey*) eddsa->newPrivateKey();
	EDPrivateKey* privKey2 = (EDPrivateKey*) eddsa->newPrivateKey();

	// Reconstruct public and private key #1
	ByteString ec1 = "06032b6570"; // ed25519
	ByteString k1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
	ByteString a1 = "0420d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

	pubKey1->setEC(ec1);
	pubKey1->setA(a1);
	privKey1->setEC(ec1);
	privKey1->setK(k1);

	// Test with key #1
	ByteString data1; // ""
	ByteString goodSignature1 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
	ByteString badSignature1 = "e5564300c360ac728086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

	// Reconstruct public and private key #2
	ByteString ec2 = "06032b6570"; // ed25519
	ByteString k2 = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
	ByteString a2 = "0420fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

	pubKey2->setEC(ec2);
	pubKey2->setA(a2);
	privKey2->setEC(ec2);
	privKey2->setK(k2);

	// Test with key #2
	ByteString data2 = "af82";
	ByteString goodSignature2 = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
	ByteString badSignature2 = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027bedeea1ec40a";

	CPPUNIT_ASSERT(eddsa->verify(pubKey1, data1, goodSignature1, AsymMech::EDDSA));
	CPPUNIT_ASSERT(!eddsa->verify(pubKey1, data1, badSignature1, AsymMech::EDDSA));
	CPPUNIT_ASSERT(eddsa->verify(pubKey2, data2, goodSignature2, AsymMech::EDDSA));
	CPPUNIT_ASSERT(!eddsa->verify(pubKey2, data2, badSignature2, AsymMech::EDDSA));

	eddsa->recyclePublicKey(pubKey1);
	eddsa->recyclePublicKey(pubKey2);
	eddsa->recyclePrivateKey(privKey1);
	eddsa->recyclePrivateKey(privKey2);
}

void EDDSATests::testDerivation()
{
	AsymmetricKeyPair* kpa;
	AsymmetricKeyPair* kpb;
	ECParameters* p;

	// Curves to test
	std::vector<ByteString> curves;
	// Add x25519
	curves.push_back(ByteString("06032b656e"));

	for (std::vector<ByteString>::iterator c = curves.begin(); c != curves.end(); c++)
	{
		// Get parameters
		p = new ECParameters;
		CPPUNIT_ASSERT(p != NULL);
		p->setEC(*c);

		// Generate key-pairs
		CPPUNIT_ASSERT(eddsa->generateKeyPair(&kpa, p));
		CPPUNIT_ASSERT(eddsa->generateKeyPair(&kpb, p));

		// Derive secrets
		SymmetricKey* sa;
		CPPUNIT_ASSERT(eddsa->deriveKey(&sa, kpb->getPublicKey(), kpa->getPrivateKey()));
		SymmetricKey* sb;
		CPPUNIT_ASSERT(eddsa->deriveKey(&sb, kpa->getPublicKey(), kpb->getPrivateKey()));

		// Must be the same
		CPPUNIT_ASSERT(sa->getKeyBits() == sb->getKeyBits());

		// Clean up
		eddsa->recycleSymmetricKey(sa);
		eddsa->recycleSymmetricKey(sb);
		eddsa->recycleKeyPair(kpa);
		eddsa->recycleKeyPair(kpb);
		eddsa->recycleParameters(p);
	}
}

void EDDSATests::testDeriveKnownVector()
{
	EDPublicKey* pubKeya = (EDPublicKey*) eddsa->newPublicKey();
	EDPublicKey* pubKeyb = (EDPublicKey*) eddsa->newPublicKey();
	EDPrivateKey* privKeya = (EDPrivateKey*) eddsa->newPrivateKey();
	EDPrivateKey* privKeyb = (EDPrivateKey*) eddsa->newPrivateKey();

	// Reconstruct public and private key for Alice
	ByteString ec = "06032b656e"; // x25519
	ByteString ka = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	ByteString aa = "04208520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

	pubKeya->setEC(ec);
	pubKeya->setA(aa);
	privKeya->setEC(ec);
	privKeya->setK(ka);

	// Reconstruct public and private key for Bob
	ByteString kb = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
	ByteString ab = "0420de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

	pubKeyb->setEC(ec);
	pubKeyb->setA(ab);
	privKeyb->setEC(ec);
	privKeyb->setK(kb);

	// Test
	ByteString expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
	SymmetricKey* sa;
	CPPUNIT_ASSERT(eddsa->deriveKey(&sa, pubKeya, privKeyb));
	CPPUNIT_ASSERT(sa->getKeyBits() == expected);
	SymmetricKey* sb;
	CPPUNIT_ASSERT(eddsa->deriveKey(&sb, pubKeyb, privKeya));
	CPPUNIT_ASSERT(sb->getKeyBits() == expected);

	eddsa->recyclePublicKey(pubKeya);
	eddsa->recyclePublicKey(pubKeyb);
	eddsa->recyclePrivateKey(privKeya);
	eddsa->recyclePrivateKey(privKeyb);
	eddsa->recycleSymmetricKey(sa);
	eddsa->recycleSymmetricKey(sb);
}
#endif
