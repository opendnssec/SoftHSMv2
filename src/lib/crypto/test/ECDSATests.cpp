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

	ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);

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
	// Add secp521r1
	curves.push_back(ByteString("06052b81040023"));

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

void ECDSATests::testPKCS8()
{
	// Get prime256v1 domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06082a8648ce3d030107"));

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(ecdsa->generateKeyPair(&kp, p));
	CPPUNIT_ASSERT(kp != NULL);

	ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();
	CPPUNIT_ASSERT(priv != NULL);

	// Encode and decode the private key
	ByteString pkcs8 = priv->PKCS8Encode();
	CPPUNIT_ASSERT(pkcs8.size() != 0);

	ECPrivateKey* dPriv = (ECPrivateKey*) ecdsa->newPrivateKey();
	CPPUNIT_ASSERT(dPriv != NULL);

	CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

	CPPUNIT_ASSERT(priv->getEC() == dPriv->getEC());
	CPPUNIT_ASSERT(priv->getD() == dPriv->getD());

	ecdsa->recycleParameters(p);
	ecdsa->recycleKeyPair(kp);
	ecdsa->recyclePrivateKey(dPriv);
}

void ECDSATests::testSigningVerifying()
{
	AsymmetricKeyPair* kp;
	ECParameters *p;

	// Curves/Hashes to test
	std::vector<std::pair<ByteString, HashAlgo::Type> > totest;
	// Add X9.62 prime256v1
	totest.push_back(std::make_pair(ByteString("06082a8648ce3d030107"), HashAlgo::SHA256));
	// Add secp384r1
	totest.push_back(std::make_pair(ByteString("06052b81040022"), HashAlgo::SHA384));
	// Add secp521r1
	totest.push_back(std::make_pair(ByteString("06052b81040023"), HashAlgo::SHA384));

	for (std::vector<std::pair<ByteString, HashAlgo::Type> >::iterator k = totest.begin(); k != totest.end(); k++)
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
		CPPUNIT_ASSERT(ecdsa->sign(kp->getPrivateKey(), hResult, sig, AsymMech::ECDSA));

		// And verify it
		CPPUNIT_ASSERT(ecdsa->verify(kp->getPublicKey(), hResult, sig, AsymMech::ECDSA));

		ecdsa->recycleKeyPair(kp);
		ecdsa->recycleParameters(p);
		CryptoFactory::i()->recycleHashAlgorithm(hash);
	}
}

void ECDSATests::testSignVerifyKnownVector()
{
	ECPublicKey* pubKey1 = (ECPublicKey*) ecdsa->newPublicKey();
	ECPublicKey* pubKey2 = (ECPublicKey*) ecdsa->newPublicKey();
	ECPrivateKey* privKey1 = (ECPrivateKey*) ecdsa->newPrivateKey();
	ECPrivateKey* privKey2 = (ECPrivateKey*) ecdsa->newPrivateKey();
	HashAlgorithm* hash1 = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA256);
	HashAlgorithm* hash2 = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA384);

	// Reconstruct public and private key #1
	ByteString ec1 = "06082a8648ce3d030107"; // X9.62 prime256v1
	ByteString d1 = "dc51d3866a15bacde33d96f992fca99da7e6ef0934e7097559c27f1614c88a7f";
	// add 04 (ASN_String) <len+1> 04 (UNCOMPRESSED) in front!
	ByteString q1 = "0441042442a5cc0ecd015fa3ca31dc8e2bbc70bf42d60cbca20085e0822cb04235e9706fc98bd7e50211a4a27102fa3549df79ebcb4bf246b80945cddfe7d509bbfd7d";

	pubKey1->setEC(ec1);
	pubKey1->setQ(q1);
	privKey1->setEC(ec1);
	privKey1->setD(d1);
	CPPUNIT_ASSERT(hash1 != NULL);

	// Test with key #1
	ByteString data1 = "616263"; // "abc"
	ByteString goodSignature1 = "cb28e0999b9c7715fd0a80d8e47a77079716cbbf917dd72e97566ea1c066957c86fa3bb4e26cad5bf90b7f81899256ce7594bb1ea0c89212748bff3b3d5b0315";
	ByteString badSignature1 = "cb28e0999b9c7715fd0a80d8e47a77079716cbbf917dd72e97566ea1c066957c86fa3bb4e26cad5bf90b7f81899256ce7594bb1ea0c89212748bff3b3d5b0316";

	// Reconstruct public and private key #2
	ByteString ec2 = "06052b81040022"; // secp384r1
	ByteString d2 = "0beb646634ba87735d77ae4809a0ebea865535de4c1e1dcb692e84708e81a5af62e528c38b2a81b35309668d73524d9f";
	// add 04 (ASN_String) <len+1> 04 (UNCOMPRESSED) in front!
	ByteString q2 = "04610496281bf8dd5e0525ca049c048d345d3082968d10fedf5c5aca0c64e6465a97ea5ce10c9dfec21797415710721f437922447688ba94708eb6e2e4d59f6ab6d7edff9301d249fe49c33096655f5d502fad3d383b91c5e7edaa2b714cc99d5743ca";

	pubKey2->setEC(ec2);
	pubKey2->setQ(q2);
	privKey2->setEC(ec2);
	privKey2->setD(d2);
	CPPUNIT_ASSERT(hash2 != NULL);

	// Test with key #2
	ByteString data2 = "616263"; // "abc"
	ByteString goodSignature2 = "fb017b914e29149432d8bac29a514640b46f53ddab2c69948084e2930f1c8f7e08e07c9c63f2d21a07dcb56a6af56eb3b263a1305e057f984d38726a1b46874109f417bca112674c528262a40a629af1cbb9f516ce0fa7d2ff630863a00e8b9f";
	ByteString badSignature2 = "fb017b914e29149432d8bac29a514640b46f53ddab2c69948084e2930f1c8f7e08e07c9c63f2d21a07dcb56a6af56eb3b263a1305e057f984d38726a1b46874109f417bca112674c528262a40a629af1cbb9f516ce0fa7d2ff630863a00e8b9e";

	CPPUNIT_ASSERT(hash1->hashInit());
	CPPUNIT_ASSERT(hash1->hashUpdate(data1));
	ByteString hResult1;
	CPPUNIT_ASSERT(hash1->hashFinal(hResult1));
	CPPUNIT_ASSERT(ecdsa->verify(pubKey1, hResult1, goodSignature1, AsymMech::ECDSA));
	CPPUNIT_ASSERT(!ecdsa->verify(pubKey1, hResult1, badSignature1, AsymMech::ECDSA));
	CPPUNIT_ASSERT(hash2->hashInit());
	CPPUNIT_ASSERT(hash2->hashUpdate(data2));
	ByteString hResult2;
	CPPUNIT_ASSERT(hash2->hashFinal(hResult2));
	CPPUNIT_ASSERT(ecdsa->verify(pubKey2, hResult2, goodSignature2, AsymMech::ECDSA));
	CPPUNIT_ASSERT(!ecdsa->verify(pubKey2, hResult2, badSignature2, AsymMech::ECDSA));

	ecdsa->recyclePublicKey(pubKey1);
	ecdsa->recyclePublicKey(pubKey2);
	ecdsa->recyclePrivateKey(privKey1);
	ecdsa->recyclePrivateKey(privKey2);
	CryptoFactory::i()->recycleHashAlgorithm(hash1);
	CryptoFactory::i()->recycleHashAlgorithm(hash2);
}
#endif
