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

	dsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA);

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
#ifndef WITH_FIPS
	keySizes.push_back(1024);
	keySizes.push_back(1536);
#else
	keySizes.push_back(1024);
#endif
#ifndef WITH_BOTAN
	keySizes.push_back(2048);
#endif

	for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
	{
		// Generate parameters
		DSAParameters* p;
		AsymmetricParameters** ap = (AsymmetricParameters**) &p;

		CPPUNIT_ASSERT(dsa->generateParameters(ap, (void*) *k));

		// Generate key-pair
		CPPUNIT_ASSERT(dsa->generateKeyPair(&kp, p));

		DSAPublicKey* pub = (DSAPublicKey*) kp->getPublicKey();
		DSAPrivateKey* priv = (DSAPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getBitLength() == *k);
		CPPUNIT_ASSERT(priv->getBitLength() == *k);

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

	CPPUNIT_ASSERT(pubKey->getP() == dPubKey->getP());
	CPPUNIT_ASSERT(pubKey->getQ() == dPubKey->getQ());
	CPPUNIT_ASSERT(pubKey->getG() == dPubKey->getG());
	CPPUNIT_ASSERT(pubKey->getY() == dPubKey->getY());

	dsa->recycleParameters(p);
	dsa->recycleParameters(dP);
	dsa->recycleKeyPair(kp);
	dsa->recycleKeyPair(dKP);
}

void DSATests::testPKCS8()
{
	// Generate 1024-bit parameters for testing
	AsymmetricParameters* p;

	CPPUNIT_ASSERT(dsa->generateParameters(&p, (void*) 1024));

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(dsa->generateKeyPair(&kp, p));
	CPPUNIT_ASSERT(kp != NULL);

	DSAPrivateKey* priv = (DSAPrivateKey*) kp->getPrivateKey();
	CPPUNIT_ASSERT(priv != NULL);

	// Encode and decode the private key
	ByteString pkcs8 = priv->PKCS8Encode();
	CPPUNIT_ASSERT(pkcs8.size() != 0);

	DSAPrivateKey* dPriv = (DSAPrivateKey*) dsa->newPrivateKey();
	CPPUNIT_ASSERT(dPriv != NULL);

	CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

	CPPUNIT_ASSERT(priv->getP() == dPriv->getP());
	CPPUNIT_ASSERT(priv->getQ() == dPriv->getQ());
	CPPUNIT_ASSERT(priv->getG() == dPriv->getG());
	CPPUNIT_ASSERT(priv->getX() == dPriv->getX());

	dsa->recycleParameters(p);
	dsa->recycleKeyPair(kp);
	dsa->recyclePrivateKey(dPriv);
}

void DSATests::testSigningVerifying()
{
	AsymmetricKeyPair* kp;

	// Key sizes to test
	std::vector<size_t> keySizes;
#ifndef WITH_FIPS
	keySizes.push_back(1024);
	keySizes.push_back(1536);
#else
	keySizes.push_back(1024);
#endif
#ifndef WITH_BOTAN
	keySizes.push_back(2048);
#endif

	// Mechanisms to test
	std::vector<AsymMech::Type> mechanisms;
	mechanisms.push_back(AsymMech::DSA_SHA1);
	mechanisms.push_back(AsymMech::DSA_SHA224);
	mechanisms.push_back(AsymMech::DSA_SHA256);

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

		// Test mechanisms that perform internal hashing
		for (std::vector<AsymMech::Type>::iterator m = mechanisms.begin(); m != mechanisms.end(); m++)
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

		// Test mechanisms that do not perform internal hashing
		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, *k >= 2048 ? 32 : 20));

		// Sign the data
		ByteString signature;
		CPPUNIT_ASSERT(dsa->sign(kp->getPrivateKey(), dataToSign, signature, AsymMech::DSA));

		// Verify the signature
		CPPUNIT_ASSERT(dsa->verify(kp->getPublicKey(), dataToSign, signature, AsymMech::DSA));

		dsa->recycleKeyPair(kp);
		dsa->recycleParameters(p);
	}
}

void DSATests::testSignVerifyKnownVector()
{
	DSAPublicKey* pubKey1 = (DSAPublicKey*) dsa->newPublicKey();
	DSAPublicKey* pubKey2 = (DSAPublicKey*) dsa->newPublicKey();
	DSAPrivateKey* privKey1 = (DSAPrivateKey*) dsa->newPrivateKey();
	DSAPrivateKey* privKey2 = (DSAPrivateKey*) dsa->newPrivateKey();

	// Reconstruct public and private key #1
	ByteString p1 = "e0a67598cd1b763bc98c8abb333e5dda0cd3aa0e5e1fb5ba8a7b4eabc10ba338fae06dd4b90fda70d7cf0cb0c638be3341bec0af8a7330a3307ded2299a0ee606df035177a239c34a912c202aa5f83b9c4a7cf0235b5316bfc6efb9a248411258b30b839af172440f32563056cb67a861158ddd90e6a894c72a5bbef9e286c6b";
	ByteString q1 = "e950511eab424b9a19a2aeb4e159b7844c589c4f";
	ByteString g1 = "d29d5121b0423c2769ab21843e5a3240ff19cacc792264e3bb6be4f78edd1b15c4dff7f1d905431f0ab16790e1f773b5ce01c804e509066a9919f5195f4abc58189fd9ff987389cb5bedf21b4dab4f8b76a055ffe2770988fe2ec2de11ad92219f0b351869ac24da3d7ba87011a701ce8ee7bfe49486ed4527b7186ca4610a75";
	ByteString x1 = "d0ec4e50bb290a42e9e355c73d8809345de2e139";
	ByteString y1 = "25282217f5730501dd8dba3edfcf349aaffec20921128d70fac44110332201bba3f10986140cbb97c726938060473c8ec97b4731db004293b5e730363609df9780f8d883d8c4d41ded6a2f1e1bbbdc979e1b9d6d3c940301f4e978d65b19041fcf1e8b518f5c0576c770fe5a7a485d8329ee2914a2de1b5da4a6128ceab70f79";

	pubKey1->setP(p1);
	pubKey1->setQ(q1);
	pubKey1->setG(g1);
	pubKey1->setY(y1);
	privKey1->setP(p1);
	privKey1->setQ(q1);
	privKey1->setG(g1);
	privKey1->setX(x1);

	// Test with key #1
	ByteString data1 = "616263"; // "abc"
	ByteString goodSignature1 = "636155ac9a4633b4665d179f9e4117df68601f346c540b02d9d4852f89df8cfc99963204f4347704";
	ByteString badSignature1 = "636155ac9a4633b4665d179f9e4117df68601f346c540b02d9d4852f89df8cfc99963204f4347705";

	// Reconstruct public and private key #2
	ByteString p2 = "f56c2a7d366e3ebdeaa1891fd2a0d099436438a673fed4d75f594959cffebca7be0fc72e4fe67d91d801cba0693ac4ed9e411b41d19e2fd1699c4390ad27d94c69c0b143f1dc88932cfe2310c886412047bd9b1c7a67f8a25909132627f51a0c866877e672e555342bdf9355347dbd43b47156b2c20bad9d2b071bc2fdcf9757f75c168c5d9fc43131be162a0756d1bdec2ca0eb0e3b018a8b38d3ef2487782aeb9fbf99d8b30499c55e4f61e5c7dcee2a2bb55bd7f75fcdf00e48f2e8356bdb59d86114028f67b8e07b127744778aff1cf1399a4d679d92fde7d941c5c85c5d7bff91ba69f9489d531d1ebfa727cfda651390f8021719fa9f7216ceb177bd75";
	ByteString q2 = "c24ed361870b61e0d367f008f99f8a1f75525889c89db1b673c45af5867cb467";
	ByteString g2 = "8dc6cc814cae4a1c05a3e186a6fe27eaba8cdb133fdce14a963a92e809790cba096eaa26140550c129fa2b98c16e84236aa33bf919cd6f587e048c52666576db6e925c6cbe9b9ec5c16020f9a44c9f1c8f7a8e611c1f6ec2513ea6aa0b8d0f72fed73ca37df240db57bbb27431d618697b9e771b0b301d5df05955425061a30dc6d33bb6d2a32bd0a75a0a71d2184f506372abf84a56aeeea8eb693bf29a640345fa1298a16e85421b2208d00068a5a42915f82cf0b858c8fa39d43d704b6927e0b2f916304e86fb6a1b487f07d8139e428bb096c6d67a76ec0b8d4ef274b8a2cf556d279ad267ccef5af477afed029f485b5597739f5d0240f67c2d948a6279";
	ByteString x2 = "0caf2ef547ec49c4f3a6fe6df4223a174d01f2c115d49a6f73437c29a2a8458c";
	ByteString y2 = "2828003d7c747199143c370fdd07a2861524514acc57f63f80c38c2087c6b795b62de1c224bf8d1d1424e60ce3f5ae3f76c754a2464af292286d873a7a30b7eacbbc75aafde7191d9157598cdb0b60e0c5aa3f6ebe425500c611957dbf5ed35490714a42811fdcdeb19af2ab30beadff2907931cee7f3b55532cffaeb371f84f01347630eb227a419b1f3f558bc8a509d64a765d8987d493b007c4412c297caf41566e26faee475137ec781a0dc088a26c8804a98c23140e7c936281864b99571ee95c416aa38ceebb41fdbff1eb1d1dc97b63ce1355257627c8b0fd840ddb20ed35be92f08c49aea5613957d7e5c7a6d5a5834b4cb069e0831753ecf65ba02b";

	pubKey2->setP(p2);
	pubKey2->setQ(q2);
	pubKey2->setG(g2);
	pubKey2->setY(y2);
	privKey2->setP(p2);
	privKey2->setQ(q2);
	privKey2->setG(g2);
	privKey2->setX(x2);

	// Test with key #2
	ByteString data2 = "616263"; // "abc"
	ByteString goodSignature2 = "315c875dcd4850e948b8ac42824e9483a32d5ba5abe0681b9b9448d444f2be3c89718d12e54a8d9ed066e4a55f7ed5a2229cd23b9a3cee78f83ed6aa61f6bcb9";
	ByteString badSignature2 = "315c875dcd4850e948b8ac42824e9483a32d5ba5abe0681b9b9448d444f2be3c89718d12e54a8d9ed066e4a55f7ed5a2229cd23b9a3cee78f83ed6aa61f6bcb8";

	CPPUNIT_ASSERT(dsa->verify(pubKey1, data1, goodSignature1, AsymMech::DSA_SHA1));
	CPPUNIT_ASSERT(!dsa->verify(pubKey1, data1, badSignature1, AsymMech::DSA_SHA1));
	CPPUNIT_ASSERT(dsa->verify(pubKey2, data2, goodSignature2, AsymMech::DSA_SHA256));
	CPPUNIT_ASSERT(!dsa->verify(pubKey2, data2, badSignature2, AsymMech::DSA_SHA256));

	dsa->recyclePublicKey(pubKey1);
	dsa->recyclePublicKey(pubKey2);
	dsa->recyclePrivateKey(privKey1);
	dsa->recyclePrivateKey(privKey2);
}
