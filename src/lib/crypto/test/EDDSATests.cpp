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
#include "EDDSAMechanismParam.h"
#ifdef WITH_OPENSSL
#include <openssl/opensslv.h>
#endif

// Contexts and pre-hashing need OpenSSL 3.2 or later; Botan 2.X has no context support at all
#if defined(WITH_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x30200000L
	#define EDDSA_HAVE_CONTEXT	0
	#define EDDSA_HAVE_PREHASH	0
#elif defined(WITH_BOTAN)
	#define EDDSA_HAVE_CONTEXT	0
	#define EDDSA_HAVE_PREHASH	1
#else
	#define EDDSA_HAVE_CONTEXT	1
	#define EDDSA_HAVE_PREHASH	1
#endif

// Botan 2.X only supports Ed25519
#ifdef WITH_BOTAN
	#define EDDSA_HAVE_ED448	0
#else
	#define EDDSA_HAVE_ED448	1
#endif

// Curve identifiers used by the test vectors below
#define ED25519_CURVE	"06032b6570"
#define ED448_CURVE	"130a65647761726473343438"

CPPUNIT_TEST_SUITE_REGISTRATION(EDDSATests);

static const std::vector<ByteString> montCurves = {
	// x25519 [RFC 7748] per PKCS#11 3.0
	ByteString("130a63757276653235353139"),
#ifndef WITH_BOTAN
	// x448 [RFC 7748] per PKCS#11 3.0
	ByteString("13086375727665343438"),
#endif
};

static const std::vector<ByteString> montCompatCurves = {
	// x25519 [RFC 8410] -- non-standard !
	ByteString("06032b656e"),
#ifndef WITH_BOTAN
	// x448 [RFC 8410] -- non-standard !
	ByteString("06032b656f"),
#endif
};

static const std::vector<ByteString> edCurves = {
	// ed25519 [RFC 8032] per PKCS#11 3.0
	ByteString("130c656477617264733235353139"),
#ifndef WITH_BOTAN
	// ed448 [RFC 8032] per PKCS#11 3.0
	ByteString("130a65647761726473343438"),
#endif
};

static const std::vector<ByteString> edCompatCurves = {
	// ed25519 [RFC 8410] -- non-standard !
	ByteString("06032b6570"),
#ifndef WITH_BOTAN
	// ed448 [RFC 8410] -- non-standard !
	ByteString("06032b6571"),
#endif
};

static const std::vector<ByteString> allCurves = []{
	auto v = montCurves;
	v.insert(v.end(), edCurves.begin(), edCurves.end());
	return v;
}();

static const std::vector<ByteString> allCompatCurves = []{
	auto v = montCompatCurves;
	v.insert(v.end(), edCompatCurves.begin(), edCompatCurves.end());
	return v;
}();


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
	for (auto c = allCurves.begin(), cc = allCompatCurves.begin();
		c != allCurves.end() && cc != allCompatCurves.end();
		c++, cc++)
	{
		// Set domain parameters
		ECParameters* p = new ECParameters;
		p->setEC(*c);

		// Generate key-pair
		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(eddsa->generateKeyPair(&kp, p));

		EDPublicKey* pub = (EDPublicKey*) kp->getPublicKey();
		EDPrivateKey* priv = (EDPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getEC() == *c);
		CPPUNIT_ASSERT(priv->getEC() == *c);

		eddsa->recycleKeyPair(kp);

		/* Retry with compat curves: we should accept them on input */
		p->setEC(*cc);

		CPPUNIT_ASSERT(eddsa->generateKeyPair(&kp, p));

		pub = (EDPublicKey*) kp->getPublicKey();
		priv = (EDPrivateKey*) kp->getPrivateKey();

		/* But on output, we should get correctly encoded curve names */
		CPPUNIT_ASSERT(pub->getEC() == *c);
		CPPUNIT_ASSERT(priv->getEC() == *c);

		eddsa->recycleParameters(p);
		eddsa->recycleKeyPair(kp);
	}
}

void EDDSATests::testSerialisation()
{
	for (const ByteString& c : allCurves)
	{
		// Get domain parameters
		ECParameters* p = new ECParameters;
		p->setEC(c);

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
}

void EDDSATests::testPKCS8()
{
	for (const ByteString& c : allCurves)
	{
		// Get domain parameters
		ECParameters* p = new ECParameters;
		p->setEC(c);

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
}

void EDDSATests::testSigningVerifying()
{
	for (const ByteString& c : edCurves)
	{
		// Get parameters
		ECParameters* p = new ECParameters;
		CPPUNIT_ASSERT(p != NULL);
		p->setEC(c);

		// Generate key-pair
		AsymmetricKeyPair* kp;
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

void EDDSATests::testSignVerifyKnownVectorEd25519()
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

void EDDSATests::testSignVerifyKnownVectorEd448()
{
#ifndef WITH_BOTAN
	// Test vectors from RFC 8032

	EDPublicKey* pubKey1 = (EDPublicKey*) eddsa->newPublicKey();
	EDPublicKey* pubKey2 = (EDPublicKey*) eddsa->newPublicKey();
	EDPrivateKey* privKey1 = (EDPrivateKey*) eddsa->newPrivateKey();
	EDPrivateKey* privKey2 = (EDPrivateKey*) eddsa->newPrivateKey();

	// Reconstruct public and private key #1
	ByteString ec = "130a65647761726473343438"; // ed448
	ByteString k1 =
		"6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6"
		"e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
	ByteString a1 = "0439"
		"5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80"
		"e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";

	pubKey1->setEC(ec);
	pubKey1->setA(a1);
	privKey1->setEC(ec);
	privKey1->setK(k1);

	// Test with key #1
	ByteString data1; // ""
	ByteString goodSignature1 =
		"533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d4"
		"1a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"
		"ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5"
		"c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600";
	ByteString badSignature1 =
		"533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d4"
		"1a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"
		"ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5"
		"c7cdda8530a113a0f4dbb61149f05a7363268c72d95808ff2e652600";

	// Reconstruct public and private key #2
	ByteString k2 =
		"cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985"
		"083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328";
	ByteString a2 = "0439"
		"dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e93"
		"28b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400";

	pubKey2->setEC(ec);
	pubKey2->setA(a2);
	privKey2->setEC(ec);
	privKey2->setK(k2);

	// Test with key #2
	ByteString data2 = "0c3e544074ec63b0265e0c";
	ByteString goodSignature2 =
		"1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa09"
		"0a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00"
		"b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f2"
		"13fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00";
	ByteString badSignature2 =
		"1f0a8888cf25e8d458a21130879b840a9089d999aaba039eaf3e3afa09"
		"0a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00"
		"b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f2"
		"13fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00";

	CPPUNIT_ASSERT(eddsa->verify(pubKey1, data1, goodSignature1, AsymMech::EDDSA));
	CPPUNIT_ASSERT(!eddsa->verify(pubKey1, data1, badSignature1, AsymMech::EDDSA));
	CPPUNIT_ASSERT(eddsa->verify(pubKey2, data2, goodSignature2, AsymMech::EDDSA));
	CPPUNIT_ASSERT(!eddsa->verify(pubKey2, data2, badSignature2, AsymMech::EDDSA));

	eddsa->recyclePublicKey(pubKey1);
	eddsa->recyclePublicKey(pubKey2);
	eddsa->recyclePrivateKey(privKey1);
	eddsa->recyclePrivateKey(privKey2);
#endif
}

void EDDSATests::checkKnownVector(const char* ec, const char* k, const char* a, const char* msg,
				  const char* ctx, bool preHash, const char* sig)
{
	EDPublicKey* pubKey = (EDPublicKey*) eddsa->newPublicKey();
	EDPrivateKey* privKey = (EDPrivateKey*) eddsa->newPrivateKey();
	CPPUNIT_ASSERT(pubKey != NULL);
	CPPUNIT_ASSERT(privKey != NULL);

	ByteString curve = ec;
	pubKey->setEC(curve);
	pubKey->setA(ByteString(a));
	privKey->setEC(curve);
	privKey->setK(ByteString(k));

	ByteString data;
	if (msg != NULL) data = ByteString(msg);

	EDDSAMechanismParam param;
	param.prehash = preHash;
	if (ctx != NULL) param.contextData = ByteString(ctx);

	ByteString expected = sig;

	// EdDSA is deterministic, so the signature must match the test vector octet for octet
	ByteString signature;
	CPPUNIT_ASSERT(eddsa->sign(privKey, data, signature, AsymMech::EDDSA, &param));
	CPPUNIT_ASSERT(signature == expected);

	CPPUNIT_ASSERT(eddsa->verify(pubKey, data, expected, AsymMech::EDDSA, &param));

	// Flipping a single bit of the signature must break verification
	ByteString badSignature = expected;
	badSignature[0] ^= 0x01;
	CPPUNIT_ASSERT(!eddsa->verify(pubKey, data, badSignature, AsymMech::EDDSA, &param));

	eddsa->recyclePublicKey(pubKey);
	eddsa->recyclePrivateKey(privKey);
}

void EDDSATests::testSignVerifyKnownVectorEd25519ctx()
{
#if EDDSA_HAVE_CONTEXT
	// Test vectors from RFC 8032 section 7.2

	const char* k1 = "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6";
	const char* a1 = "0420dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292";
	const char* msg1 = "f726936d19c800494e3fdaff20b276a8";
	const char* ctxFoo = "666f6f"; // "foo"
	const char* ctxBar = "626172"; // "bar"

	// foo
	checkKnownVector(ED25519_CURVE, k1, a1, msg1, ctxFoo, false,
		"55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a"
		"8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d");

	// bar: same key and message, different context
	checkKnownVector(ED25519_CURVE, k1, a1, msg1, ctxBar, false,
		"fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3"
		"216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d");

	// foo2: same key and context, different message
	checkKnownVector(ED25519_CURVE, k1, a1, "508e9e6882b979fea900f62adceaca35", ctxFoo, false,
		"8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc6490"
		"8922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b");

	// foo3: different key
	checkKnownVector(ED25519_CURVE,
		"ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560",
		"04200f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772",
		msg1, ctxFoo, false,
		"21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85"
		"e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f");

	// The "foo" signature must not verify under the "bar" context
	EDPublicKey* pubKey = (EDPublicKey*) eddsa->newPublicKey();
	ByteString curve = ED25519_CURVE;
	pubKey->setEC(curve);
	pubKey->setA(ByteString(a1));

	ByteString data = msg1;
	ByteString fooSignature =
		"55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a"
		"8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d";

	EDDSAMechanismParam barParam;
	barParam.prehash = false;
	barParam.contextData = ByteString(ctxBar);
	CPPUNIT_ASSERT(!eddsa->verify(pubKey, data, fooSignature, AsymMech::EDDSA, &barParam));

	// Nor without any context at all
	EDDSAMechanismParam pureParam;
	pureParam.prehash = false;
	CPPUNIT_ASSERT(!eddsa->verify(pubKey, data, fooSignature, AsymMech::EDDSA, &pureParam));

	eddsa->recyclePublicKey(pubKey);
#endif
}

void EDDSATests::testSignVerifyKnownVectorEd25519ph()
{
#if EDDSA_HAVE_PREHASH
	// Test vector from RFC 8032 section 7.3

	const char* k = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
	const char* a = "0420ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
	const char* msg = "616263"; // "abc"
	const char* sig =
		"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
		"31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";

	checkKnownVector(ED25519_CURVE, k, a, msg, NULL, true, sig);

	// The pre-hashed signature must not verify as a pure Ed25519 signature
	EDPublicKey* pubKey = (EDPublicKey*) eddsa->newPublicKey();
	ByteString curve = ED25519_CURVE;
	pubKey->setEC(curve);
	pubKey->setA(ByteString(a));

	ByteString data = msg;
	ByteString signature = sig;

	EDDSAMechanismParam pureParam;
	pureParam.prehash = false;
	CPPUNIT_ASSERT(!eddsa->verify(pubKey, data, signature, AsymMech::EDDSA, &pureParam));

	eddsa->recyclePublicKey(pubKey);
#endif
}

void EDDSATests::testSignVerifyKnownVectorEd448ctx()
{
#if EDDSA_HAVE_ED448 && EDDSA_HAVE_CONTEXT
	// Test vector "1 octet (with context)" from RFC 8032 section 7.4

	const char* k = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
			"fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e";
	const char* a = "0439"
			"43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
			"6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480";
	const char* msg = "03";
	const char* sig =
		"d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2"
		"151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da"
		"1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d"
		"5428407e85dcbc98a49155c13764e66c3c00";

	checkKnownVector(ED448_CURVE, k, a, msg, "666f6f", false, sig);

	// The same signature must not verify without the context
	EDPublicKey* pubKey = (EDPublicKey*) eddsa->newPublicKey();
	ByteString curve = ED448_CURVE;
	pubKey->setEC(curve);
	pubKey->setA(ByteString(a));

	ByteString data = msg;
	ByteString signature = sig;

	EDDSAMechanismParam pureParam;
	pureParam.prehash = false;
	CPPUNIT_ASSERT(!eddsa->verify(pubKey, data, signature, AsymMech::EDDSA, &pureParam));

	eddsa->recyclePublicKey(pubKey);
#endif
}

void EDDSATests::testSignVerifyKnownVectorEd448ph()
{
#if EDDSA_HAVE_ED448 && EDDSA_HAVE_PREHASH
	// Test vectors from RFC 8032 section 7.5

	const char* k = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
			"ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49";
	const char* a = "0439"
			"259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743"
			"c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880";
	const char* msg = "616263"; // "abc"

	checkKnownVector(ED448_CURVE, k, a, msg, NULL, true,
		"822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae38"
		"1f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd"
		"433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3"
		"ad203df7dc7ce360c3cd3696d9d9fab90f00");

#if EDDSA_HAVE_CONTEXT
	checkKnownVector(ED448_CURVE, k, a, msg, "666f6f", true,
		"c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa48"
		"1065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3"
		"653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab7128"
		"4f8d0704a608c54a6b62d97beb511d132100");
#endif
#endif
}

void EDDSATests::testDerivation()
{
	for (const ByteString& c : montCurves)
	{
		// Get parameters
		ECParameters* p = new ECParameters;
		CPPUNIT_ASSERT(p != NULL);
		p->setEC(c);

		// Generate key-pairs
		AsymmetricKeyPair* kpa;
		CPPUNIT_ASSERT(eddsa->generateKeyPair(&kpa, p));
		AsymmetricKeyPair* kpb;
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

void EDDSATests::testDeriveKnownVectorX25519()
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

void EDDSATests::testDeriveKnownVectorX448()
{
#ifndef WITH_BOTAN
	// Test vectors from RFC 7748

	EDPublicKey* pubKeya = (EDPublicKey*) eddsa->newPublicKey();
	EDPublicKey* pubKeyb = (EDPublicKey*) eddsa->newPublicKey();
	EDPrivateKey* privKeya = (EDPrivateKey*) eddsa->newPrivateKey();
	EDPrivateKey* privKeyb = (EDPrivateKey*) eddsa->newPrivateKey();

	// Reconstruct public and private key for Alice
	ByteString ec = "13086375727665343438"; // x448
	ByteString ka =
		"9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
		"d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
	ByteString aa = "0438"
		"9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
		"22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";

	pubKeya->setEC(ec);
	pubKeya->setA(aa);
	privKeya->setEC(ec);
	privKeya->setK(ka);

	// Reconstruct public and private key for Bob
	ByteString kb =
		"1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
		"6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
	ByteString ab = "0438"
		"3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
		"27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";

	pubKeyb->setEC(ec);
	pubKeyb->setA(ab);
	privKeyb->setEC(ec);
	privKeyb->setK(kb);

	// Test
	ByteString expected =
		"07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
		"b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";
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
#endif
}
#endif
