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
 RSATests.cpp

 Contains test cases to test the RNG class
 *****************************************************************************/

#include <stdlib.h>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "RSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(RSATests);

void RSATests::setUp()
{
	rsa = NULL;

	rsa = CryptoFactory::i()->getAsymmetricAlgorithm("RSA");

	// Check the RSA object
	CPPUNIT_ASSERT(rsa != NULL);
}

void RSATests::tearDown()
{
	if (rsa != NULL)
	{
		delete rsa;
	}

	fflush(stdout);
}

void RSATests::testKeyGeneration()
{
	AsymmetricKeyPair* kp;
	RSAParameters p;

	// Public exponents to test
	std::vector<ByteString> exponents;
	exponents.push_back("010001");
	exponents.push_back("03");
	exponents.push_back("0B");
	exponents.push_back("11");

	// Key sizes to test
	std::vector<size_t> keySizes;
	keySizes.push_back(1024);
	keySizes.push_back(1280);
	keySizes.push_back(2048);
	//keySizes.push_back(4096);

	for (std::vector<ByteString>::iterator e = exponents.begin(); e != exponents.end(); e++)
	{
		for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
		{
			setRSAParameters(p, *e);
		
			// Generate key-pair
			CPPUNIT_ASSERT(rsa->generateKeyPair(&kp, *k, &p));
		
			RSAPublicKey* pub = (RSAPublicKey*) kp->getPublicKey();
			RSAPrivateKey* priv = (RSAPrivateKey*) kp->getPrivateKey();
		
			CPPUNIT_ASSERT(pub->getN().size() == (*k/8));
			CPPUNIT_ASSERT(priv->getN().size() == (*k/8));
			CPPUNIT_ASSERT(pub->getE() == *e);
			CPPUNIT_ASSERT(priv->getE() == *e);
		
			delete kp;
		}
	}
}

void RSATests::testSerialisation()
{
	// Generate a 1024-bit key-pair for testing
	AsymmetricKeyPair* kp;
	RSAParameters p;

	setRSAParameters(p, "010001"); // Exponent F4

	CPPUNIT_ASSERT(rsa->generateKeyPair(&kp, 1024, &p));
	CPPUNIT_ASSERT(kp != NULL);

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	CPPUNIT_ASSERT(serialisedKP.size() != 0);

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(rsa->reconstructKeyPair(&dKP, serialisedKP));
	CPPUNIT_ASSERT(serialisedKP.size() == 0);
	CPPUNIT_ASSERT(dKP != NULL);

	RSAPublicKey* pub = (RSAPublicKey*) kp->getPublicKey();
	RSAPrivateKey* priv = (RSAPrivateKey*) kp->getPrivateKey();

	RSAPublicKey* dPub = (RSAPublicKey*) dKP->getPublicKey();
	RSAPrivateKey* dPriv = (RSAPrivateKey*) dKP->getPrivateKey();

	CPPUNIT_ASSERT(pub->getN() == dPub->getN());
	CPPUNIT_ASSERT(pub->getE() == dPub->getE());

	CPPUNIT_ASSERT(priv->getP() == dPriv->getP());
	CPPUNIT_ASSERT(priv->getQ() == dPriv->getQ());
	CPPUNIT_ASSERT(priv->getPQ() == dPriv->getPQ());
	CPPUNIT_ASSERT(priv->getDP1() == dPriv->getDP1());
	CPPUNIT_ASSERT(priv->getDQ1() == dPriv->getDQ1());
	CPPUNIT_ASSERT(priv->getD() == dPriv->getD());
	CPPUNIT_ASSERT(priv->getN() == dPriv->getN());
	CPPUNIT_ASSERT(priv->getE() == dPriv->getE());

	// Serialise and deserialise the public key
	ByteString serialisedPub = pub->serialise();

	RSAPublicKey* desPub;

	CPPUNIT_ASSERT(rsa->reconstructPublicKey((PublicKey**) &desPub, serialisedPub));
	CPPUNIT_ASSERT(serialisedPub.size() == 0);
	CPPUNIT_ASSERT(desPub != NULL);

	CPPUNIT_ASSERT(pub->getN() == desPub->getN());
	CPPUNIT_ASSERT(pub->getE() == desPub->getE());

	// Serialise and deserialise the private key
	ByteString serialisedPriv = priv->serialise();

	RSAPrivateKey* desPriv;

	CPPUNIT_ASSERT(rsa->reconstructPrivateKey((PrivateKey**) &desPriv, serialisedPriv));
	CPPUNIT_ASSERT(serialisedPriv.size() == 0);
	CPPUNIT_ASSERT(desPriv != NULL);

	CPPUNIT_ASSERT(priv->getP() == desPriv->getP());
	CPPUNIT_ASSERT(priv->getQ() == desPriv->getQ());
	CPPUNIT_ASSERT(priv->getPQ() == desPriv->getPQ());
	CPPUNIT_ASSERT(priv->getDP1() == desPriv->getDP1());
	CPPUNIT_ASSERT(priv->getDQ1() == desPriv->getDQ1());
	CPPUNIT_ASSERT(priv->getD() == desPriv->getD());
	CPPUNIT_ASSERT(priv->getN() == desPriv->getN());
	CPPUNIT_ASSERT(priv->getE() == desPriv->getE());

	delete kp;
	delete dKP;
	delete desPub;
	delete desPriv;
}

