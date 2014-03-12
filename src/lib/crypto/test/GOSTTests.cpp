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
 GOSTTests.cpp

 Contains test cases to test the GOST implementations
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "GOSTTests.h"
#include "CryptoFactory.h"
#include <stdio.h>
#include "AsymmetricAlgorithm.h"
#include "AsymmetricKeyPair.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "RNG.h"
#ifdef WITH_GOST
#include "ECParameters.h"
#include "GOSTPublicKey.h"
#include "GOSTPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(GOSTTests);

void GOSTTests::setUp()
{
	hash = NULL;
	mac = NULL;
	gost = NULL;
	rng = NULL;

	gost = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::GOST);

	// Check the GOST object
	CPPUNIT_ASSERT(gost != NULL);
}

void GOSTTests::tearDown()
{
	if (hash != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
	}

	if (mac != NULL)
	{
		CryptoFactory::i()->recycleMacAlgorithm(mac);
	}

	if (gost != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
	}

	fflush(stdout);
}

void GOSTTests::testHash()
{
	char testData[4096] = "FE5A773751EAB2F18921C04806D6907444557B4469CDA7C822288E5065DA58F448A27FA0B4C8786853F246B093E3DBFDC332759D7764B6D057895184D9B82E626DF70AEB99B969EA35E5BE4D50C7406EA4A7450AC063933F96F77960EE711A445593119CF69061702CB4797F214FA440C94127E3DCD92F2C71B39D354C6F4284E030DCBFCB91EA5E543E0E3560ECD355091850BA080287BD87B74BB84A8892E0F2172F136D187305179F23EB8296BF1798405BAB52E201F22BCA5B793C5BA6F2CA15F154598EEC73E7E61B405262F6FE5FDC0F9AE0528801C3F965956C79A6C6805EDD0C6515AEA27D1DB9D70A56B0F13A544429C448FB6DB390C0E367EDF997E0B681ADE3846D77D1898F06FB60CB2384015F3749BD1E8163E532529E4D3BB8B200BBE79DA76D4865621FF2E583A1A1F8EBFB7A51B65DC9152B173A7DF91C6943F2FE497CDBC306827146199ADA925DD42B8A48429F5B6E3670AA85A44BDFAB3D273EA6711B996B5C27E04949BE61ED9ECB932F429ADCF31A2E0E9F83FCB1CE6BC0EE81627D1F9D08ECD599F16A1D68B256B002E90A8B4E5830A049ECE9ADF1D50C027EC537DD5412AA1509E91CEF358B2D495D3B37651987F51D9643A5AF2E0EF3D8C02E6023BB76FF8F1EB5CD018FA32BD7886A1A46A7D5CA15E4E0CDB793F0C1986EF4480305801A518B1D4596AAA741C093FC7AD075B637B1B2CC4DA33B6EB6D549001B33E1753C9C4358FB541FDE6541238BD011CD8ACAFB4CFF15B289872956DFBCC732593E838B6300E48ED3455CD101920114640A5B7C1250E419B7D771EC65934F53176BBD7A61A36D6D3D64A1F29C3D41745993636F812930E2936E9ED34E92A3C31239176ED3F78461EE80C54D92CBD9EF9F5746F8069809A38549FC7A8FD99FB350C27230966D6001D3136114A7BDCDEE495B72E4A633845BC88400DEDADC2FA2CD8640049CDB4F8F695C45EACF24FD573E1FB1670F688C9D7706A9AE9EB30E0DFDD54C7F3F3EE6F9BBFBBED6DB6E7C7B979E677DCD8457949DC271BD6ACB445B16247D8DAC1B59D45B8FFBBFDAEA20A5C450E0F93B399AE69887E1C721B0EF86C8CD37FC7514C4F2B70AA1E757DE95DCC3B74C6E18E51D272D433330826435B7CBA6C099558B51E408B1BFE60E876141A74195A00BF914F2536D92170FB43E078D98F784E6F150ED2B16DB5B629EBABF16444639C87A544050E03FB7CCD538DA29C45CE764F68682B48BF8AE5ED43064E833338A88605B1743FEB025D5F5607BB13A2078A99924A2D4818CD582ACDC1556FAEBA70959DE8498F3FCBF85BD269A7DF23A3AD5704908978031667C7BF4A85D1EF42F3ED144670E6EEB5D8213DB43B0B7B43767FD4277EF0EC52B5718A7D187A003DE8E5DFF9C3A3CD520615FB9B52281506E5BB033818E0912980A8BCAA54E21C5630B9E863C83";
	char testResult[512] = "3EC65819A084AD30712C4B3EB69CE130A8C7221EA3D8A9996D4BA6F298BC39F9";

	// Get a GOST R 34.11-94 hash instance
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("gost")) != NULL);

	ByteString b(testData);
	ByteString osslHash(testResult), gostHash;

	// Now recreate the hash using our implementation in a single operation
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b));
	CPPUNIT_ASSERT(hash->hashFinal(gostHash));

	CPPUNIT_ASSERT(osslHash == gostHash);

	// Now recreate the hash in a single part operation
	gostHash.wipe();

	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(hash->hashUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(hash->hashFinal(gostHash));

	CPPUNIT_ASSERT(osslHash == gostHash);

	CryptoFactory::i()->recycleHashAlgorithm(hash);

	hash = NULL;
	rng = NULL;
}

void GOSTTests::testHmac()
{
	// Get an RNG and HMAC GOST R34.11-94 instance
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
	CPPUNIT_ASSERT((mac = CryptoFactory::i()->getMacAlgorithm("hmac-gost")) != NULL);

	// Key
	char pk[] = "a_key_for_HMAC-GOST_R-34.11-94_test";
	ByteString k((unsigned char *)pk, sizeof(pk));
	SymmetricKey key;
	CPPUNIT_ASSERT(key.setKeyBits(k));

	// Generate some random input data
	ByteString b;

	CPPUNIT_ASSERT(rng->generateRandom(b, 1024));

	// Sign the MAC using our implementation in a single operation
	ByteString mResult1;

	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b));
	CPPUNIT_ASSERT(mac->signFinal(mResult1));

	// Sign the MAC in a multiple part operation
	ByteString mResult2;

	CPPUNIT_ASSERT(mac->signInit(&key));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->signUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->signFinal(mResult2));

	// Now verify the MAC using our implementation in a single operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(mac->verifyFinal(mResult2));

	// Now verify the MAC in a multiple part operation
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(0, 567)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567, 989)));
	CPPUNIT_ASSERT(mac->verifyUpdate(b.substr(567 + 989)));
	CPPUNIT_ASSERT(mac->verifyFinal(mResult1));

	// Check if bad key is refused
	mResult1[10] ^= 0x11;
	CPPUNIT_ASSERT(mac->verifyInit(&key));
	CPPUNIT_ASSERT(mac->verifyUpdate(b));
	CPPUNIT_ASSERT(!mac->verifyFinal(mResult1));

	CryptoFactory::i()->recycleMacAlgorithm(mac);

	mac = NULL;
	rng = NULL;
}

void GOSTTests::testHashKnownVector()
{
	CPPUNIT_ASSERT((hash = CryptoFactory::i()->getHashAlgorithm("gost")) != NULL);

	// Message to hash for test #1
	ByteString msg = "6d65737361676520646967657374"; // "message digest"
	ByteString expected = "bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0";
	ByteString result;

	// Test #1
	CPPUNIT_ASSERT(hash->hashInit());
	CPPUNIT_ASSERT(hash->hashUpdate(msg));
	CPPUNIT_ASSERT(hash->hashFinal(result));

	CPPUNIT_ASSERT(result == expected);

	CryptoFactory::i()->recycleHashAlgorithm(hash);
	hash = NULL;
}

void GOSTTests::testKeyGeneration()
{
	AsymmetricKeyPair* kp;

	// Set domain parameters
	ByteString curve = "06072a850302022301";
	ECParameters* p = new ECParameters;
	p->setEC(curve);

	// Generate key-pair
	CPPUNIT_ASSERT(gost->generateKeyPair(&kp, p));

	GOSTPublicKey* pub = (GOSTPublicKey*) kp->getPublicKey();
	GOSTPrivateKey* priv = (GOSTPrivateKey*) kp->getPrivateKey();

	CPPUNIT_ASSERT(pub->getQ().size() == 64);
	CPPUNIT_ASSERT(priv->getD().size() == 32);

	gost->recycleParameters(p);
	gost->recycleKeyPair(kp);
}

void GOSTTests::testSerialisation()
{
	// Get GOST R 34.10-2001 params-A domain parameters
	ECParameters* p = new ECParameters;
	p->setEC(ByteString("06072a850302022301"));

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dEC;

	CPPUNIT_ASSERT(gost->reconstructParameters(&dEC, serialisedParams));

	CPPUNIT_ASSERT(dEC->areOfType(ECParameters::type));

	ECParameters* ddEC = (ECParameters*) dEC;

	CPPUNIT_ASSERT(p->getEC() == ddEC->getEC());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(gost->generateKeyPair(&kp, dEC));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(gost->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	GOSTPrivateKey* privKey = (GOSTPrivateKey*) kp->getPrivateKey();
	GOSTPublicKey* pubKey = (GOSTPublicKey*) kp->getPublicKey();

	GOSTPrivateKey* dPrivKey = (GOSTPrivateKey*) dKP->getPrivateKey();
	GOSTPublicKey* dPubKey = (GOSTPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getD() == dPrivKey->getD());
	CPPUNIT_ASSERT(pubKey->getQ() == dPubKey->getQ());

	gost->recycleParameters(p);
	gost->recycleParameters(dEC);
	gost->recycleKeyPair(kp);
	gost->recycleKeyPair(dKP);
}

void GOSTTests::testSigningVerifying()
{
	AsymmetricKeyPair* kp;
	ECParameters *p;
	ByteString curve = "06072a850302022301";

	// Get parameters
	p = new ECParameters;
	CPPUNIT_ASSERT(p != NULL);
	p->setEC(curve);

	// Generate key-pair
	CPPUNIT_ASSERT(gost->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG* rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(gost->sign(kp->getPrivateKey(), dataToSign, sig, "gost-gost"));

	// And verify it
	CPPUNIT_ASSERT(gost->verify(kp->getPublicKey(), dataToSign, sig, "gost-gost"));

	gost->recycleKeyPair(kp);
	gost->recycleParameters(p);
}

void GOSTTests::testSignVerifyKnownVector()
{
	// TODO
}
#endif
