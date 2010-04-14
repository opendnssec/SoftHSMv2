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
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
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
			p.setE(*e);
			p.setBitLength(*k);	
		
			// Generate key-pair
			CPPUNIT_ASSERT(rsa->generateKeyPair(&kp, &p));
		
			RSAPublicKey* pub = (RSAPublicKey*) kp->getPublicKey();
			RSAPrivateKey* priv = (RSAPrivateKey*) kp->getPrivateKey();
		
			CPPUNIT_ASSERT(pub->getN().size() == (*k/8));
			CPPUNIT_ASSERT(priv->getN().size() == (*k/8));
			CPPUNIT_ASSERT(pub->getE() == *e);
			CPPUNIT_ASSERT(priv->getE() == *e);
		
			rsa->recycleKeyPair(kp);
		}
	}
}

void RSATests::testSerialisation()
{
	// Generate a 1024-bit key-pair for testing
	AsymmetricKeyPair* kp;
	RSAParameters p;

	p.setE("010001");
	p.setBitLength(1024);	

	CPPUNIT_ASSERT(rsa->generateKeyPair(&kp, &p));
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

	rsa->recycleKeyPair(kp);
	rsa->recycleKeyPair(dKP);
	rsa->recyclePublicKey(desPub);
	rsa->recyclePrivateKey(desPriv);
}

void RSATests::testSigningVerifying()
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

	// Mechanisms to test
	std::vector<const char*> mechanisms;
	mechanisms.push_back("rsa-md5-pkcs");
	mechanisms.push_back("rsa-sha1-pkcs");
	mechanisms.push_back("rsa-sha256-pkcs");
	mechanisms.push_back("rsa-sha512-pkcs");
	mechanisms.push_back("rsa-ssl");

	for (std::vector<ByteString>::iterator e = exponents.begin(); e != exponents.end(); e++)
	{
		for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
		{
			p.setE(*e);
			p.setBitLength(*k);	

			// Generate key-pair
			CPPUNIT_ASSERT(rsa->generateKeyPair(&kp, &p));
	
			// Generate some data to sign
			ByteString dataToSign;

			RNG* rng = CryptoFactory::i()->getRNG();

			CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

			for (std::vector<const char*>::iterator m = mechanisms.begin(); m != mechanisms.end(); m++)
			{
				ByteString blockSignature, singlePartSignature;

				// Sign the data in blocks
				CPPUNIT_ASSERT(rsa->signInit(kp->getPrivateKey(), *m));
				CPPUNIT_ASSERT(rsa->signUpdate(dataToSign.substr(0, 134)));
				CPPUNIT_ASSERT(rsa->signUpdate(dataToSign.substr(134, 289)));
				CPPUNIT_ASSERT(rsa->signUpdate(dataToSign.substr(134 + 289)));
				CPPUNIT_ASSERT(rsa->signFinal(blockSignature));

				// Sign the data in one pass
				CPPUNIT_ASSERT(rsa->sign(kp->getPrivateKey(), dataToSign, singlePartSignature, *m));

				// If it is not a PSS signature, check if the two signatures match
				if (strstr(*m, "pss") == NULL)
				{
					// Check if the two signatures match
					CPPUNIT_ASSERT(blockSignature == singlePartSignature);
				}

				// Now perform multi-pass verification
				CPPUNIT_ASSERT(rsa->verifyInit(kp->getPublicKey(), *m));
				CPPUNIT_ASSERT(rsa->verifyUpdate(dataToSign.substr(0, 125)));
				CPPUNIT_ASSERT(rsa->verifyUpdate(dataToSign.substr(125, 247)));
				CPPUNIT_ASSERT(rsa->verifyUpdate(dataToSign.substr(125 + 247)));
				CPPUNIT_ASSERT(rsa->verifyFinal(blockSignature));

				// And single-pass verification
				CPPUNIT_ASSERT(rsa->verify(kp->getPublicKey(), dataToSign, singlePartSignature, *m));
			}
	
			CryptoFactory::i()->recycleRNG(rng);
			rsa->recycleKeyPair(kp);
		}
	}
}

void RSATests::testSignVerifyKnownVector()
{
	// These test vectors were taken from the Crypto++ set of test vectors
	// Crypto++ can be downloaded from www.cryptopp.com

	RSAPublicKey* pubKey1 = (RSAPublicKey*) rsa->newPublicKey();
	RSAPublicKey* pubKey2 = (RSAPublicKey*) rsa->newPublicKey();
	RSAPrivateKey* privKey1_1 = (RSAPrivateKey*) rsa->newPrivateKey();
	RSAPrivateKey* privKey1_2 = (RSAPrivateKey*) rsa->newPrivateKey();
	RSAPrivateKey* privKey2_1 = (RSAPrivateKey*) rsa->newPrivateKey();
	RSAPrivateKey* privKey2_2 = (RSAPrivateKey*) rsa->newPrivateKey();

	// Reconstruct public and private key #1
	ByteString n1	= "0A66791DC6988168DE7AB77419BB7FB0C001C62710270075142942E19A8D8C51D053B3E3782A1DE5DC5AF4EBE99468170114A1DFE67CDC9A9AF55D655620BBAB";
	ByteString e1	= "010001";
	ByteString d1	= "0123C5B61BA36EDB1D3679904199A89EA80C09B9122E1400C09ADCF7784676D01D23356A7D44D6BD8BD50E94BFC723FA87D8862B75177691C11D757692DF8881";
	ByteString p1	= "33D48445C859E52340DE704BCDDA065FBB4058D740BD1D67D29E9C146C11CF61";
	ByteString q1	= "335E8408866B0FD38DC7002D3F972C67389A65D5D8306566D5C4F2A5AA52628B";
	ByteString dp11	= "045EC90071525325D3D46DB79695E9AFACC4523964360E02B119BAA366316241";
	ByteString dq11	= "15EB327360C7B60D12E5E2D16BDCD97981D17FBA6B70DB13B20B436E24EADA59";
	ByteString pq1	= "2CA6366D72781DFA24D34A9A24CBC2AE927A9958AF426563FF63FB11658A461D";

	pubKey1->setN(n1);
	pubKey1->setE(e1);
	privKey1_1->setN(n1);
	privKey1_1->setE(e1);
	privKey1_1->setD(d1);
	privKey1_1->setP(p1);
	privKey1_1->setQ(q1);
	privKey1_1->setDP1(dp11);
	privKey1_1->setDQ1(dq11);
	privKey1_1->setPQ(pq1);

	// The same key but without CRT factors
	privKey1_2->setN(n1);
	privKey1_2->setE(e1);
	privKey1_2->setD(d1);

	// Reconstruct public and private key #2
	ByteString n2	= "A885B6F851A8079AB8A281DB0297148511EE0D8C07C0D4AE6D6FED461488E0D41E3FF8F281B06A3240B5007A5C2AB4FB6BE8AF88F119DB998368DDDC9710ABED";
	ByteString e2	= "010001";
	ByteString d2	= "2B259D2CA3DF851EE891F6F4678BDDFD9A131C95D3305C63D2723B4A5B9C960F5EC8BB7DCDDBEBD8B6A38767D64AD451E9383E0891E4EE7506100481F2B49323";
	ByteString p2	= "D7103CD676E39824E2BE50B8E6533FE7CB7484348E283802AD2B8D00C80D19DF";
	ByteString q2	= "C89996DC169CEB3F227958275968804D4BE9FC4012C3219662F1A438C9950BB3";
	ByteString dp12	= "5D8EA4C8AF83A70634D5920C3DB66D908AC3AF57A597FD75BC9BBB856181C185";
	ByteString dq12	= "C598E54DAEC8ABC1E907769A6C2BD01653ED0C9960E1EDB7E186FDA922883A99";
	ByteString pq2	= "7C6F27B5B51B78AD80FB36E700990CF307866F2943124CBD93D97C137794C104";

	pubKey2->setN(n2);
	pubKey2->setE(e2);
	privKey2_1->setN(n2);
	privKey2_1->setE(e2);
	privKey2_1->setD(d2);
	privKey2_1->setP(p2);
	privKey2_1->setQ(q2);
	privKey2_1->setDP1(dp12);
	privKey2_1->setDQ1(dq12);
	privKey2_1->setPQ(pq2);

	// The same key but without CRT factors
	privKey2_2->setN(n2);
	privKey2_2->setE(e2);
	privKey2_2->setD(d2);

	// Test with key #1
	const char* testValue1 = "Everyone gets Friday off.";

	ByteString dataToSign1((const unsigned char*) testValue1, strlen(testValue1));

	ByteString expectedSignature1 = "0610761F95FFD1B8F29DA34212947EC2AA0E358866A722F03CC3C41487ADC604A48FF54F5C6BEDB9FB7BD59F82D6E55D8F3174BA361B2214B2D74E8825E04E81";
	ByteString signature1_1;
	ByteString signature1_2;

	CPPUNIT_ASSERT(rsa->signInit(privKey1_1, "rsa-sha1-pkcs"));
	CPPUNIT_ASSERT(rsa->signUpdate(dataToSign1));
	CPPUNIT_ASSERT(rsa->signFinal(signature1_1));

	CPPUNIT_ASSERT(rsa->signInit(privKey1_2, "rsa-sha1-pkcs"));
	CPPUNIT_ASSERT(rsa->signUpdate(dataToSign1));
	CPPUNIT_ASSERT(rsa->signFinal(signature1_2));

	CPPUNIT_ASSERT(signature1_1 == signature1_2);
	CPPUNIT_ASSERT(signature1_1 == expectedSignature1);

	CPPUNIT_ASSERT(rsa->verifyInit(pubKey1, "rsa-sha1-pkcs"));
	CPPUNIT_ASSERT(rsa->verifyUpdate(dataToSign1));
	CPPUNIT_ASSERT(rsa->verifyFinal(expectedSignature1));

	// Test with key #2
	const char* testValue2 = "test";

	ByteString dataToSign2((const unsigned char*) testValue2, strlen(testValue2));

	ByteString expectedSignature2 = "A7E00CE4391F914D82158D9B732759808E25A1C6383FE87A5199157650D4296CF612E9FF809E686A0AF328238306E79965F6D0138138829D9A1A22764306F6CE";
	ByteString signature2_1;
	ByteString signature2_2;

	CPPUNIT_ASSERT(rsa->signInit(privKey2_1, "rsa-sha1-pkcs"));
	CPPUNIT_ASSERT(rsa->signUpdate(dataToSign2));
	CPPUNIT_ASSERT(rsa->signFinal(signature2_1));

	CPPUNIT_ASSERT(rsa->signInit(privKey2_2, "rsa-sha1-pkcs"));
	CPPUNIT_ASSERT(rsa->signUpdate(dataToSign2));
	CPPUNIT_ASSERT(rsa->signFinal(signature2_2));

	CPPUNIT_ASSERT(signature2_1 == signature2_2);
	CPPUNIT_ASSERT(signature2_1 == expectedSignature2);

	CPPUNIT_ASSERT(rsa->verifyInit(pubKey2, "rsa-sha1-pkcs"));
	CPPUNIT_ASSERT(rsa->verifyUpdate(dataToSign2));
	CPPUNIT_ASSERT(rsa->verifyFinal(expectedSignature2));

	rsa->recyclePublicKey(pubKey1);
	rsa->recyclePublicKey(pubKey2);
	rsa->recyclePrivateKey(privKey1_1);
	rsa->recyclePrivateKey(privKey1_2);
	rsa->recyclePrivateKey(privKey2_1);
	rsa->recyclePrivateKey(privKey2_2);
}

void RSATests::testEncryptDecrypt()
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

	// Paddings to test
	std::vector<const char*> paddings;
	paddings.push_back("rsa-pkcs");
	paddings.push_back("rsa-pkcs-oaep");
	paddings.push_back("rsa-raw");

	for (std::vector<ByteString>::iterator e = exponents.begin(); e != exponents.end(); e++)
	{
		for (std::vector<size_t>::iterator k = keySizes.begin(); k != keySizes.end(); k++)
		{
			p.setE(*e);
			p.setBitLength(*k);	

			// Generate key-pair
			CPPUNIT_ASSERT(rsa->generateKeyPair(&kp, &p));
	
			RNG* rng = CryptoFactory::i()->getRNG();

			for (std::vector<const char*>::iterator pad = paddings.begin(); pad != paddings.end(); pad++)
			{
				// Generate some test data to encrypt based on the selected padding
				ByteString testData;

				if (!strcmp(*pad, "rsa-pkcs"))
				{
					CPPUNIT_ASSERT(rng->generateRandom(testData, (*k >> 3) - 12));
				}
				else if (!strcmp(*pad, "rsa-pkcs-oaep"))
				{
					CPPUNIT_ASSERT(rng->generateRandom(testData, (*k >> 3) - 42));
				}
				else if (!strcmp(*pad, "rsa-raw"))
				{
					CPPUNIT_ASSERT(rng->generateRandom(testData, *k >> 3));
					testData[0] &= 0x0F;
				}
				else
				{
					CPPUNIT_ASSERT(true == false);
				}

				// Encrypt the data
				ByteString encryptedData;

				CPPUNIT_ASSERT(rsa->encrypt(kp->getPublicKey(), testData, encryptedData, *pad));

				// The encrypted data length should equal the modulus length
				CPPUNIT_ASSERT(encryptedData.size() == (*k >> 3));
				CPPUNIT_ASSERT(encryptedData != testData);

				// Now decrypt the data
				ByteString decryptedData;

				CPPUNIT_ASSERT(rsa->decrypt(kp->getPrivateKey(), encryptedData, decryptedData, *pad));

				// Check that the data was properly decrypted
				CPPUNIT_ASSERT(decryptedData == testData);
			}
			
			CryptoFactory::i()->recycleRNG(rng);
			rsa->recycleKeyPair(kp);
		}
	}
}

