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
 AESTests.cpp

 Contains test cases to test the AES implementation
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "AESTests.h"
#include "CryptoFactory.h"
#include "AESKey.h"
#include <stdio.h>

CPPUNIT_TEST_SUITE_REGISTRATION(AESTests);

void AESTests::setUp()
{
	aes = NULL;

	aes = CryptoFactory::i()->getSymmetricAlgorithm("aes");

	// Check the return value
	CPPUNIT_ASSERT(aes != NULL);
}

void AESTests::tearDown()
{
	if (aes != NULL)
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
	}

	fflush(stdout);
}

void AESTests::testCBC()
{
	char testKeys128[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"89436760984679018453504364534464",
		"49587346983643545706904580436731"
	};

	char testKeys192[][49] =
	{
		"000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101213141516171819",
		"404142434445464748494A4B4C4D4E4F5051525354555657",
		"096874395874290867409857496743857632098479834634",
		"439867439058743095864395348375043296845094854983"
	};
	
	char testKeys256[][65] =
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"4394398576098257436095746985679043867498572406874967416846341641",
		"4369006859867098670492857409386741095643756930847023587048579014"
	};

	char testData[][256] =
	{
		"4938673409687134684698438657403986439058740935874395813968496846",
		"549813644389670948567490687546098245665626527788",
		"64398769586792586795867965624526",
		"468376458463264536"
	};

	char testIV[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"69836472094875029486750948672066",
		"48670943876904867104398574908554"
	};

	for (int i = 0; i < 5; i++)
	{
		char commandLine[2048];

		ByteString keyData128(testKeys128[i]);
		ByteString keyData192(testKeys192[i]);
		ByteString keyData256(testKeys256[i]);

		AESKey aesKey128(128);
		CPPUNIT_ASSERT(aesKey128.setKeyBits(keyData128));
		AESKey aesKey192(192);
		CPPUNIT_ASSERT(aesKey192.setKeyBits(keyData192));
		AESKey aesKey256(256);
		CPPUNIT_ASSERT(aesKey256.setKeyBits(keyData256));

		ByteString IV(testIV[i]);

		for (int j = 0; j < 4; j++)
		{
			ByteString plainText(testData[j]), shsmPlainText;
			ByteString cipherText;
			ByteString shsmCipherText, OB;

			// Test 128-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl aes-128-cbc -in shsmv2-aestest.tmp -out shsmv2-aestest-out.tmp -K %s -iv %s",
				testKeys128[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our AES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(aes->encryptInit(&aesKey128, "cbc", IV));

			CPPUNIT_ASSERT(aes->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(aes->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Check that we can get the plain text
			shsmPlainText.wipe(); 
			CPPUNIT_ASSERT(aes->decryptInit(&aesKey128, "cbc", IV));

			CPPUNIT_ASSERT(aes->decryptUpdate(shsmCipherText, OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(aes->decryptFinal(OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(shsmPlainText == plainText);

			// Test 192-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl aes-192-cbc -in shsmv2-aestest.tmp -out shsmv2-aestest-out.tmp -K %s -iv %s",
				testKeys192[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our AES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(aes->encryptInit(&aesKey192, "cbc", IV));

			CPPUNIT_ASSERT(aes->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(aes->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Check that we can get the plain text
			shsmPlainText.wipe(); 
			CPPUNIT_ASSERT(aes->decryptInit(&aesKey192, "cbc", IV));

			CPPUNIT_ASSERT(aes->decryptUpdate(shsmCipherText, OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(aes->decryptFinal(OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(shsmPlainText == plainText);

			// Test 256-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl aes-256-cbc -in shsmv2-aestest.tmp -out shsmv2-aestest-out.tmp -K %s -iv %s",
				testKeys256[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our AES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(aes->encryptInit(&aesKey256, "cbc", IV));

			CPPUNIT_ASSERT(aes->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(aes->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Check that we can get the plain text
			shsmPlainText.wipe(); 
			CPPUNIT_ASSERT(aes->decryptInit(&aesKey256, "cbc", IV));

			CPPUNIT_ASSERT(aes->decryptUpdate(shsmCipherText, OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(aes->decryptFinal(OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(shsmPlainText == plainText);
		}
	}
}

void AESTests::testECB()
{
	char testKeys128[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"89436760984679018453504364534464",
		"49587346983643545706904580436731"
	};

	char testKeys192[][49] =
	{
		"000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101213141516171819",
		"404142434445464748494A4B4C4D4E4F5051525354555657",
		"096874395874290867409857496743857632098479834634",
		"439867439058743095864395348375043296845094854983"
	};
	
	char testKeys256[][65] =
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"4394398576098257436095746985679043867498572406874967416846341641",
		"4369006859867098670492857409386741095643756930847023587048579014"
	};

	char testData[][256] =
	{
		"4938673409687134684698438657403986439058740935874395813968496846",
		"549813644389670948567490687546098245665626527788",
		"64398769586792586795867965624526",
		"468376458463264536"
	};

	char testIV[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"69836472094875029486750948672066",
		"48670943876904867104398574908554"
	};

	for (int i = 0; i < 5; i++)
	{
		char commandLine[2048];

		ByteString keyData128(testKeys128[i]);
		ByteString keyData192(testKeys192[i]);
		ByteString keyData256(testKeys256[i]);

		AESKey aesKey128(128);
		CPPUNIT_ASSERT(aesKey128.setKeyBits(keyData128));
		AESKey aesKey192(192);
		CPPUNIT_ASSERT(aesKey192.setKeyBits(keyData192));
		AESKey aesKey256(256);
		CPPUNIT_ASSERT(aesKey256.setKeyBits(keyData256));

		ByteString IV(testIV[i]);

		for (int j = 0; j < 4; j++)
		{
			ByteString plainText(testData[j]), shsmPlainText;
			ByteString cipherText;
			ByteString shsmCipherText, OB;

			// Test 128-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl aes-128-ecb -in shsmv2-aestest.tmp -out shsmv2-aestest-out.tmp -K %s -iv %s",
				testKeys128[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our AES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(aes->encryptInit(&aesKey128, "ecb", IV));

			CPPUNIT_ASSERT(aes->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(aes->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Check that we can get the plain text
			shsmPlainText.wipe(); 
			CPPUNIT_ASSERT(aes->decryptInit(&aesKey128, "ecb", IV));

			CPPUNIT_ASSERT(aes->decryptUpdate(shsmCipherText, OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(aes->decryptFinal(OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(shsmPlainText == plainText);

			// Test 192-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl aes-192-ecb -in shsmv2-aestest.tmp -out shsmv2-aestest-out.tmp -K %s -iv %s",
				testKeys192[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our AES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(aes->encryptInit(&aesKey192, "ecb", IV));

			CPPUNIT_ASSERT(aes->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(aes->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Check that we can get the plain text
			shsmPlainText.wipe(); 
			CPPUNIT_ASSERT(aes->decryptInit(&aesKey192, "ecb", IV));

			CPPUNIT_ASSERT(aes->decryptUpdate(shsmCipherText, OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(aes->decryptFinal(OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(shsmPlainText == plainText);

			// Test 256-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl aes-256-ecb -in shsmv2-aestest.tmp -out shsmv2-aestest-out.tmp -K %s -iv %s",
				testKeys256[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our AES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(aes->encryptInit(&aesKey256, "ecb", IV));

			CPPUNIT_ASSERT(aes->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(aes->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Check that we can get the plain text
			shsmPlainText.wipe(); 
			CPPUNIT_ASSERT(aes->decryptInit(&aesKey256, "ecb", IV));

			CPPUNIT_ASSERT(aes->decryptUpdate(shsmCipherText, OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(aes->decryptFinal(OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(shsmPlainText == plainText);
		}
	}
}

void AESTests::writeTmpFile(ByteString& data)
{
	FILE* out = fopen("shsmv2-aestest.tmp", "w");
	CPPUNIT_ASSERT(out != NULL);

	CPPUNIT_ASSERT(fwrite(&data[0], 1, data.size(), out) == data.size());
	CPPUNIT_ASSERT(!fclose(out));
}

void AESTests::readTmpFile(ByteString& data)
{
	unsigned char buf[256];

	data.wipe();

	FILE* in = fopen("shsmv2-aestest-out.tmp", "r");
	CPPUNIT_ASSERT(in != NULL);

	int read = 0;

	do
	{
		read = fread(buf, 1, 256, in);

		data += ByteString(buf, read);
	}
	while (read > 0);

	CPPUNIT_ASSERT(read == 0);
	CPPUNIT_ASSERT(!fclose(in));
}

