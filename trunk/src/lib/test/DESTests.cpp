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
 DESTests.cpp

 Contains test cases to test the DES implementation
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "DESTests.h"
#include "CryptoFactory.h"
#include "DESKey.h"
#include <stdio.h>

CPPUNIT_TEST_SUITE_REGISTRATION(DESTests);

void DESTests::setUp()
{
	des = NULL;

	des = CryptoFactory::i()->getSymmetricAlgorithm("des");

	// Check the return value
	CPPUNIT_ASSERT(des != NULL);
}

void DESTests::tearDown()
{
	if (des != NULL)
	{
		delete des;
	}
}

void DESTests::testCBC()
{
	char testKeys56[][17] =
	{
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4698436794236871",
		"0940278947239572"
	};

	char testKeys112[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"64398647034486943598534703463870",
		"87406984068406984607412103517413"
	};
	
	char testKeys168[][49] =
	{
		"000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101112131415161718",
		"404142434445464748494A4B4C4D4E4F5051525354555657",
		"643906874509874309687459084769847562436043696747",
		"430135460496813044639085714376487549490586439575"
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
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4693867334098764",
		"6209876098547207"
	};

	for (int i = 0; i < 5; i++)
	{
		char commandLine[2048];

		ByteString keyData56(testKeys56[i]);
		CPPUNIT_ASSERT(keyData56.size() == 8);
		ByteString keyData112(testKeys112[i]);
		CPPUNIT_ASSERT(keyData112.size() == 16);
		ByteString keyData168(testKeys168[i]);
		CPPUNIT_ASSERT(keyData168.size() == 24);

		DESKey desKey56(56);
		CPPUNIT_ASSERT(desKey56.setKeyBits(keyData56));
		DESKey desKey112(112);
		CPPUNIT_ASSERT(desKey112.setKeyBits(keyData112));
		DESKey desKey168(168);
		CPPUNIT_ASSERT(desKey168.setKeyBits(keyData168));

		ByteString IV(testIV[i]);

		for (int j = 0; j < 4; j++)
		{
			ByteString plainText(testData[j]);
			ByteString cipherText;
			ByteString shsmCipherText, OB;

			// Test 56-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-cbc -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys56[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey56, "cbc", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 112-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede-cbc -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys112[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey112, "cbc", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 168-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede3-cbc -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys168[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey168, "cbc", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);
		}
	}
}

void DESTests::testECB()
{
	char testKeys56[][17] =
	{
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4698436794236871",
		"0940278947239572"
	};

	char testKeys112[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"64398647034486943598534703463870",
		"87406984068406984607412103517413"
	};
	
	char testKeys168[][49] =
	{
		"000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101112131415161718",
		"404142434445464748494A4B4C4D4E4F5051525354555657",
		"643906874509874309687459084769847562436043696747",
		"430135460496813044639085714376487549490586439575"
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
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4693867334098764",
		"6209876098547207"
	};

	for (int i = 0; i < 5; i++)
	{
		char commandLine[2048];

		ByteString keyData56(testKeys56[i]);
		CPPUNIT_ASSERT(keyData56.size() == 8);
		ByteString keyData112(testKeys112[i]);
		CPPUNIT_ASSERT(keyData112.size() == 16);
		ByteString keyData168(testKeys168[i]);
		CPPUNIT_ASSERT(keyData168.size() == 24);

		DESKey desKey56(56);
		CPPUNIT_ASSERT(desKey56.setKeyBits(keyData56));
		DESKey desKey112(112);
		CPPUNIT_ASSERT(desKey112.setKeyBits(keyData112));
		DESKey desKey168(168);
		CPPUNIT_ASSERT(desKey168.setKeyBits(keyData168));

		ByteString IV(testIV[i]);

		for (int j = 0; j < 4; j++)
		{
			ByteString plainText(testData[j]);
			ByteString cipherText;
			ByteString shsmCipherText, OB;

			// Test 56-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ecb -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys56[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey56, "ecb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 112-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys112[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey112, "ecb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 168-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede3 -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys168[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey168, "ecb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);
		}
	}
}

void DESTests::testOFB()
{
	char testKeys56[][17] =
	{
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4698436794236871",
		"0940278947239572"
	};

	char testKeys112[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"64398647034486943598534703463870",
		"87406984068406984607412103517413"
	};
	
	char testKeys168[][49] =
	{
		"000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101112131415161718",
		"404142434445464748494A4B4C4D4E4F5051525354555657",
		"643906874509874309687459084769847562436043696747",
		"430135460496813044639085714376487549490586439575"
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
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4693867334098764",
		"6209876098547207"
	};

	for (int i = 0; i < 5; i++)
	{
		char commandLine[2048];

		ByteString keyData56(testKeys56[i]);
		CPPUNIT_ASSERT(keyData56.size() == 8);
		ByteString keyData112(testKeys112[i]);
		CPPUNIT_ASSERT(keyData112.size() == 16);
		ByteString keyData168(testKeys168[i]);
		CPPUNIT_ASSERT(keyData168.size() == 24);

		DESKey desKey56(56);
		CPPUNIT_ASSERT(desKey56.setKeyBits(keyData56));
		DESKey desKey112(112);
		CPPUNIT_ASSERT(desKey112.setKeyBits(keyData112));
		DESKey desKey168(168);
		CPPUNIT_ASSERT(desKey168.setKeyBits(keyData168));

		ByteString IV(testIV[i]);

		for (int j = 0; j < 4; j++)
		{
			ByteString plainText(testData[j]);
			ByteString cipherText;
			ByteString shsmCipherText, OB;

			// Test 56-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ofb -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys56[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey56, "ofb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 112-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede-ofb -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys112[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey112, "ofb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 168-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede3-ofb -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys168[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey168, "ofb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);
		}
	}
}

void DESTests::testCFB()
{
	char testKeys56[][17] =
	{
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4698436794236871",
		"0940278947239572"
	};

	char testKeys112[][33] =
	{
		"00000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F10",
		"404142434445464748494A4B4C4D4E4F",
		"64398647034486943598534703463870",
		"87406984068406984607412103517413"
	};
	
	char testKeys168[][49] =
	{
		"000000000000000000000000000000000000000000000000",
		"0102030405060708090A0B0C0D0E0F101112131415161718",
		"404142434445464748494A4B4C4D4E4F5051525354555657",
		"643906874509874309687459084769847562436043696747",
		"430135460496813044639085714376487549490586439575"
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
		"0000000000000000",
		"0102030405060708",
		"4041424344454647",
		"4693867334098764",
		"6209876098547207"
	};

	for (int i = 0; i < 5; i++)
	{
		char commandLine[2048];

		ByteString keyData56(testKeys56[i]);
		CPPUNIT_ASSERT(keyData56.size() == 8);
		ByteString keyData112(testKeys112[i]);
		CPPUNIT_ASSERT(keyData112.size() == 16);
		ByteString keyData168(testKeys168[i]);
		CPPUNIT_ASSERT(keyData168.size() == 24);

		DESKey desKey56(56);
		CPPUNIT_ASSERT(desKey56.setKeyBits(keyData56));
		DESKey desKey112(112);
		CPPUNIT_ASSERT(desKey112.setKeyBits(keyData112));
		DESKey desKey168(168);
		CPPUNIT_ASSERT(desKey168.setKeyBits(keyData168));

		ByteString IV(testIV[i]);

		for (int j = 0; j < 4; j++)
		{
			ByteString plainText(testData[j]);
			ByteString cipherText;
			ByteString shsmCipherText, OB;

			// Test 56-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-cfb -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys56[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey56, "cfb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 112-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede-cfb -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys112[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey112, "cfb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			// Test 168-bit key

			// First, use the OpenSSL command line tool to encrypt the test data
			writeTmpFile(plainText);

			sprintf(commandLine, "openssl des-ede3-cfb -in shsmv2-destest.tmp -out shsmv2-destest-out.tmp -K %s -iv %s",
				testKeys168[i], testIV[i]);

			CPPUNIT_ASSERT(!system(commandLine));

			readTmpFile(cipherText);

			// Now, do the same thing using our DES implementation
			shsmCipherText.wipe();
			CPPUNIT_ASSERT(des->encryptInit(&desKey168, "cfb", IV));

			CPPUNIT_ASSERT(des->encryptUpdate(plainText, OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(des->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);
		}
	}
}

void DESTests::writeTmpFile(ByteString& data)
{
	FILE* out = fopen("shsmv2-destest.tmp", "w");
	CPPUNIT_ASSERT(out != NULL);

	CPPUNIT_ASSERT(fwrite(&data[0], 1, data.size(), out) == data.size());
	CPPUNIT_ASSERT(!fclose(out));
}

void DESTests::readTmpFile(ByteString& data)
{
	unsigned char buf[256];

	data.wipe();

	FILE* in = fopen("shsmv2-destest-out.tmp", "r");
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

