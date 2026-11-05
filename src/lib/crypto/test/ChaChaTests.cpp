/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 ChaChaTests.cpp

 Contains test cases to test the ChaCha20-Poly1305 implementation
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "ChaChaTests.h"
#include "CryptoFactory.h"
#include "SymmetricKey.h"
#include <stdio.h>

CPPUNIT_TEST_SUITE_REGISTRATION(ChaChaTests);

// Test vectors from RFC 8439: key, nonce, plaintext, AAD, ciphertext || tag
static const char testVectors[2][5][1024] =
{
	// Section 2.8.2 (nonce is the 32-bit constant 07000000 || IV 4041424344454647)
	{
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
		"070000004041424344454647",
		"4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E",
		"50515253C0C1C2C3C4C5C6C7",
		"D31A8D34648E60DB7B86AFBC53EF7EC2A4ADED51296E08FEA9E2B5A736EE62D63DBEA45E8CA9671282FAFB69DA92728B1A71DE0A9E060B2905D6A5B67ECD3B3692DDBD7F2D778B8C9803AEE328091B58FAB324E4FAD675945585808B4831D7BC3FF4DEF08E4B7A9DE576D26586CEC64B6116"
		"1AE10B594F09E26A7E902ECBD0600691"
	},
	// Appendix A.5
	{
		"1C9240A5EB55D38AF333888604F6B5F0473917C1402B80099DCA5CBC207075C0",
		"000000000102030405060708",
		"496E7465726E65742D4472616674732061726520647261667420646F63756D656E74732076616C696420666F722061206D6178696D756D206F6620736978206D6F6E74687320616E64206D617920626520757064617465642C207265706C616365642C206F72206F62736F6C65746564206279206F7468657220646F63756D656E747320617420616E792074696D652E20497420697320696E617070726F70726961746520746F2075736520496E7465726E65742D447261667473206173207265666572656E6365206D6174657269616C206F7220746F2063697465207468656D206F74686572207468616E206173202FE2809C776F726B20696E2070726F67726573732E2FE2809D",
		"F33388860000000000004E91",
		"64A0861575861AF460F062C79BE643BD5E805CFD345CF389F108670AC76C8CB24C6CFC18755D43EEA09EE94E382D26B0BDB7B73C321B0100D4F03B7F355894CF332F830E710B97CE98C8A84ABD0B948114AD176E008D33BD60F982B1FF37C8559797A06EF4F0EF61C186324E2B3506383606907B6A7C02B0F9F6157B53C867E4B9166C767B804D46A59B5216CDE7A4E99040C5A40433225EE282A1B0A06C523EAF4534D7F83FA1155B0047718CBC546A0D072B04B3564EEA1B422273F548271A0BB2316053FA76991955EBD63159434ECEBB4E466DAE5A1073A6727627097A1049E617D91D361094FA68F0FF77987130305BEABA2EDA04DF997B714D6C6F2C29A6AD5CB4022B02709B"
		"EEAD9D67890CBB22392336FEA1851F38"
	}
};

static const size_t tagBytes = 16;

void ChaChaTests::setUp()
{
	chacha = NULL;

	chacha = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::ChaCha20Poly1305);

	// Check the return value
	CPPUNIT_ASSERT(chacha != NULL);
}

void ChaChaTests::tearDown()
{
	if (chacha != NULL)
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(chacha);
	}

	fflush(stdout);
}

void ChaChaTests::testBlockSize()
{
	// ChaCha20-Poly1305 is a stream cipher
	CPPUNIT_ASSERT(chacha->getBlockSize() == 1);
}

void ChaChaTests::testRFC8439()
{
	for (int i = 0; i < 2; i++)
	{
		SymmetricKey key(256);
		CPPUNIT_ASSERT(key.setKeyBits(ByteString(testVectors[i][0])));

		ByteString nonce(testVectors[i][1]);
		ByteString plainText(testVectors[i][2]);
		ByteString AAD(testVectors[i][3]);
		ByteString cipherText(testVectors[i][4]);

		ByteString shsmCipherText;
		ByteString shsmPlainText;
		ByteString OB;

		// Encrypt and compare with the expected ciphertext and tag
		CPPUNIT_ASSERT(chacha->encryptInit(&key, SymMode::ChaCha20Poly1305, nonce, false, 0, AAD, tagBytes));

		CPPUNIT_ASSERT(chacha->encryptUpdate(plainText, OB));
		shsmCipherText += OB;

		CPPUNIT_ASSERT(chacha->encryptFinal(OB));
		shsmCipherText += OB;

		CPPUNIT_ASSERT(shsmCipherText == cipherText);

		// Decrypt the expected ciphertext and compare with the plaintext
		CPPUNIT_ASSERT(chacha->decryptInit(&key, SymMode::ChaCha20Poly1305, nonce, false, 0, AAD, tagBytes));

		CPPUNIT_ASSERT(chacha->decryptUpdate(cipherText, OB));
		CPPUNIT_ASSERT(OB.size() == 0);

		CPPUNIT_ASSERT(chacha->decryptFinal(OB));
		shsmPlainText += OB;

		CPPUNIT_ASSERT(shsmPlainText == plainText);
	}
}

void ChaChaTests::testRFC8439MultiPart()
{
	// Chunk sizes that do not line up with the 16-byte Poly1305 block
	// or the 64-byte ChaCha20 block
	const size_t chunkSizes[] = { 1, 7, 16, 63, 64, 100 };

	for (int i = 0; i < 2; i++)
	{
		SymmetricKey key(256);
		CPPUNIT_ASSERT(key.setKeyBits(ByteString(testVectors[i][0])));

		ByteString nonce(testVectors[i][1]);
		ByteString plainText(testVectors[i][2]);
		ByteString AAD(testVectors[i][3]);
		ByteString cipherText(testVectors[i][4]);

		for (size_t c = 0; c < sizeof(chunkSizes)/sizeof(chunkSizes[0]); c++)
		{
			const size_t chunk = chunkSizes[c];
			ByteString shsmCipherText;
			ByteString shsmPlainText;
			ByteString OB;

			CPPUNIT_ASSERT(chacha->encryptInit(&key, SymMode::ChaCha20Poly1305, nonce, false, 0, AAD, tagBytes));
			for (size_t pos = 0; pos < plainText.size(); pos += chunk)
			{
				size_t len = plainText.size() - pos < chunk ? plainText.size() - pos : chunk;
				CPPUNIT_ASSERT(chacha->encryptUpdate(plainText.substr(pos, len), OB));
				shsmCipherText += OB;
			}
			CPPUNIT_ASSERT(chacha->encryptFinal(OB));
			shsmCipherText += OB;

			CPPUNIT_ASSERT(shsmCipherText == cipherText);

			CPPUNIT_ASSERT(chacha->decryptInit(&key, SymMode::ChaCha20Poly1305, nonce, false, 0, AAD, tagBytes));
			for (size_t pos = 0; pos < cipherText.size(); pos += chunk)
			{
				size_t len = cipherText.size() - pos < chunk ? cipherText.size() - pos : chunk;
				CPPUNIT_ASSERT(chacha->decryptUpdate(cipherText.substr(pos, len), OB));
				CPPUNIT_ASSERT(OB.size() == 0);
			}
			CPPUNIT_ASSERT(chacha->decryptFinal(OB));
			shsmPlainText += OB;

			CPPUNIT_ASSERT(shsmPlainText == plainText);
		}
	}
}

void ChaChaTests::testRFC8439Tampered()
{
	for (int i = 0; i < 2; i++)
	{
		SymmetricKey key(256);
		CPPUNIT_ASSERT(key.setKeyBits(ByteString(testVectors[i][0])));

		ByteString nonce(testVectors[i][1]);
		ByteString AAD(testVectors[i][3]);
		ByteString cipherText(testVectors[i][4]);
		ByteString OB;

		// Flipped bit in the tag
		ByteString badTag(cipherText);
		badTag[badTag.size() - 1] ^= 0x01;

		CPPUNIT_ASSERT(chacha->decryptInit(&key, SymMode::ChaCha20Poly1305, nonce, false, 0, AAD, tagBytes));
		CPPUNIT_ASSERT(chacha->decryptUpdate(badTag, OB));
		CPPUNIT_ASSERT(!chacha->decryptFinal(OB));
		CPPUNIT_ASSERT(OB.size() == 0);

		// Flipped bit in the ciphertext
		ByteString badCipherText(cipherText);
		badCipherText[0] ^= 0x01;

		CPPUNIT_ASSERT(chacha->decryptInit(&key, SymMode::ChaCha20Poly1305, nonce, false, 0, AAD, tagBytes));
		CPPUNIT_ASSERT(chacha->decryptUpdate(badCipherText, OB));
		CPPUNIT_ASSERT(!chacha->decryptFinal(OB));
		CPPUNIT_ASSERT(OB.size() == 0);

		// Flipped bit in the AAD
		ByteString badAAD(AAD);
		badAAD[0] ^= 0x01;

		CPPUNIT_ASSERT(chacha->decryptInit(&key, SymMode::ChaCha20Poly1305, nonce, false, 0, badAAD, tagBytes));
		CPPUNIT_ASSERT(chacha->decryptUpdate(cipherText, OB));
		CPPUNIT_ASSERT(!chacha->decryptFinal(OB));
		CPPUNIT_ASSERT(OB.size() == 0);

		// Wrong nonce
		ByteString badNonce(nonce);
		badNonce[nonce.size() - 1] ^= 0x01;

		CPPUNIT_ASSERT(chacha->decryptInit(&key, SymMode::ChaCha20Poly1305, badNonce, false, 0, AAD, tagBytes));
		CPPUNIT_ASSERT(chacha->decryptUpdate(cipherText, OB));
		CPPUNIT_ASSERT(!chacha->decryptFinal(OB));
		CPPUNIT_ASSERT(OB.size() == 0);
	}
}
