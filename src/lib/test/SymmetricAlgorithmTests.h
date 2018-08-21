/*
 * Copyright (c) 2012 SURFnet
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
 SymmetricAlgorithmTests.h

 Contains test cases for symmetrical algorithms (i.e., AES and DES)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMENCRYPTDECRYPTTESTS_H
#define _SOFTHSM_V2_SYMENCRYPTDECRYPTTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class SymmetricAlgorithmTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(SymmetricAlgorithmTests);
	CPPUNIT_TEST(testAesEncryptDecrypt);
	CPPUNIT_TEST(testDesEncryptDecrypt);
#ifdef HAVE_AES_KEY_WRAP
	CPPUNIT_TEST(testAesWrapUnwrap);
#endif
	CPPUNIT_TEST(testNullTemplate);
	CPPUNIT_TEST(testNonModifiableDesKeyGeneration);
	CPPUNIT_TEST(testCheckValue);
	CPPUNIT_TEST(testAesCtrOverflow);
	CPPUNIT_TEST(testGenericKey);
	CPPUNIT_TEST_SUITE_END();

public:
	void testAesEncryptDecrypt();
	void testDesEncryptDecrypt();
	void testAesWrapUnwrap();
	void testNullTemplate();
	void testNonModifiableDesKeyGeneration();
	void testCheckValue();
	void testAesCtrOverflow();
	void testGenericKey();

protected:
	CK_RV generateGenericKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#ifndef WITH_FIPS
	CK_RV generateDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif
	CK_RV generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	void encryptDecrypt(
			CK_MECHANISM_TYPE mechanismType,
			size_t sizeOfIV,
			CK_SESSION_HANDLE hSession,
			CK_OBJECT_HANDLE hKey,
			size_t messageSize,
			bool isSizeOK=true);
	void aesWrapUnwrapGeneric(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	void aesWrapUnwrapRsa(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	CK_RV generateRsaPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#ifdef WITH_GOST
	void aesWrapUnwrapGost(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	CK_RV generateGostPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif
};

#endif // !_SOFTHSM_V2_SYMENCRYPTDECRYPTTESTS_H
