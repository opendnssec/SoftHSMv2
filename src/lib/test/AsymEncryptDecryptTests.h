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
 AsymEncryptDecryptTests.h

 Contains test cases for C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt
 using asymmetrical algorithms (i.e., RSA)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ASYMENCRYPTDECRYPTTESTS_H
#define _SOFTHSM_V2_ASYMENCRYPTDECRYPTTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class AsymEncryptDecryptTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(AsymEncryptDecryptTests);
	CPPUNIT_TEST(testRsaEncryptDecrypt);
	CPPUNIT_TEST_SUITE_END();

public:
	void testRsaEncryptDecrypt();

protected:
	CK_RV generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
	void rsaEncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey);
	void rsaOAEPParams(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey);
};

#endif // !_SOFTHSM_V2_ASYMENCRYPTDECRYPTTESTS_H
