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
 SignVerifyTests.h

 Contains test cases to C_SignInit,C_Sign,C_SignUpdate,C_SignFinal,
 C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SIGNVERIFYTESTS_H
#define _SOFTHSM_V2_SIGNVERIFYTESTS_H

#include "config.h"
#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#ifdef WITH_OPENSSL
	#include <openssl/opensslv.h>
#endif

class SignVerifyTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(SignVerifyTests);
	CPPUNIT_TEST(testRsaSignVerify);
#ifdef WITH_ECC
	CPPUNIT_TEST(testEcSignVerify);
#endif
#ifdef WITH_EDDSA
	CPPUNIT_TEST_PARAMETERIZED(testEdSignVerify, {"Ed25519", "Ed448"});
	CPPUNIT_TEST_PARAMETERIZED(testEdSignVerifyWithContext, {"Ed25519", "Ed448"});
	CPPUNIT_TEST_PARAMETERIZED(testEdSignVerifyWithContextPreHashed, {"Ed25519", "Ed448"});
	CPPUNIT_TEST_PARAMETERIZED(testEdSignVerifyMismatchedParams, {"Ed25519", "Ed448"});
	CPPUNIT_TEST(testEdSignVerifyInvalidParams);
#endif
	CPPUNIT_TEST(testMacSignVerify);
#ifdef WITH_ML_DSA
	CPPUNIT_TEST_PARAMETERIZED(testMLDSASignVerify, {CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87});
#endif
	CPPUNIT_TEST(testSignInitWrongKeyType);
	CPPUNIT_TEST(testVerifyInitWrongKeyType);
	CPPUNIT_TEST_SUITE_END();

public:
	void testRsaSignVerify();
#ifdef WITH_ECC
	void testEcSignVerify();
#endif
#ifdef WITH_EDDSA
	void testEdSignVerify(const char* curve);
	void testEdSignVerifyWithContext(const char* curve);
	void testEdSignVerifyWithContextPreHashed(const char* curve);
	void testEdSignVerifyMismatchedParams(const char* curve);
	void testEdSignVerifyInvalidParams();
#endif
	void testMacSignVerify();
#ifdef WITH_ML_DSA
	void testMLDSASignVerify(CK_ULONG parameterSet);
#endif
	void testSignInitWrongKeyType();
	void testVerifyInitWrongKeyType();

protected:
	CK_RV generateRSA(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
#ifdef WITH_ECC
	CK_RV generateEC(const char* curve, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
#endif
#ifdef WITH_EDDSA
	CK_RV generateED(const char* curve, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
#endif
#ifdef WITH_ML_DSA
	CK_RV generateMLDSA(CK_ULONG parameterSet, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
#endif
	void signVerifySingle(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param = NULL_PTR, CK_ULONG paramLen = 0);
	void signVerifySingleData(size_t dataSize, CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param = NULL_PTR, CK_ULONG paramLen = 0);
	void signVerifySingleData(CK_BYTE_PTR data, size_t dataSize, CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param = NULL_PTR, CK_ULONG paramLen = 0);
#ifdef WITH_EDDSA
	void signVerifyMismatchedParams(CK_BYTE_PTR data, size_t dataSize, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR signParam, CK_ULONG signParamLen, CK_VOID_PTR verifyParam, CK_ULONG verifyParamLen);
#endif
	void signVerifyMulti(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param = NULL_PTR, CK_ULONG paramLen = 0);
	CK_RV generateKey(CK_SESSION_HANDLE hSession, CK_KEY_TYPE keyType, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	void macSignVerify(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
};

#endif // !_SOFTHSM_V2_SIGNVERIFYTESTS_H
