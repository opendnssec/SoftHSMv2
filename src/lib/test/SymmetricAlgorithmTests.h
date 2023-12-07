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

#include <array>
#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class WrappedMaterial;

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
	// TODO: check CKA_CHECK_VALUE error
	//CPPUNIT_TEST(testCheckValue);
	CPPUNIT_TEST(testAesCtrOverflow);
	CPPUNIT_TEST(testGenericKey);
	CPPUNIT_TEST(testEncDecFinalNULLValidation);
	CPPUNIT_TEST(testOpTermIssue585);
	CPPUNIT_TEST_SUITE_END();

public:
	using Bytes = std::vector<CK_BYTE>;
	
	void testAesEncryptDecrypt();
	void testDesEncryptDecrypt();
	void testAesWrapUnwrap();
	void testDesWrapUnwrap();
	void testNullTemplate();
	void testNonModifiableDesKeyGeneration();
	void testCheckValue();
	void testAesCtrOverflow();
	void testGenericKey();
	void testEncDecFinalNULLValidation();
	void testOpTermIssue585();

protected:
	CK_RV generateGenericKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#ifndef WITH_FIPS
	CK_RV generateDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif
	CK_RV generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	void encryptDecrypt(
			CK_MECHANISM mechanism,
			size_t sizeOfIV,
			CK_SESSION_HANDLE hSession,
			CK_OBJECT_HANDLE hKey,
			size_t messageSize,
			bool isSizeOK=true);
	void aesWrapUnwrapGeneric(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	void aesWrapUnwrapRsa(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	void desWrapUnwrapRsa(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	CK_RV generateRsaPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#ifdef WITH_GOST
	void aesWrapUnwrapGost(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	CK_RV generateGostPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif
#ifdef WITH_EDDSA
	using EDCurveParam = const std::array<CK_BYTE, 5>;
        void aesWrapUnwrapED(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
        CK_RV generateEDPrivateKey(CK_SESSION_HANDLE hSession,
				   CK_BBOOL bToken,
				   CK_BBOOL bPrivate,
				   CK_OBJECT_HANDLE &hKey,
				   EDCurveParam &curveparam);
#endif
#ifndef WITH_FIPS
	CK_RV importDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey, const Bytes & vKeyValue );
	CK_RV importDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey, const Bytes & vKeyValue );
#endif
	CK_RV importDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey, const Bytes & vKeyValue );
	CK_RV importAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey, const Bytes & vKeyValue );

	void unwrapKnownKey(const CK_SESSION_HANDLE hSession, WrappedMaterial & sWrapped);
private:
	void wrapUnwrapRsa(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	CK_RV importKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey, const CK_KEY_TYPE keyType, const Bytes & vKeyValue );
};


class WrappedMaterial {

	using Bytes = std::vector<CK_BYTE>;

	std::string m_descr;
	std::vector<Bytes> m_data;
	CK_OBJECT_CLASS m_wrappedobjectclass;
	CK_KEY_TYPE m_wrappedkeytype;
	CK_KEY_TYPE m_wrappingkeytype;
	CK_MECHANISM m_mechanism;

public:

	WrappedMaterial( std::string description,
			 CK_KEY_TYPE wrappingKeyType,
			 CK_MECHANISM_TYPE mechType,
			 CK_OBJECT_CLASS wrappedObjectClass,
			 CK_KEY_TYPE wrappedKeyType,
			 std::initializer_list<Bytes> il ) :
		m_descr ( description ),
		m_wrappedobjectclass ( wrappedObjectClass ),
		m_wrappedkeytype ( wrappedKeyType ),
		m_wrappingkeytype ( wrappingKeyType )
	{
		for( auto &&i : il ) {
			m_data.emplace_back( std::move(i) );
		}
		m_mechanism.mechanism = mechType;
	}

	std::string description() { return m_descr; }
	Bytes &wrappingKeyBytes() { return m_data[0]; }
	Bytes &cbcIv() { return m_data[1]; }
	Bytes &wrappedKey() { return m_data[2]; };
	CK_OBJECT_CLASS &wrappedObjectClass() { return m_wrappedobjectclass; };
	CK_KEY_TYPE &wrappingKeyType() { return m_wrappingkeytype; };
	CK_KEY_TYPE &wrappedKeyType() { return m_wrappedkeytype; };
	CK_MECHANISM &mechanism() {
		// adjust mechanism to point to data provided
		// we do it here and not in the constructor,
		// has data() can move around as we push to the vectors
		m_mechanism.pParameter = m_data[1].data();
		m_mechanism.ulParameterLen = m_data[1].size();
		return m_mechanism;
	};
};

#endif // !_SOFTHSM_V2_SYMENCRYPTDECRYPTTESTS_H
