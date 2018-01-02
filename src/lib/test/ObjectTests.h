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
 ObjectTests.h

 Contains test cases to C_CreateObject, C_CopyObject, C_DestroyObject,
 C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit,
 C_FindObjects, C_FindObjectsFinal, C_GenerateKeyPair
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OBJECTTESTS_H
#define _SOFTHSM_V2_OBJECTTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class ObjectTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(ObjectTests);
	CPPUNIT_TEST(testCreateObject);
	CPPUNIT_TEST(testCopyObject);
	CPPUNIT_TEST(testDestroyObject);
	CPPUNIT_TEST(testGetObjectSize);
	CPPUNIT_TEST(testGetAttributeValue);
	CPPUNIT_TEST(testSetAttributeValue);
	CPPUNIT_TEST(testFindObjects);
	CPPUNIT_TEST(testGenerateKeys);
	CPPUNIT_TEST(testCreateCertificates);
	CPPUNIT_TEST(testDefaultDataAttributes);
	CPPUNIT_TEST(testDefaultX509CertAttributes);
	CPPUNIT_TEST(testDefaultRSAPubAttributes);
	CPPUNIT_TEST(testDefaultRSAPrivAttributes);
	CPPUNIT_TEST(testAlwaysNeverAttribute);
	CPPUNIT_TEST(testSensitiveAttributes);
	CPPUNIT_TEST(testGetInvalidAttribute);
	CPPUNIT_TEST(testAllowedMechanisms);
	CPPUNIT_TEST(testReAuthentication);
	CPPUNIT_TEST(testTemplateAttribute);
	CPPUNIT_TEST(testCreateSecretKey);
	CPPUNIT_TEST_SUITE_END();

public:
	void testCreateObject();
	void testCopyObject();
	void testDestroyObject();
	void testGetObjectSize();
	void testGetAttributeValue();
	void testSetAttributeValue();
	void testFindObjects();
	void testGenerateKeys();
	void testCreateCertificates();
	void testDefaultDataAttributes();
	void testDefaultX509CertAttributes();
	void testDefaultRSAPubAttributes();
	void testDefaultRSAPrivAttributes();
	void testAlwaysNeverAttribute();
	void testSensitiveAttributes();
	void testGetInvalidAttribute();
	void testReAuthentication();
	void testAllowedMechanisms();
	void testTemplateAttribute();
	void testCreateSecretKey();

protected:
	void checkCommonObjectAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_OBJECT_CLASS objectClass
	);
	void checkCommonStorageObjectAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_BBOOL bToken,
		CK_BBOOL bPrivate,
		CK_BBOOL bModifiable,
		CK_UTF8CHAR_PTR pLabel, CK_ULONG ulLabelLen,
		CK_BBOOL bCopyable,
		CK_BBOOL bDestroyable
	);
	void checkDataObjectAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_UTF8CHAR_PTR pApplication, CK_ULONG ulApplicationLen,
		CK_BYTE_PTR pObjectID, CK_ULONG ulObjectIdLen,
		CK_BYTE_PTR pValue, CK_ULONG ulValueLen
	);
	void checkCommonCertificateObjectAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_CERTIFICATE_TYPE certType,
		CK_BBOOL bTrusted,
		CK_ULONG ulCertificateCategory,
		CK_BYTE_PTR pCheckValue, CK_ULONG ulCheckValueLen,
		CK_DATE startDate, CK_ULONG ulStartDateLen,
		CK_DATE endDate, CK_ULONG ulEndDateLen
	);
	void checkX509CertificateObjectAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen,
		CK_BYTE_PTR pId, CK_ULONG ulIdLen,
		CK_BYTE_PTR pIssuer, CK_ULONG ulIssuerLen,
		CK_BYTE_PTR pSerialNumber, CK_ULONG ulSerialNumberLen,
		CK_BYTE_PTR pValue, CK_ULONG ulValueLen,
		CK_BYTE_PTR pUrl, CK_ULONG ulUrlLen,
		CK_BYTE_PTR pHashOfSubjectPublicKey, CK_ULONG ulHashOfSubjectPublicKeyLen,
		CK_BYTE_PTR pHashOfIssuerPublicKey, CK_ULONG ulHashOfIssuerPublicKeyLen,
		CK_ULONG ulJavaMidpSecurityDomain,
		CK_MECHANISM_TYPE nameHashAlgorithm
	);
	void checkCommonKeyAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_KEY_TYPE keyType,
		CK_BYTE_PTR pId, CK_ULONG ulIdLen,
		CK_DATE startDate, CK_ULONG ulStartDateLen,
		CK_DATE endDate, CK_ULONG ulEndDateLen,
		CK_BBOOL bDerive,
		CK_BBOOL bLocal,
		CK_MECHANISM_TYPE keyMechanismType,
		CK_MECHANISM_TYPE_PTR pAllowedMechanisms, CK_ULONG ulAllowedMechanismsLen /* len = count * sizeof(CK_MECHANISM_TYPE) */
	);
	void checkCommonPublicKeyAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen,
		CK_BBOOL bEncrypt,
		CK_BBOOL bVerify,
		CK_BBOOL bVerifyRecover,
		CK_BBOOL bWrap,
		CK_BBOOL bTrusted,
		CK_ATTRIBUTE_PTR pWrapTemplate, CK_ULONG ulWrapTemplateLen /* len = count * sizeof(CK_ATTRIBUTE) */
	);
	void checkCommonPrivateKeyAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen,
		CK_BBOOL bSensitive,
		CK_BBOOL bDecrypt,
		CK_BBOOL bSign,
		CK_BBOOL bSignRecover,
		CK_BBOOL bUnwrap,
		CK_BBOOL bExtractable,
		CK_BBOOL bAlwaysSensitive,
		CK_BBOOL bNeverExtractable,
		CK_BBOOL bWrapWithTrusted,
		CK_ATTRIBUTE_PTR pUnwrapTemplate, CK_ULONG ulUnwrapTemplateLen, /* len = count * sizeof(CK_ATTRIBUTE) */
		CK_BBOOL bAlwaysAuthenticate
	);
	void checkCommonRSAPublicKeyAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen,
		CK_ULONG ulModulusBits,
		CK_BYTE_PTR pPublicExponent, CK_ULONG ulPublicExponentLen
	);
	void checkCommonRSAPrivateKeyAttributes
	(	CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen,
		CK_BYTE_PTR pPublicExponent, CK_ULONG ulPublicExponentLen,
		CK_BYTE_PTR pPrivateExponent, CK_ULONG ulPrivateExponentLen,
		CK_BYTE_PTR pPrime1, CK_ULONG ulPrime1Len,
		CK_BYTE_PTR pPrime2, CK_ULONG ulPrime2Len,
		CK_BYTE_PTR pExponent1, CK_ULONG ulExponent1Len,
		CK_BYTE_PTR pExponent2, CK_ULONG ulExponent2Len,
		CK_BYTE_PTR pCoefficient, CK_ULONG ulCoefficientLen
	);

	CK_RV createDataObjectMinimal(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject);
	CK_RV createDataObjectMCD(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_BBOOL bModifiable, CK_BBOOL bCopyable, CK_BBOOL bDestroyable, CK_OBJECT_HANDLE &hObject);
	CK_RV createDataObjectNormal(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject);

	CK_RV createCertificateObjectIncomplete(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject);
	CK_RV createCertificateObjectX509(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject);

	CK_RV generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
};

#endif // !_SOFTHSM_V2_OBJECTTESTS_H
