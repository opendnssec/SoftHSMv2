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
 ObjectTests.cpp

 Contains test cases for:
	 C_CreateObject
	 C_CopyObject
	 C_DestroyObject
	 C_GetAttributeValue
	 C_SetAttributeValue
	 C_FindObjectsInit
	 C_FindObjects
	 C_FindObjectsFinal
	 C_GenererateKeyPair

 Below is a list of tests we need to add in order to verify that the PKCS#11 library
 is working as expected.

 We want to be sure that order of attributes does not impact the tests, therefore
 every function involving attributes should have the order of the attributes
 in the template randomized.

 We want to be sure that only attributes that are specified as being part of an
 object class can be used when creating an object.
 Using other attributes should return an error on creation of the object.

 We want to be sure that attributes that are required but missing will result
 in a template incomplete return value.

 We want to be sure that we get an error when trying to modify an attribute that
 may not be modified

 We want to be sure that attributes that may be changed to one value but not
 back to the previous value are handled correctly.

 We want to verify that an error is returned when we are trying to modify
 read-only attributes.

 We want to verify that sensitive attributes cannot be read.

 Because the teardown also removes token objects it is not really
 required to destroy objects created during the test in the CreateObject tests.

 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "ObjectTests.h"

// Common object attributes
const CK_BBOOL CKA_TOKEN_DEFAULT = CK_FALSE;
//const CK_BBOOL CKA_PRIVATE_DEFAULT = <token/object attribute dependent>
const CK_BBOOL CKA_MODIFIABLE_DEFAULT = CK_TRUE;
const CK_UTF8CHAR_PTR CKA_LABEL_DEFAULT = NULL;
const CK_BBOOL CKA_COPYABLE_DEFAULT = CK_TRUE;
const CK_BBOOL CKA_DESTROYABLE_DEFAULT = CK_TRUE;

// Data Object Attributes
const CK_UTF8CHAR_PTR CKA_APPLICATION_DEFAULT = NULL;
const CK_BYTE_PTR CKA_OBJECT_ID_DEFAULT = NULL;
const CK_BYTE_PTR CKA_VALUE_DEFAULT = NULL;

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(ObjectTests);

void ObjectTests::checkCommonObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_OBJECT_CLASS objClass)
{
	CK_RV rv;

	CK_OBJECT_CLASS obj_class = CKO_VENDOR_DEFINED;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(obj_class == objClass);
}

void ObjectTests::checkCommonStorageObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BBOOL bToken, CK_BBOOL /*bPrivate*/, CK_BBOOL bModifiable, CK_UTF8CHAR_PTR pLabel, CK_ULONG ulLabelLen, CK_BBOOL bCopyable, CK_BBOOL bDestroyable)
{
	CK_RV rv;

	CK_BBOOL obj_token = CK_FALSE;
	CK_BBOOL obj_private = CK_FALSE;
	CK_BBOOL obj_modifiable = CK_FALSE;
	CK_BBOOL obj_copyable = CK_FALSE;
	CK_BBOOL obj_destroyable = CK_FALSE;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_LABEL, NULL_PTR, 0 },
		{ CKA_TOKEN, &obj_token, sizeof(obj_token) },
		{ CKA_PRIVATE, &obj_private, sizeof(obj_private) },
		{ CKA_MODIFIABLE, &obj_modifiable, sizeof(obj_modifiable) },
		{ CKA_COPYABLE, &obj_copyable, sizeof(obj_copyable) },
		{ CKA_DESTROYABLE, &obj_destroyable, sizeof(obj_destroyable) }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 6) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulLabelLen);
	CPPUNIT_ASSERT(obj_token == bToken);
	/* Default is token-specifict
	CPPUNIT_ASSERT(obj_private == bPrivate); */
	CPPUNIT_ASSERT(obj_modifiable == bModifiable);
	CPPUNIT_ASSERT(obj_copyable == bCopyable);
	CPPUNIT_ASSERT(obj_destroyable == bDestroyable);
	if (ulLabelLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pLabel, ulLabelLen) == 0);

	free(attribs[0].pValue);
}

void ObjectTests::checkDataObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_UTF8CHAR_PTR pApplication, CK_ULONG ulApplicationLen, CK_BYTE_PTR pObjectID, CK_ULONG ulObjectIdLen, CK_BYTE_PTR pValue, CK_ULONG ulValueLen)
{
	CK_RV rv;

	CK_ATTRIBUTE attribs[] = {
		{ CKA_APPLICATION, NULL_PTR, 0 },
		{ CKA_OBJECT_ID, NULL_PTR, 0 },
		{ CKA_VALUE, NULL_PTR, 0 }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 3) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);
	attribs[1].pValue = (CK_VOID_PTR)malloc(attribs[1].ulValueLen);
	attribs[2].pValue = (CK_VOID_PTR)malloc(attribs[2].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 3) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulApplicationLen);
	CPPUNIT_ASSERT(attribs[1].ulValueLen == ulObjectIdLen);
	CPPUNIT_ASSERT(attribs[2].ulValueLen == ulValueLen);
	if (ulApplicationLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pApplication, ulApplicationLen) == 0);
	if (ulObjectIdLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[1].pValue, pObjectID, ulObjectIdLen) == 0);
	if (ulValueLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[2].pValue, pValue, ulValueLen) == 0);

	free(attribs[0].pValue);
	free(attribs[1].pValue);
	free(attribs[2].pValue);
}

void ObjectTests::checkCommonCertificateObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_CERTIFICATE_TYPE certType, CK_BBOOL bTrusted, CK_ULONG ulCertificateCategory, CK_BYTE_PTR pCheckValue, CK_ULONG ulCheckValueLen, CK_DATE startDate, CK_ULONG ulStartDateLen, CK_DATE endDate, CK_ULONG ulEndDateLen)
{
	CK_RV rv;

	CK_CERTIFICATE_TYPE obj_type = CKC_X_509;
	CK_BBOOL obj_trusted = CK_FALSE;
	CK_ULONG obj_category = 0;
	CK_DATE obj_start;
	CK_DATE obj_end;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_CHECK_VALUE, NULL_PTR, 0 },
		{ CKA_CERTIFICATE_TYPE, &obj_type, sizeof(obj_type) },
		{ CKA_TRUSTED, &obj_trusted, sizeof(obj_trusted) },
		{ CKA_CERTIFICATE_CATEGORY, &obj_category, sizeof(obj_category) },
		{ CKA_START_DATE, &obj_start, sizeof(obj_start) },
		{ CKA_END_DATE, &obj_end, sizeof(obj_end) }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 6) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulCheckValueLen);
	CPPUNIT_ASSERT(obj_type == certType);
	CPPUNIT_ASSERT(obj_trusted == bTrusted);
	CPPUNIT_ASSERT(obj_category == ulCertificateCategory);
	CPPUNIT_ASSERT(attribs[4].ulValueLen == ulStartDateLen);
	CPPUNIT_ASSERT(attribs[5].ulValueLen == ulEndDateLen);
	if (ulCheckValueLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pCheckValue, ulCheckValueLen) == 0);
	if (ulStartDateLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[4].pValue, &startDate, ulStartDateLen) == 0);
	if (ulEndDateLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[5].pValue, &endDate, ulEndDateLen) == 0);

	free(attribs[0].pValue);
}

void ObjectTests::checkX509CertificateObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen, CK_BYTE_PTR pId, CK_ULONG ulIdLen, CK_BYTE_PTR pIssuer, CK_ULONG ulIssuerLen, CK_BYTE_PTR pSerialNumber, CK_ULONG ulSerialNumberLen, CK_BYTE_PTR pValue, CK_ULONG ulValueLen, CK_BYTE_PTR pUrl, CK_ULONG ulUrlLen, CK_BYTE_PTR pHashOfSubjectPublicKey, CK_ULONG ulHashOfSubjectPublicKeyLen, CK_BYTE_PTR pHashOfIssuerPublicKey, CK_ULONG ulHashOfIssuerPublicKeyLen, CK_ULONG ulJavaMidpSecurityDomain, CK_MECHANISM_TYPE nameHashAlgorithm)
{
	CK_RV rv;

	CK_ULONG obj_java = 0;
	CK_MECHANISM_TYPE obj_mech = CKM_VENDOR_DEFINED;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_SUBJECT, NULL_PTR, 0 },
		{ CKA_ID, NULL_PTR, 0 },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 },
		{ CKA_VALUE, NULL_PTR, 0 },
		{ CKA_URL, NULL_PTR, 0 },
		{ CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NULL_PTR, 0 },
		{ CKA_HASH_OF_ISSUER_PUBLIC_KEY, NULL_PTR, 0 },
		{ CKA_JAVA_MIDP_SECURITY_DOMAIN, &obj_java, sizeof(obj_java) },
		{ CKA_NAME_HASH_ALGORITHM, &obj_mech, sizeof(obj_mech) }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 8) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);
	attribs[1].pValue = (CK_VOID_PTR)malloc(attribs[1].ulValueLen);
	attribs[2].pValue = (CK_VOID_PTR)malloc(attribs[2].ulValueLen);
	attribs[3].pValue = (CK_VOID_PTR)malloc(attribs[3].ulValueLen);
	attribs[4].pValue = (CK_VOID_PTR)malloc(attribs[4].ulValueLen);
	attribs[5].pValue = (CK_VOID_PTR)malloc(attribs[5].ulValueLen);
	attribs[6].pValue = (CK_VOID_PTR)malloc(attribs[6].ulValueLen);
	attribs[7].pValue = (CK_VOID_PTR)malloc(attribs[7].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 10) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulSubjectLen);
	CPPUNIT_ASSERT(attribs[1].ulValueLen == ulIdLen);
	CPPUNIT_ASSERT(attribs[2].ulValueLen == ulIssuerLen);
	CPPUNIT_ASSERT(attribs[3].ulValueLen == ulSerialNumberLen);
	CPPUNIT_ASSERT(attribs[4].ulValueLen == ulValueLen);
	CPPUNIT_ASSERT(attribs[5].ulValueLen == ulUrlLen);
	CPPUNIT_ASSERT(attribs[6].ulValueLen == ulHashOfSubjectPublicKeyLen);
	CPPUNIT_ASSERT(attribs[7].ulValueLen == ulHashOfIssuerPublicKeyLen);
	CPPUNIT_ASSERT(obj_java == ulJavaMidpSecurityDomain);
	CPPUNIT_ASSERT(obj_mech == nameHashAlgorithm);
	if (ulSubjectLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pSubject, ulSubjectLen) == 0);
	if (ulIdLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[1].pValue, pId, ulIdLen) == 0);
	if (ulIssuerLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[2].pValue, pIssuer, ulIssuerLen) == 0);
	if (ulSerialNumberLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[3].pValue, pSerialNumber, ulSerialNumberLen) == 0);
	if (ulValueLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[4].pValue, pValue, ulValueLen) == 0);
	if (ulUrlLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[5].pValue, pUrl, ulUrlLen) == 0);
	if (ulHashOfSubjectPublicKeyLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[6].pValue, pHashOfSubjectPublicKey, ulHashOfSubjectPublicKeyLen) == 0);
	if (ulHashOfIssuerPublicKeyLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[7].pValue, pHashOfIssuerPublicKey, ulHashOfIssuerPublicKeyLen) == 0);

	free(attribs[0].pValue);
	free(attribs[1].pValue);
	free(attribs[2].pValue);
	free(attribs[3].pValue);
	free(attribs[4].pValue);
	free(attribs[5].pValue);
	free(attribs[6].pValue);
	free(attribs[7].pValue);
}

void ObjectTests::checkCommonKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_KEY_TYPE keyType, CK_BYTE_PTR pId, CK_ULONG ulIdLen, CK_DATE startDate, CK_ULONG ulStartDateLen, CK_DATE endDate, CK_ULONG ulEndDateLen, CK_BBOOL bDerive, CK_BBOOL bLocal, CK_MECHANISM_TYPE keyMechanismType, CK_MECHANISM_TYPE_PTR pAllowedMechanisms, CK_ULONG ulAllowedMechanismsLen)
{
	CK_RV rv;

	CK_KEY_TYPE obj_type = CKK_VENDOR_DEFINED;
	CK_DATE obj_start;
	CK_DATE obj_end;
	CK_BBOOL obj_derive = CK_FALSE;
	CK_BBOOL obj_local = CK_FALSE;
	CK_MECHANISM_TYPE obj_mech = CKM_VENDOR_DEFINED;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_ID, NULL_PTR, 0 },
		{ CKA_KEY_TYPE, &obj_type, sizeof(obj_type) },
		{ CKA_START_DATE, &obj_start, sizeof(obj_start) },
		{ CKA_END_DATE, &obj_end, sizeof(obj_end) },
		{ CKA_DERIVE, &obj_derive, sizeof(obj_derive) },
		{ CKA_LOCAL, &obj_local, sizeof(obj_local) },
		{ CKA_KEY_GEN_MECHANISM, &obj_mech, sizeof(obj_mech) },
		{ CKA_ALLOWED_MECHANISMS, NULL_PTR, 0 }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 8) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulIdLen);
	CPPUNIT_ASSERT(obj_type == keyType);
	CPPUNIT_ASSERT(attribs[2].ulValueLen == ulStartDateLen);
	CPPUNIT_ASSERT(attribs[3].ulValueLen == ulEndDateLen);
	CPPUNIT_ASSERT(obj_derive == bDerive);
	CPPUNIT_ASSERT(obj_local == bLocal);
	CPPUNIT_ASSERT(obj_mech == keyMechanismType);
	CPPUNIT_ASSERT(attribs[7].ulValueLen == ulAllowedMechanismsLen);

	if (ulIdLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pId, ulIdLen) == 0);
	if (ulStartDateLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[2].pValue, &startDate, ulStartDateLen) == 0);
	if (ulEndDateLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[3].pValue, &endDate, ulEndDateLen) == 0);
	if (ulAllowedMechanismsLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[7].pValue, pAllowedMechanisms, ulAllowedMechanismsLen) == 0);

	free(attribs[0].pValue);
}

void ObjectTests::checkCommonPublicKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen, CK_BBOOL /*bEncrypt*/, CK_BBOOL /*bVerify*/, CK_BBOOL /*bVerifyRecover*/, CK_BBOOL /*bWrap*/, CK_BBOOL bTrusted, CK_ATTRIBUTE_PTR pWrapTemplate, CK_ULONG ulWrapTemplateLen)
{
	CK_RV rv;

	CK_BBOOL obj_encrypt = CK_FALSE;
	CK_BBOOL obj_verify = CK_FALSE;
	CK_BBOOL obj_verify_recover = CK_FALSE;
	CK_BBOOL obj_wrap = CK_FALSE;
	CK_BBOOL obj_trusted = CK_FALSE;
	CK_LONG len_wrap_template = ulWrapTemplateLen;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_SUBJECT, NULL_PTR, 0 },
		{ CKA_ENCRYPT, &obj_encrypt, sizeof(obj_encrypt) },
		{ CKA_VERIFY, &obj_verify, sizeof(obj_verify) },
		{ CKA_VERIFY_RECOVER, &obj_verify_recover, sizeof(obj_verify_recover) },
		{ CKA_WRAP, &obj_wrap, sizeof(obj_wrap) },
		{ CKA_TRUSTED, &obj_trusted, sizeof(obj_trusted) },
		{ CKA_WRAP_TEMPLATE, pWrapTemplate, ulWrapTemplateLen }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 7) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulSubjectLen);
	/* Default is token-specifict
	CPPUNIT_ASSERT(obj_encrypt == bEncrypt);
	CPPUNIT_ASSERT(obj_verify == bVerify);
	CPPUNIT_ASSERT(obj_verify_recover == bVerifyRecover);
	CPPUNIT_ASSERT(obj_wrap == bWrap); */
	CPPUNIT_ASSERT(obj_trusted == bTrusted);
	len_wrap_template = attribs[6].ulValueLen;
	CPPUNIT_ASSERT(len_wrap_template == 0);
	if (ulSubjectLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pSubject, ulSubjectLen) == 0);

	free(attribs[0].pValue);
}

void ObjectTests::checkCommonPrivateKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen, CK_BBOOL bSensitive, CK_BBOOL bDecrypt, CK_BBOOL bSign, CK_BBOOL bSignRecover, CK_BBOOL bUnwrap, CK_BBOOL bExtractable, CK_BBOOL bAlwaysSensitive, CK_BBOOL bNeverExtractable, CK_BBOOL bWrapWithTrusted, CK_ATTRIBUTE_PTR pUnwrapTemplate, CK_ULONG ulUnwrapTemplateLen, CK_BBOOL bAlwaysAuthenticate)
{
	CK_RV rv;

	CK_BBOOL obj_sensitive = CK_FALSE;
	CK_BBOOL obj_decrypt = CK_FALSE;
	CK_BBOOL obj_sign = CK_FALSE;
	CK_BBOOL obj_sign_recover = CK_FALSE;
	CK_BBOOL obj_unwrap = CK_FALSE;
	CK_BBOOL obj_extractable = CK_FALSE;
	CK_BBOOL obj_always_sensitive = CK_FALSE;
	CK_BBOOL obj_never_extractable = CK_FALSE;
	CK_BBOOL obj_wrap_with_trusted = CK_FALSE;
	CK_BBOOL obj_always_authenticate = CK_FALSE;
	CK_LONG len_unwrap_template = ulUnwrapTemplateLen;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_SUBJECT, NULL_PTR, 0 },
		{ CKA_SENSITIVE, &obj_sensitive, sizeof(obj_sensitive) },
		{ CKA_DECRYPT, &obj_decrypt, sizeof(obj_decrypt) },
		{ CKA_SIGN, &obj_sign, sizeof(obj_sign) },
		{ CKA_SIGN_RECOVER, &obj_sign_recover, sizeof(obj_sign_recover) },
		{ CKA_UNWRAP, &obj_unwrap, sizeof(obj_unwrap) },
		{ CKA_EXTRACTABLE, &obj_extractable, sizeof(obj_extractable) },
		{ CKA_ALWAYS_SENSITIVE, &obj_always_sensitive, sizeof(obj_always_sensitive) },
		{ CKA_NEVER_EXTRACTABLE, &obj_never_extractable, sizeof(obj_never_extractable) },
		{ CKA_WRAP_WITH_TRUSTED, &obj_wrap_with_trusted, sizeof(obj_wrap_with_trusted) },
		{ CKA_UNWRAP_TEMPLATE, pUnwrapTemplate, ulUnwrapTemplateLen },
		{ CKA_ALWAYS_AUTHENTICATE, &obj_always_authenticate, sizeof(obj_always_authenticate) }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 12) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulSubjectLen);
	CPPUNIT_ASSERT(obj_sensitive == bSensitive);
	CPPUNIT_ASSERT(obj_decrypt == bDecrypt);
	CPPUNIT_ASSERT(obj_sign == bSign);
	CPPUNIT_ASSERT(obj_sign_recover == bSignRecover);
	CPPUNIT_ASSERT(obj_unwrap == bUnwrap);
	CPPUNIT_ASSERT(obj_extractable == bExtractable);
	CPPUNIT_ASSERT(obj_always_sensitive == bAlwaysSensitive);
	CPPUNIT_ASSERT(obj_never_extractable == bNeverExtractable);
	CPPUNIT_ASSERT(obj_wrap_with_trusted == bWrapWithTrusted);
	CPPUNIT_ASSERT(obj_always_authenticate == bAlwaysAuthenticate);
	len_unwrap_template = attribs[10].ulValueLen;
	CPPUNIT_ASSERT(len_unwrap_template == 0);
	if (ulSubjectLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pSubject, ulSubjectLen) == 0);

	free(attribs[0].pValue);
}

void ObjectTests::checkCommonRSAPublicKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen, CK_ULONG ulModulusBits, CK_BYTE_PTR pPublicExponent, CK_ULONG ulPublicExponentLen)
{
	CK_RV rv;

	CK_ULONG obj_bits = 0;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_MODULUS, NULL_PTR, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
		{ CKA_MODULUS_BITS, &obj_bits, sizeof(obj_bits) }
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);
	attribs[1].pValue = (CK_VOID_PTR)malloc(attribs[1].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 3) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulModulusLen);
	CPPUNIT_ASSERT(attribs[1].ulValueLen == ulPublicExponentLen);
	CPPUNIT_ASSERT(obj_bits == ulModulusBits);
	if (ulModulusLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pModulus, ulModulusLen) == 0);
	if (ulPublicExponentLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[1].pValue, pPublicExponent, ulPublicExponentLen) == 0);

	free(attribs[0].pValue);
	free(attribs[1].pValue);
}

void ObjectTests::checkCommonRSAPrivateKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen, CK_BYTE_PTR /*pPublicExponent*/, CK_ULONG /*ulPublicExponentLen*/, CK_BYTE_PTR pPrivateExponent, CK_ULONG ulPrivateExponentLen, CK_BYTE_PTR /*pPrime1*/, CK_ULONG /*ulPrime1Len*/, CK_BYTE_PTR /*pPrime2*/, CK_ULONG /*ulPrime2Len*/, CK_BYTE_PTR /*pExponent1*/, CK_ULONG /*ulExponent1Len*/, CK_BYTE_PTR /*pExponent2*/, CK_ULONG /*ulExponent2Len*/, CK_BYTE_PTR /*pCoefficient*/, CK_ULONG /*ulCoefficientLen*/)
{
	CK_RV rv;

	CK_ATTRIBUTE attribs[] = {
		{ CKA_MODULUS, NULL_PTR, 0 },
		{ CKA_PRIVATE_EXPONENT, NULL_PTR, 0 }
		/* Some tokens may only store modulus and private exponent
		{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
		{ CKA_PRIME_1, NULL_PTR, 0 },
		{ CKA_PRIME_2, NULL_PTR, 0 },
		{ CKA_EXPONENT_1, NULL_PTR, 0 },
		{ CKA_EXPONENT_2, NULL_PTR, 0 },
		{ CKA_COEFFICIENT, NULL_PTR, 0 }, */
	};

	// Get length
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	attribs[0].pValue = (CK_VOID_PTR)malloc(attribs[0].ulValueLen);
	attribs[1].pValue = (CK_VOID_PTR)malloc(attribs[1].ulValueLen);

	// Check values
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &attribs[0], 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == ulModulusLen);
	CPPUNIT_ASSERT(attribs[1].ulValueLen == ulPrivateExponentLen);
	if (ulModulusLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[0].pValue, pModulus, ulModulusLen) == 0);
	if (ulPrivateExponentLen > 0)
		CPPUNIT_ASSERT(memcmp(attribs[1].pValue, pPrivateExponent, ulPrivateExponentLen) == 0);

	free(attribs[0].pValue);
	free(attribs[1].pValue);
}

CK_RV ObjectTests::createDataObjectMinimal(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject)
{
	CK_OBJECT_CLASS cClass = CKO_DATA;
	CK_UTF8CHAR label[] = "A data object";
	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },

		// Storage
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		//CKA_MODIFIABLE
		{ CKA_LABEL, label, sizeof(label)-1 },
		//CKA_COPYABLE
		//CKA_DESTROYABLE

		// Data
	 };

	hObject = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject) );
}

CK_RV ObjectTests::createDataObjectMCD(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_BBOOL bModifiable, CK_BBOOL bCopyable, CK_BBOOL bDestroyable, CK_OBJECT_HANDLE &hObject)
{
	CK_OBJECT_CLASS cClass = CKO_DATA;
	CK_UTF8CHAR label[] = "A data object";
	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },

		// Storage
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable) },
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_COPYABLE, &bCopyable, sizeof(bCopyable) },
		{ CKA_DESTROYABLE, &bDestroyable, sizeof(bDestroyable) }

		// Data
	 };

	hObject = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject) );
}

CK_RV ObjectTests::createDataObjectNormal(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject)
{
	CK_OBJECT_CLASS cClass = CKO_DATA;
	CK_UTF8CHAR label[] = "A data object";

	CK_UTF8CHAR application[] = "An application";
	CK_BYTE objectID[] = "invalid object id";
	CK_BYTE data[] = "Sample data";

	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },

		// Storage
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		//CKA_MODIFIABLE
		{ CKA_LABEL, label, sizeof(label)-1 },
		//CKA_COPYABLE
		//CKA_DESTROYABLE

		// Data
		{ CKA_APPLICATION, application, sizeof(application)-1 },
		{ CKA_OBJECT_ID, objectID, sizeof(objectID) },
		{ CKA_VALUE, data, sizeof(data) }
	};

	hObject = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject) );
}

CK_RV ObjectTests::createCertificateObjectIncomplete(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject)
{
	CK_OBJECT_CLASS cClass = CKO_CERTIFICATE;
	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },
		// Storage
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) }
	};

	hObject = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject) );
}

CK_RV ObjectTests::createCertificateObjectX509(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject)
{
	CK_OBJECT_CLASS cClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cType = CKC_X_509;
	const char *pSubject = "invalid subject der";
	const char *pValue = "invalid certificate der";

	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },
		// Storage
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		// Common Certificate Object Attributes
		{ CKA_CERTIFICATE_TYPE, &cType, sizeof(cType) },
		// X.509 Certificate Object Attributes
		{ CKA_SUBJECT, (CK_VOID_PTR)pSubject, strlen(pSubject) },
		{ CKA_VALUE, (CK_VOID_PTR)pValue, strlen(pValue) }
	};

	hObject = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject) );
}

CK_RV ObjectTests::generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 1536;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk) );
}

void ObjectTests::testCreateObject()
{
//    printf("\ntestCreateObject\n");

	// [PKCS#11 v2.40, C_CreateObject]
	// a. Only session objects can be created during read-only session.
	// b. Only public objects can be created unless the normal user is logged in.
	// c. Key object will have CKA_LOCAL == CK_FALSE.
	// d. If key object is secret or a private key then both CKA_ALWAYS_SENSITIVE == CK_FALSE and CKA_NEVER_EXTRACTABLE == CKA_FALSE.

	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;

	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE genKeyType = CKK_GENERIC_SECRET;
	CK_BYTE keyPtr[128];
	CK_ULONG keyLen = 128;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE, keyPtr, keyLen }
	};

	CK_BBOOL local;
	CK_BBOOL always;
	CK_BBOOL never;
	CK_ATTRIBUTE getTemplate[] = {
		{ CKA_LOCAL, &local, sizeof(local) },
		{ CKA_ALWAYS_SENSITIVE, &always, sizeof(always) },
		{ CKA_NEVER_EXTRACTABLE, &never, sizeof(never) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	/////////////////////////////////
	// READ-ONLY & PUBLIC
	/////////////////////////////////

	// Open read-only session and don't login
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Only public objects can be created unless the normal user is logged in
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// We should not be allowed to create token objects because the session is read-only
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	/////////////////////////////////
	// READ-ONLY & USER
	/////////////////////////////////

	// Login USER into the read-only session
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create private session objects
	rv  = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should not be allowed to create token objects.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	/////////////////////////////////
	// READ-WRITE & PUBLIC
	/////////////////////////////////

	// Open as read-write session but don't login.
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv ==  CKR_USER_NOT_LOGGED_IN);

	// We should be allowed to create public token objects even when not logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv ==  CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should not be able to create private token objects because we are not logged in now
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	/////////////////////////////////
	// READ-WRITE & USER
	/////////////////////////////////

	// Open as read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login to the read-write session
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should always be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be able allowed to create private session objects because we are logged in.
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create public token objects even when not logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be able to create private token objects because we are logged in now
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	/////////////////////////////////
	// READ-WRITE & SO
	/////////////////////////////////

	// Open as read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login to the read-write session
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_SO,m_soPin1,m_soPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should always be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Only public objects can be created unless the normal user is logged in.
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// We should be allowed to create public token objects even when not logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Only public objects can be created unless the normal user is logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	/////////////////////////////////
	// READ-WRITE & USER
	/////////////////////////////////

	// Open as read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login to the read-write session
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Create a secret object
	rv = CRYPTOKI_F_PTR( C_GenerateRandom(hSession, keyPtr, keyLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check value
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, getTemplate, 3) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(local == CK_FALSE);
	CPPUNIT_ASSERT(always == CK_FALSE);
	CPPUNIT_ASSERT(never == CK_FALSE);

	// Destroy the secret object
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testCopyObject()
{
//    printf("\ntestCopyObject\n");

	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;
	CK_OBJECT_HANDLE hObjectCopy;
	CK_OBJECT_HANDLE hObject1;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session and don't login
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Get a public session object
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMCD(hSession, IN_SESSION, IS_PUBLIC, CK_TRUE, CK_FALSE, CK_TRUE, hObjectCopy);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Allowed to copy it
	const char *pLabel = "Label modified via C_CopyObject";
	CK_BBOOL bToken = CK_FALSE;
	CK_BBOOL bPrivate = CK_FALSE;
	CK_OBJECT_CLASS cClass = CKO_DATA;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)pLabel, strlen(pLabel) },
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_CLASS, &cClass, sizeof(cClass) }
	};
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 1, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Not allowed to copy.
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObjectCopy, &attribs[0], 1, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_ACTION_PROHIBITED);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hObjectCopy) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Still allowed when still session and public
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 3, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Not allowed to overwrite an !ck8 attribute
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 4, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);

	// Not allowed to go on token
	bToken = CK_TRUE;
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 3, &hObject1) );
	bToken = CK_FALSE;
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	// Not allowed to go to private
	bPrivate = CK_TRUE;
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 3, &hObject1) );
	bPrivate = CK_FALSE;
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create a read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private object
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Get a public session object
	rv = createDataObjectNormal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Allowed to go on token
	bToken = CK_TRUE;
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 3, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Allowed to go to private
	bPrivate = CK_TRUE;
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 3, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hObject1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Not allowed to change a !ck8 parameter
	CK_BYTE id[] = "Another object ID";
	attribs[3].type = CKA_OBJECT_ID;
	attribs[3].pValue = id;
	attribs[3].ulValueLen = sizeof(id);
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 4, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);

	// Not allowed to downgrade privacy
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectNormal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	bToken = CK_FALSE;
	bPrivate = CK_FALSE;
	rv = CRYPTOKI_F_PTR( C_CopyObject(hSession, hObject, &attribs[0], 3, &hObject1) );
	CPPUNIT_ASSERT(rv == CKR_TEMPLATE_INCONSISTENT);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testDestroyObject()
{
//    printf("\ntestDestroyObject\n");

	// [PKCS#11 v2.40, C_Logout] When logout is successful...
	// a. Any of the application's handles to private objects become invalid.
	// b. Even if a user is later logged back into the token those handles remain invalid.
	// c. All private session objects from sessions belonging to the application area destroyed.

	// [PKCS#11 v2.40, C_CreateObject]
	// Only session objects can be created during read-only session.
	// Only public objects can be created unless the normal user is logged in.

	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;
	CK_OBJECT_HANDLE hObjectSessionPrivate;
	CK_OBJECT_HANDLE hObjectTokenPublic;
	CK_OBJECT_HANDLE hObjectTokenPrivate;
	CK_OBJECT_HANDLE hObjectDestroy;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Try to destroy an invalid object using an invalid session
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRO,CK_INVALID_HANDLE) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	// Create a read-only session.
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Trying to destroy an invalid object in a read-only session
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRO,CK_INVALID_HANDLE) );
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// Create a read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Trying to destroy an invalid object in a read-write session
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRO,CK_INVALID_HANDLE) );
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Create all permutations of session/token, public/private objects
	rv = createDataObjectMinimal(hSessionRW, IN_SESSION, IS_PUBLIC, hObjectSessionPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, IN_SESSION, IS_PRIVATE, hObjectSessionPrivate);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, ON_TOKEN, IS_PUBLIC, hObjectTokenPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, ON_TOKEN, IS_PRIVATE, hObjectTokenPrivate);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMCD(hSessionRW, IN_SESSION, IS_PUBLIC, CK_TRUE, CK_TRUE, CK_FALSE, hObjectDestroy);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should not be able to destroy a non-destroyable object.
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRO,hObjectDestroy) );
	CPPUNIT_ASSERT(rv == CKR_ACTION_PROHIBITED);

	// On a read-only session we should not be able to destroy the public token object
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRO,hObjectTokenPublic) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	// On a read-only session we should not be able to destroy the private token object
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRO,hObjectTokenPrivate) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	// Logout with a different session than the one used for login should be fine.
	rv = CRYPTOKI_F_PTR( C_Logout(hSessionRW) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Login USER into the sessions so we can destroy private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should be able to destroy the public session object from a read-only session.
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRO,hObjectSessionPublic) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// All private session objects should have been destroyed when logging out.
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRW,hObjectSessionPrivate) );
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// We should be able to destroy the public token object now.
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRW,hObjectTokenPublic) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// All handles to private token objects should have been invalidated when logging out.
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSessionRW,hObjectTokenPrivate) );
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testGetObjectSize()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open a session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Get an object
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Get the object size
	CK_ULONG objectSize;
	rv = CRYPTOKI_F_PTR( C_GetObjectSize(hSession, hObject, &objectSize) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(objectSize == CK_UNAVAILABLE_INFORMATION);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testGetAttributeValue()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Try to destroy an invalid object using an invalid session
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSessionRO,CK_INVALID_HANDLE,NULL,1) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	// Create all permutations of session/token, public/private objects
	rv = createDataObjectMinimal(hSessionRO, IN_SESSION, IS_PUBLIC, hObjectSessionPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_CLASS cClass = CKO_VENDOR_DEFINED;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_CLASS, &cClass, sizeof(cClass) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue (hSessionRO,hObjectSessionPublic,&attribs[0],1) );//sizeof(attribs)/sizeof(CK_ATTRIBUTE));
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testSetAttributeValue()
{
	// [PKCS#11 v2.40, 4.1.1 Creating objects]
	//    1. If the supplied template specifies a value for an invalid attribute, then the attempt
	//    should fail with the error code CKR_ATTRIBUTE_TYPE_INVALID. An attribute
	//    is valid if it is either one of the attributes described in the Cryptoki specification or an
	//    additional vendor-specific attribute supported by the library and token.
	//
	//    2. If the supplied template specifies an invalid value for a valid attribute, then the
	//    attempt should fail with the error code CKR_ATTRIBUTE_VALUE_INVALID.
	//    The valid values for Cryptoki attributes are described in the Cryptoki specification.
	//
	//    3. If the supplied template specifies a value for a read-only attribute, then the attempt
	//    should fail with the error code CKR_ATTRIBUTE_READ_ONLY. Whether or not a
	//    given Cryptoki attribute is read-only is explicitly stated in the Cryptoki specification;
	//    however, a particular library and token may be even more restrictive than Cryptoki
	//    specifies. In other words, an attribute which Cryptoki says is not read-only may
	//    nonetheless be read-only under certain circumstances (i.e., in conjunction with some
	//    combinations of other attributes) for a particular library and token. Whether or not a
	//    given non-Cryptoki attribute is read-only is obviously outside the scope of Cryptoki.
	//
	//    4. N/A (Does not apply to C_SetAttributeValue)
	//
	//    5. If the attribute values in the supplied template, together with any default attribute
	//    values and any attribute values contributed to the object by the object-creation
	//    function itself, are inconsistent, then the attempt should fail with the error code
	//    CKR_TEMPLATE_INCONSISTENT. A set of attribute values is inconsistent if not
	//    all of its members can be satisfied simultaneously by the token, although each value
	//    individually is valid in Cryptoki. One example of an inconsistent template would be
	//    using a template which specifies two different values for the same attribute. Another
	//    example would be trying to create a secret key object with an attribute which is
	//    appropriate for various types of public keys or private keys, but not for secret keys.
	//    A final example would be a template with an attribute that violates some token
	//    specific requirement. Note that this final example of an inconsistent template is
	//    token-dependent—on a different token, such a template might not be inconsistent.
	//
	//    6. If the supplied template specifies the same value for a particular attribute more than
	//    once (or the template specifies the same value for a particular attribute that the object-
	//    creation function itself contributes to the object), then the behavior of Cryptoki is not
	//    completely specified. The attempt to create an object can either succeed—thereby
	//    creating the same object that would have been created if the multiply-specified
	//    attribute had only appeared once—or it can fail with error code
	//    CKR_TEMPLATE_INCONSISTENT. Library developers are encouraged to make
	//    their libraries behave as though the attribute had only appeared once in the template;
	//    application developers are strongly encouraged never to put a particular attribute into
	//    a particular template more than once.

	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;
	CK_OBJECT_HANDLE hObjectSessionPrivate;
	CK_OBJECT_HANDLE hObjectTokenPublic;
	CK_OBJECT_HANDLE hObjectTokenPrivate;
	CK_OBJECT_HANDLE hObjectSet;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Create all permutations of session/token, public/private objects
	rv = createDataObjectMinimal(hSessionRO, IN_SESSION, IS_PUBLIC, hObjectSessionPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, IN_SESSION, IS_PRIVATE, hObjectSessionPrivate);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, ON_TOKEN, IS_PUBLIC, hObjectTokenPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, ON_TOKEN, IS_PRIVATE, hObjectTokenPrivate);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMCD(hSessionRO, IN_SESSION, IS_PUBLIC, CK_FALSE, CK_TRUE, CK_TRUE, hObjectSet);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check that label can be modified on all combintations of session/token and public/private objects
	const char  *pLabel = "Label modified via C_SetAttributeValue";
	CK_ATTRIBUTE attribs[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)pLabel, strlen(pLabel) }
	};

	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRO,hObjectSessionPublic,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRO,hObjectSessionPrivate,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRO,hObjectTokenPublic,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRW,hObjectTokenPublic,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRO,hObjectTokenPrivate,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRW,hObjectTokenPrivate,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRO,hObjectSet,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_ACTION_PROHIBITED);

	attribs[0].pValue = NULL_PTR;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSessionRO,hObjectSessionPublic,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == strlen(pLabel));

	char pStoredLabel[64];
	attribs[0].pValue = &pStoredLabel[0];
	attribs[0].ulValueLen = 64;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSessionRO,hObjectSessionPublic,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == strlen(pLabel));
	CPPUNIT_ASSERT(memcmp(pLabel,pStoredLabel,strlen(pLabel)) == 0);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testFindObjects()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;
	CK_OBJECT_HANDLE hObjectSessionPrivate;
	CK_OBJECT_HANDLE hObjectTokenPublic;
	CK_OBJECT_HANDLE hObjectTokenPrivate;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Create all permutations of session/token, public/private objects
	rv = createDataObjectMinimal(hSessionRO, IN_SESSION, IS_PUBLIC, hObjectSessionPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, IN_SESSION, IS_PRIVATE, hObjectSessionPrivate);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, ON_TOKEN, IS_PUBLIC, hObjectTokenPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = createDataObjectMinimal(hSessionRW, ON_TOKEN, IS_PRIVATE, hObjectTokenPrivate);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Set labels for the objects
	const char  *pLabel = "Label modified via C_SetAttributeValue";
	CK_ATTRIBUTE attribs[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)pLabel, strlen(pLabel) }
	};
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRO,hObjectSessionPublic,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRO,hObjectSessionPrivate,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRW,hObjectTokenPublic,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue (hSessionRW,hObjectTokenPrivate,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now find the objects while logged in should find them all.
	rv = CRYPTOKI_F_PTR( C_FindObjectsInit(hSessionRO,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_OBJECT_HANDLE hObjects[16];
	CK_ULONG ulObjectCount = 0;
	rv = CRYPTOKI_F_PTR( C_FindObjects(hSessionRO,&hObjects[0],16,&ulObjectCount) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(4 == ulObjectCount);
	rv = CRYPTOKI_F_PTR( C_FindObjectsFinal(hSessionRO) );


	rv = CRYPTOKI_F_PTR( C_Logout(hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now find the objects while no longer logged in should find only 2
	rv = CRYPTOKI_F_PTR( C_FindObjectsInit(hSessionRO,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_FindObjects(hSessionRO,&hObjects[0],16,&ulObjectCount) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(2 == ulObjectCount);
	rv = CRYPTOKI_F_PTR( C_FindObjectsFinal(hSessionRO) );

	// Close the session used to create the session objects, should also destroy the session objects.
	rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now find just the public token object as public session object should be gone now.
	rv = CRYPTOKI_F_PTR( C_FindObjectsInit(hSessionRW,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_FindObjects(hSessionRW,&hObjects[0],16,&ulObjectCount) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(1 == ulObjectCount);
	rv = CRYPTOKI_F_PTR( C_FindObjectsFinal(hSessionRW) );

	// Login USER into the sessions so we can gain access to private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Now find just the public token object as public session object should be gone now.
	rv = CRYPTOKI_F_PTR( C_FindObjectsInit(hSessionRW,&attribs[0],1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_FindObjects(hSessionRW,&hObjects[0],16,&ulObjectCount) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(2 == ulObjectCount);
	rv = CRYPTOKI_F_PTR( C_FindObjectsFinal(hSessionRW) );
}


void ObjectTests::testGenerateKeys()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	// Generate all combinations of session/token public/private key pairs.
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PRIVATE,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PUBLIC,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PRIVATE,IN_SESSION,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PRIVATE,IN_SESSION,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PUBLIC,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = generateRsaKeyPair(hSessionRW,ON_TOKEN,IS_PRIVATE,ON_TOKEN,IS_PRIVATE,hPuk,hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testCreateCertificates()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

	rv = createCertificateObjectIncomplete(hSession,IN_SESSION,IS_PUBLIC,hObject);
	CPPUNIT_ASSERT(rv == CKR_TEMPLATE_INCOMPLETE);
	rv = createCertificateObjectX509(hSession,IN_SESSION,IS_PUBLIC,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_BYTE pCheckValue[] = { 0x2b, 0x84, 0xf6 };
	CK_ATTRIBUTE attribs[] = {
		{ CKA_CHECK_VALUE, pCheckValue, sizeof(pCheckValue) }
	};

	rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hObject, attribs, 1) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);
}

void ObjectTests::testDefaultDataAttributes()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

	// Minimal data object
	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create minimal data object
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check attributes in data object
	checkCommonObjectAttributes(hSession, hObject, objClass);
	checkCommonStorageObjectAttributes(hSession, hObject, CK_FALSE, CK_TRUE, CK_TRUE, NULL_PTR, 0, CK_TRUE, CK_TRUE);
	checkDataObjectAttributes(hSession, hObject, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, 0);
}

void ObjectTests::testDefaultX509CertAttributes()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

	// Minimal X509 certificate object
	CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certificateType = CKC_X_509;
	CK_BYTE pSubject[] = "Test1";
	CK_BYTE pValue[] = "Test2";
	CK_BYTE pCheckValue[] = { 0x2b, 0x84, 0xf6 };
	CK_DATE emptyDate;
	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType) },
		{ CKA_SUBJECT, pSubject, sizeof(pSubject)-1 },
		{ CKA_VALUE, pValue, sizeof(pValue)-1 }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create minimal X509 certificate
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check attributes in X509 certificate object
	checkCommonObjectAttributes(hSession, hObject, objClass);
	checkCommonStorageObjectAttributes(hSession, hObject, CK_FALSE, CK_FALSE, CK_TRUE, NULL_PTR, 0, CK_TRUE, CK_TRUE);
	memset(&emptyDate, 0, sizeof(emptyDate));
	checkCommonCertificateObjectAttributes(hSession, hObject, CKC_X_509, CK_FALSE, 0, pCheckValue, sizeof(pCheckValue), emptyDate, 0, emptyDate, 0);
	checkX509CertificateObjectAttributes(hSession, hObject, pSubject, sizeof(pSubject)-1, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, 0, pValue, sizeof(pValue)-1, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, 0, 0, CKM_SHA_1);
}

void ObjectTests::testDefaultRSAPubAttributes()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

	// Minimal RSA public key object
	CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE objType = CKK_RSA;
	CK_BYTE pN[] = { 0xC6, 0x47, 0xDD, 0x74, 0x3B, 0xCB, 0xDC, 0x6F, 0xCE, 0xA7,
			 0xF0, 0x5F, 0x29, 0x4B, 0x27, 0x00, 0xCC, 0x92, 0xE9, 0x20,
			 0x8A, 0x2C, 0x87, 0x36, 0x47, 0x24, 0xB0, 0xD5, 0x7D, 0xB0,
			 0x92, 0x01, 0xA0, 0xA3, 0x55, 0x2E, 0x3F, 0xFE, 0xA7, 0x4C,
			 0x4B, 0x3F, 0x9D, 0x4E, 0xCB, 0x78, 0x12, 0xA9, 0x42, 0xAD,
			 0x51, 0x1F, 0x3B, 0xBD, 0x3D, 0x6A, 0xE5, 0x38, 0xB7, 0x45,
			 0x65, 0x50, 0x30, 0x35 };
        CK_BYTE pE[] = { 0x01, 0x00, 0x01 };
	CK_DATE emptyDate;
	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_KEY_TYPE, &objType, sizeof(objType) },
		{ CKA_MODULUS, pN, sizeof(pN) },
		{ CKA_PUBLIC_EXPONENT, pE, sizeof(pE) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create minimal RSA public key object
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check attributes in RSA public key object
	checkCommonObjectAttributes(hSession, hObject, objClass);
	checkCommonStorageObjectAttributes(hSession, hObject, CK_FALSE, CK_FALSE, CK_TRUE, NULL_PTR, 0, CK_TRUE, CK_TRUE);
	memset(&emptyDate, 0, sizeof(emptyDate));
	checkCommonKeyAttributes(hSession, hObject, objType, NULL_PTR, 0, emptyDate, 0, emptyDate, 0, CK_FALSE, CK_FALSE, CK_UNAVAILABLE_INFORMATION, NULL_PTR, 0);
	checkCommonPublicKeyAttributes(hSession, hObject, NULL_PTR, 0, CK_TRUE, CK_TRUE, CK_TRUE, CK_TRUE, CK_FALSE, NULL_PTR, 0);
	checkCommonRSAPublicKeyAttributes(hSession, hObject, pN, sizeof(pN), 512, pE, sizeof(pE));
}

void ObjectTests::testDefaultRSAPrivAttributes()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

	// Minimal RSA private key object
	CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE objType = CKK_RSA;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BYTE pN[] = { 0xC6, 0x47, 0xDD, 0x74, 0x3B, 0xCB, 0xDC, 0x6F, 0xCE, 0xA7,
			 0xF0, 0x5F, 0x29, 0x4B, 0x27, 0x00, 0xCC, 0x92, 0xE9, 0x20,
			 0x8A, 0x2C, 0x87, 0x36, 0x47, 0x24, 0xB0, 0xD5, 0x7D, 0xB0,
			 0x92, 0x01, 0xA0, 0xA3, 0x55, 0x2E, 0x3F, 0xFE, 0xA7, 0x4C,
			 0x4B, 0x3F, 0x9D, 0x4E, 0xCB, 0x78, 0x12, 0xA9, 0x42, 0xAD,
			 0x51, 0x1F, 0x3B, 0xBD, 0x3D, 0x6A, 0xE5, 0x38, 0xB7, 0x45,
			 0x65, 0x50, 0x30, 0x35 };
        CK_BYTE pD[] = { 0x6D, 0x94, 0x6B, 0xEB, 0xFF, 0xDC, 0x03, 0x80, 0x7B, 0x0A,
			 0x4F, 0x0A, 0x98, 0x6C, 0xA3, 0x2A, 0x8A, 0xE4, 0xAA, 0x18,
			 0x44, 0xA4, 0xA5, 0x39, 0x37, 0x0A, 0x2C, 0xFC, 0x5F, 0xD1,
			 0x44, 0x6E, 0xCE, 0x25, 0x9B, 0xE5, 0xD1, 0x51, 0xAF, 0xA8,
			 0x30, 0xD1, 0x4D, 0x3C, 0x60, 0x33, 0xB5, 0xED, 0x4C, 0x39,
			 0xDA, 0x68, 0x78, 0xF9, 0x6B, 0x4F, 0x47, 0x55, 0xB2, 0x02,
			 0x00, 0x7E, 0x9C, 0x05 };
	CK_DATE emptyDate;
	// Make the key non-sensitive and extractable so that we can test it.
	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_KEY_TYPE, &objType, sizeof(objType) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_MODULUS, pN, sizeof(pN) },
		{ CKA_PRIVATE_EXPONENT, pD, sizeof(pD) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create minimal RSA public key object
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check attributes in RSA public key object
	checkCommonObjectAttributes(hSession, hObject, objClass);
	checkCommonStorageObjectAttributes(hSession, hObject, CK_FALSE, CK_TRUE, CK_TRUE, NULL_PTR, 0, CK_TRUE, CK_TRUE);
	memset(&emptyDate, 0, sizeof(emptyDate));
	checkCommonKeyAttributes(hSession, hObject, objType, NULL_PTR, 0, emptyDate, 0, emptyDate, 0, CK_FALSE, CK_FALSE, CK_UNAVAILABLE_INFORMATION, NULL_PTR, 0);
	checkCommonPrivateKeyAttributes(hSession, hObject, NULL_PTR, 0, CK_FALSE, CK_TRUE, CK_TRUE, CK_TRUE, CK_TRUE, CK_TRUE, CK_FALSE, CK_FALSE, CK_FALSE, NULL_PTR, 0, CK_FALSE);
	checkCommonRSAPrivateKeyAttributes(hSession, hObject, pN, sizeof(pN), NULL_PTR, 0, pD, sizeof(pD), NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, 0);
}

void ObjectTests::testAlwaysNeverAttribute()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 1536;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL always;
	CK_BBOOL never;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};
	CK_ATTRIBUTE getTemplate[] = {
		{ CKA_ALWAYS_SENSITIVE, &always, sizeof(always) },
		{ CKA_NEVER_EXTRACTABLE, &never, sizeof(never) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create object
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism, pukAttribs, 1, prkAttribs, 2, &hPuk, &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check value
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, getTemplate, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(always == CK_TRUE);
	CPPUNIT_ASSERT(never == CK_TRUE);

	// Set value
	rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPrk, prkAttribs, 2) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);

	// Create object
	prkAttribs[0].pValue = &bFalse;
	prkAttribs[1].pValue = &bTrue;
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism, pukAttribs, 1, prkAttribs, 2, &hPuk, &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check value
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, getTemplate, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(always == CK_FALSE);
	CPPUNIT_ASSERT(never == CK_FALSE);
}

void ObjectTests::testSensitiveAttributes()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 1536;
	CK_BBOOL bSensitive = CK_TRUE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) }
	};
	// Sensitive attributes cannot be revealed in plaintext even if wrapping is allowed
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_SENSITIVE, &bSensitive, sizeof(bSensitive) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};
	CK_ATTRIBUTE getTemplate[] = {
		{ CKA_PRIVATE_EXPONENT, NULL_PTR, 0 },
		{ CKA_PRIME_1, NULL_PTR, 0 },
		{ CKA_PRIME_2, NULL_PTR, 0 },
		{ CKA_EXPONENT_1, NULL_PTR, 0 },
		{ CKA_EXPONENT_2, NULL_PTR, 0 },
		{ CKA_COEFFICIENT, NULL_PTR, 0 }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create object
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism, pukAttribs, 1, prkAttribs, 2, &hPuk, &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check value
	for (int i = 0; i < 6; i++)
	{
		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, &getTemplate[i], 1) );
		CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_SENSITIVE);
	}

	// Retry with non-sensitive object
	bSensitive = CK_FALSE;
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism, pukAttribs, 1, prkAttribs, 2, &hPuk, &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check value
	for (int i = 0; i < 6; i++)
	{
		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, &getTemplate[i], 1) );
		CPPUNIT_ASSERT(rv == CKR_OK);
	}
}

void ObjectTests::testGetInvalidAttribute()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

	// Minimal data object
	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_BBOOL bSign;
	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) }
	};
	CK_ATTRIBUTE getTemplate[] = {
		{ CKA_SIGN, &bSign, sizeof(bSign) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create minimal data object
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, 1, &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Check value
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, getTemplate, 1) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);
}

void ObjectTests::testReAuthentication()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 1024;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_ALWAYS_AUTHENTICATE, &bTrue, sizeof(bTrue) }
	};

	CK_MECHANISM signMech = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE signature256[256];
	CK_ULONG signature256Len = sizeof(signature256);

	CK_MECHANISM encMech = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE cipherText[256];
	CK_ULONG ulCipherTextLen = sizeof(cipherText);
	CK_BYTE recoveredText[256];
	CK_ULONG ulRecoveredTextLen = sizeof(recoveredText);

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create object
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism, pukAttribs, 1, prkAttribs, 4, &hPuk, &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test C_Sign with re-authentication with invalid and valid PIN
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_CONTEXT_SPECIFIC,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &signMech, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_CONTEXT_SPECIFIC,m_userPin1,m_userPin1Length-1) );
	CPPUNIT_ASSERT(rv == CKR_PIN_INCORRECT);
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_CONTEXT_SPECIFIC,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession, data, sizeof(data), signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test C_Sign without re-authentication
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &signMech, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession, data, sizeof(data), signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession, data, sizeof(data), signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	// Test C_SignUpdate with re-authentication
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &signMech, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_CONTEXT_SPECIFIC,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SignUpdate(hSession, data, sizeof(data)) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SignFinal(hSession, signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test C_SignUpdate without re-authentication
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &signMech, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SignUpdate(hSession, data, sizeof(data)) );
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);
	rv = CRYPTOKI_F_PTR( C_SignUpdate(hSession, data, sizeof(data)) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	// Test C_SignFinal with re-authentication
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &signMech, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_CONTEXT_SPECIFIC,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SignFinal(hSession, signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test C_SignFinal without re-authentication
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &signMech, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_SignFinal(hSession, signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);
	rv = CRYPTOKI_F_PTR( C_SignFinal(hSession, signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	// Encrypt some data
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&encMech,hPuk) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,data,sizeof(data),cipherText,&ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Test C_Decrypt with re-authentication
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&encMech,hPrk) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_CONTEXT_SPECIFIC,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(memcmp(data, &recoveredText[ulRecoveredTextLen-sizeof(data)], sizeof(data)) == 0);

	// Test C_Decrypt without re-authentication
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&encMech,hPrk) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen) );
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);
}

void ObjectTests::testAllowedMechanisms()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_BYTE key[65] = { "0000000000000000000000000000000000000000000000000000000000000000" };
	CK_MECHANISM_TYPE allowedMechs[] = { CKM_SHA256_HMAC, CKM_SHA512_HMAC };
	CK_ATTRIBUTE attribs[] = {
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_CLASS, &secretClass, sizeof(secretClass) },
			{ CKA_VALUE, &key, sizeof(key)-1 },
			{ CKA_ALLOWED_MECHANISMS, &allowedMechs, sizeof(allowedMechs) }
	};

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	// SHA_1_HMAC is not an allowed mechanism
	CK_MECHANISM mechanism = { CKM_SHA_1_HMAC, NULL_PTR, 0 };
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hKey) );
	CPPUNIT_ASSERT(rv == CKR_MECHANISM_INVALID);

	// SHA256_HMAC is an allowed mechanism
	mechanism.mechanism = CKM_SHA256_HMAC;
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_BYTE signature256[256];
	CK_ULONG signature256Len = sizeof(signature256);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession, data, sizeof(data), signature256, &signature256Len) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// SHA384_HMAC is not an allowed mechanism
	mechanism.mechanism = CKM_SHA384_HMAC;
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hKey) );
	CPPUNIT_ASSERT(rv == CKR_MECHANISM_INVALID);

	// SHA512_HMAC is an allowed mechanism
	mechanism.mechanism = CKM_SHA512_HMAC;
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mechanism, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_BYTE signature512[512];
	CK_ULONG signature512Len = sizeof(signature512);
	rv = CRYPTOKI_F_PTR( C_Sign(hSession, data, sizeof(data), signature512, &signature512Len) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testTemplateAttribute()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
	CK_BYTE pE[] = { 0x01, 0x00, 0x01 };
	CK_MECHANISM_TYPE allowedMechs[] = { CKM_SHA256_HMAC, CKM_SHA512_HMAC };

	// Wrap template
	CK_KEY_TYPE wrapType = CKK_SHA256_HMAC;;
	CK_ATTRIBUTE wrapTemplate[] = {
		{ CKA_KEY_TYPE, &wrapType, sizeof(wrapType) },
		{ CKA_PUBLIC_EXPONENT, pE, sizeof(pE) },
		{ CKA_ALLOWED_MECHANISMS, &allowedMechs, sizeof(allowedMechs) }
	};

	// Minimal public key object
	CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE objType = CKK_RSA;
	CK_BYTE pN[] = { 0xC6, 0x47, 0xDD, 0x74, 0x3B, 0xCB, 0xDC, 0x6F, 0xCE, 0xA7,
			 0xF0, 0x5F, 0x29, 0x4B, 0x27, 0x00, 0xCC, 0x92, 0xE9, 0x20,
			 0x8A, 0x2C, 0x87, 0x36, 0x47, 0x24, 0xB0, 0xD5, 0x7D, 0xB0,
			 0x92, 0x01, 0xA0, 0xA3, 0x55, 0x2E, 0x3F, 0xFE, 0xA7, 0x4C,
			 0x4B, 0x3F, 0x9D, 0x4E, 0xCB, 0x78, 0x12, 0xA9, 0x42, 0xAD,
			 0x51, 0x1F, 0x3B, 0xBD, 0x3D, 0x6A, 0xE5, 0x38, 0xB7, 0x45,
			 0x65, 0x50, 0x30, 0x35 };
	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_KEY_TYPE, &objType, sizeof(objType) },
		{ CKA_MODULUS, pN, sizeof(pN) },
		{ CKA_PUBLIC_EXPONENT, pE, sizeof(pE) },
		{ CKA_WRAP_TEMPLATE, wrapTemplate, sizeof(wrapTemplate) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Create minimal RSA public key object
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_ATTRIBUTE wrapAttribs[] = {
		{ 0, NULL_PTR, 0 },
		{ 0, NULL_PTR, 0 },
		{ 0, NULL_PTR, 0 }
	};
	CK_ATTRIBUTE wrapAttrib = { CKA_WRAP_TEMPLATE, NULL_PTR, 0 };

	// Get number of elements
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &wrapAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(wrapAttrib.ulValueLen == 3 * sizeof(CK_ATTRIBUTE));

	// Get element types and sizes
	wrapAttrib.pValue = wrapAttribs;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &wrapAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(wrapAttrib.ulValueLen == 3 * sizeof(CK_ATTRIBUTE));
	for (size_t i = 0; i < 3; i++)
	{
		switch (wrapAttribs[i].type)
		{
			case CKA_KEY_TYPE:
				CPPUNIT_ASSERT(wrapAttribs[i].ulValueLen == sizeof(CK_KEY_TYPE));
				break;
			case CKA_PUBLIC_EXPONENT:
				CPPUNIT_ASSERT(wrapAttribs[i].ulValueLen == sizeof(pE));
				break;
			case CKA_ALLOWED_MECHANISMS:
				CPPUNIT_ASSERT(wrapAttribs[i].ulValueLen == sizeof(allowedMechs));
				break;
			default:
				CPPUNIT_ASSERT(false);
		}
	}

	// Get values
	wrapAttribs[0].pValue = (CK_VOID_PTR)malloc(wrapAttribs[0].ulValueLen);
	wrapAttribs[1].pValue = (CK_VOID_PTR)malloc(wrapAttribs[1].ulValueLen);
	wrapAttribs[2].pValue = (CK_VOID_PTR)malloc(wrapAttribs[2].ulValueLen);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, &wrapAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	for (size_t i = 0; i < 3; i++)
	{
		switch (wrapAttribs[i].type)
		{
			case CKA_KEY_TYPE:
				CPPUNIT_ASSERT(*(CK_KEY_TYPE*) wrapAttribs[i].pValue == CKK_SHA256_HMAC);
				break;
			case CKA_PUBLIC_EXPONENT:
				CPPUNIT_ASSERT(memcmp(wrapAttribs[i].pValue, pE, sizeof(pE)) == 0);
				break;
			case CKA_ALLOWED_MECHANISMS:
				CPPUNIT_ASSERT(memcmp(wrapAttribs[i].pValue, allowedMechs, sizeof(allowedMechs)) == 0);
				break;
			default:
				CPPUNIT_ASSERT(false);
		}
	}

	free(wrapAttribs[0].pValue);
	free(wrapAttribs[1].pValue);
	free(wrapAttribs[2].pValue);
}

void ObjectTests::testCreateSecretKey()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_BYTE genericKey[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06
	};
	CK_BYTE aesKey[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06
	};
	CK_BYTE desKey[] = {
		0x81, 0xdc, 0x9b, 0xdb, 0x52, 0xd0, 0x4d, 0xc2
	};
	CK_BYTE des2Key[] = {
		0x81, 0xdc, 0x9b, 0xdb, 0x52, 0xd0, 0x4d, 0xc2, 0x00, 0x36,
		0xdb, 0xd8, 0x31, 0x3e, 0xd0, 0x55
	};
	CK_BYTE des3Key[] = {
		0x81, 0xdc, 0x9b, 0xdb, 0x52, 0xd0, 0x4d, 0xc2, 0x00, 0x36,
		0xdb, 0xd8, 0x31, 0x3e, 0xd0, 0x55, 0xcc, 0x57, 0x76, 0xd1,
		0x6a, 0x1f, 0xb6, 0xe4
	};
	CK_BYTE genericKCV[] = { 0x5c, 0x3b, 0x7c };
	CK_BYTE aesKCV[] =     { 0x08, 0xbd, 0x28 };
	CK_BYTE desKCV[] =     { 0x08, 0xa1, 0x50 };
	CK_BYTE des2KCV[] =    { 0xa9, 0x67, 0xae };
	CK_BYTE des3KCV[] =    { 0x5c, 0x5e, 0xec };

	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_VALUE, genericKey, sizeof(genericKey) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) }
	};

	CK_BYTE pCheckValue[3];
	CK_ATTRIBUTE attribKCV[] = {
		{ CKA_CHECK_VALUE, pCheckValue, sizeof(pCheckValue) }
	};

	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, attribKCV, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribKCV[0].ulValueLen == 3);
	CPPUNIT_ASSERT(memcmp(pCheckValue, genericKCV, 3) == 0);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	keyType = CKK_AES;
	attribs[0].pValue = aesKey;
	attribs[0].ulValueLen = sizeof(aesKey);
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, attribKCV, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribKCV[0].ulValueLen == 3);
	CPPUNIT_ASSERT(memcmp(pCheckValue, aesKCV, 3) == 0);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	keyType = CKK_DES;
	attribs[0].pValue = desKey;
	attribs[0].ulValueLen = sizeof(desKey);
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, attribKCV, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribKCV[0].ulValueLen == 3);
	CPPUNIT_ASSERT(memcmp(pCheckValue, desKCV, 3) == 0);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	keyType = CKK_DES2;
	attribs[0].pValue = des2Key;
	attribs[0].ulValueLen = sizeof(des2Key);
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, attribKCV, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribKCV[0].ulValueLen == 3);
	CPPUNIT_ASSERT(memcmp(pCheckValue, des2KCV, 3) == 0);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	keyType = CKK_DES3;
	attribs[0].pValue = des3Key;
	attribs[0].ulValueLen = sizeof(des3Key);
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hObject, attribKCV, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribKCV[0].ulValueLen == 3);
	CPPUNIT_ASSERT(memcmp(pCheckValue, des3KCV, 3) == 0);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession,hObject) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

