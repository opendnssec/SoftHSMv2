/* $Id$ */

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
	 C_DestroyObject
	 C_GetAttributeValue
	 C_SetAttributeValue
	 C_FindObjectsInit
	 C_FindObjects
	 C_FindObjectsFinal
	 C_GenererateKeyPair

TODO:
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

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "ObjectTests.h"
#include "testconfig.h"

// Common object attributes
const CK_BBOOL CKA_TOKEN_DEFAULT = CK_FALSE;
//const CK_BBOOL CKA_PRIVATE_DEFAULT = <token/object attribute dependent>
const CK_BBOOL CKA_MODIFIABLE_DEFAULT = CK_TRUE;
const CK_UTF8CHAR_PTR CKA_LABEL_DEFAULT = NULL;
const CK_BBOOL CKA_COPYABLE_DEFAULT = CK_TRUE;

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

void ObjectTests::setUp()
{
//    printf("\nObjectTests\n");

	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);

	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSession;

	CK_UTF8CHAR label[32];
	memset(label, ' ', 32);
	memcpy(label, "token1", strlen("token1"));

	// (Re)initialize the token
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_InitToken(SLOT_INIT_TOKEN, sopin,sopinLength, label);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login SO
	rv = C_Login(hSession,CKU_SO, sopin, sopinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Initialize the user pin
	rv = C_InitPIN(hSession, pin, pinLength);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::tearDown()
{
	C_Finalize(NULL_PTR);
}

void ObjectTests::checkCommonObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_OBJECT_CLASS objClass)
{
}

void ObjectTests::checkCommonStorageObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_BBOOL bModifiable, CK_UTF8CHAR_PTR pLabel, CK_ULONG ulLabelLen, CK_BBOOL bCopyable)
{
}

void ObjectTests::checkDataObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_UTF8CHAR_PTR pApplication, CK_ULONG ulApplicationLen, CK_BYTE_PTR pObjectID, CK_ULONG ulObjectIdLen, CK_BYTE_PTR pValue, CK_ULONG ulValueLen)
{
}

void ObjectTests::checkCommonCertificateObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_CERTIFICATE_TYPE certType, CK_BBOOL bTrusted, CK_ULONG ulCertificateCategory, CK_BYTE_PTR pCheckValue, CK_ULONG ulCheckValueLen, CK_DATE startDate, CK_DATE endDate)
{
}

void ObjectTests::checkX509CertificateObjectAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen, CK_BYTE_PTR pId, CK_ULONG ulIdLen, CK_BYTE_PTR pIssuer, CK_ULONG ulIssuerLen, CK_BYTE_PTR pSerialNumber, CK_ULONG ulSerialNumber, CK_BYTE_PTR pValue, CK_ULONG ulValueLen, CK_BYTE_PTR pUrl, CK_ULONG ulUrlLen, CK_BYTE_PTR pHashOfSubjectPublicKey, CK_ULONG ulHashOfSubjectPublicKeyLen, CK_BYTE_PTR pHashOfIssuerPublicKey, CK_ULONG ulHashOfIssuerPublicKeyLen, CK_ULONG ulJavaMidpSecurityDomain, CK_MECHANISM_TYPE nameHashAlgorithm)
{
}

void ObjectTests::checkCommonKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_KEY_TYPE keyType, CK_BYTE_PTR pId, CK_ULONG ulIdLen, CK_DATE startDate, CK_DATE endDate, CK_BBOOL bDerive, CK_BBOOL bLocal, CK_MECHANISM_TYPE keyMechanismType, CK_MECHANISM_TYPE_PTR pAllowedMechanisms, CK_ULONG ulAllowedMechanismsLen)
{
}

void ObjectTests::checkCommonPublicKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen, CK_BBOOL bEncrypt, CK_BBOOL bVerify, CK_BBOOL bVerifyRecover, CK_BBOOL bWrap, CK_BBOOL bTrusted, CK_ATTRIBUTE_PTR pWrapTemplate, CK_ULONG ulWrapTemplateLen)
{
}

void ObjectTests::checkCommonPrivateKeyAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_BYTE_PTR pSubject, CK_ULONG ulSubjectLen, CK_BBOOL bSensitive, CK_BBOOL bDecrypt, CK_BBOOL bSign, CK_BBOOL bSignRecover, CK_BBOOL bUnwrap, CK_BBOOL bExtractable, CK_BBOOL bAlwaysSensitive, CK_BBOOL bNeverExtractable, CK_BBOOL bWrapWithTrusted, CK_ATTRIBUTE_PTR pUnwrapTemplate, CK_ULONG ulUnwrapTemplateLen, CK_BBOOL bAlwaysAuthenticate)
{
}


CK_RV ObjectTests::createDataObjectMinimal(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject)
{
	CK_RV rv;
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

		// Data
	 };

	hObject = CK_INVALID_HANDLE;
	return C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject);
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

		// Data
		{ CKA_APPLICATION, application, sizeof(application)-1 },
		{ CKA_OBJECT_ID, objectID, sizeof(objectID) },
		{ CKA_VALUE, data, sizeof(data) }
	};

	hObject = CK_INVALID_HANDLE;
	return C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject);
}

CK_RV ObjectTests::createCertificateObjectIncomplete(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject)
{
	CK_OBJECT_CLASS cClass = CKO_CERTIFICATE;
	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },
	};

	hObject = CK_INVALID_HANDLE;
	return C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject);
}

CK_RV ObjectTests::createCertificateObjectValue(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject)
{
	CK_OBJECT_CLASS cClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cType = CKC_X_509;
	const char *pSubject = "invalid subject der";
	const char *pValue = "invalid certificate der";

	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },
		// Common Certificate Object Attributes
		{ CKA_CERTIFICATE_TYPE, &cType, sizeof(cType) },
		// X.509 Certificate Object Attributes
		{ CKA_SUBJECT, (CK_VOID_PTR)pSubject, strlen(pSubject) },
		{ CKA_VALUE, (CK_VOID_PTR)pValue, strlen(pValue) }
	};

	hObject = CK_INVALID_HANDLE;
	return C_CreateObject(hSession, objTemplate, sizeof(objTemplate)/sizeof(CK_ATTRIBUTE),&hObject);
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
	return C_GenerateKeyPair(hSession, &mechanism,
							 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
							 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
							 &hPuk, &hPrk);
}

void ObjectTests::testCreateObject()
{
//    printf("\ntestCreateObject\n");

	// [PKCS#11 v2.3 p126]
	// a. Only session objects can be created during read-only session.
	// b. Only public objects can be created unless the normal user is logged in.
	// c. TODO: Key object will have CKA_LOCAL == CK_FALSE.
	// d. TODO: If key object is secret or a private key then both CKA_ALWAYS_SENSITIVE == CK_FALSE and CKA_NEVER_EXTRACTABLE == CKA_FALSE.

	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	/////////////////////////////////
	// READ-ONLY & PUBLIC
	/////////////////////////////////

	// Open read-only session and don't login
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Only public objects can be created unless the normal user is logged in
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	// [PKCS#11 v2.3 p97] seems to indicate CKR_OK while [PKCS#11 v2.3 p126] clearly indicates CKR_USER_NOT_LOGGED_IN
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
	rv = C_Login(hSession,CKU_USER,pin,pinLength);
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create private session objects
	rv  = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should not be allowed to create token objects.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	// Close session
	rv = C_CloseSession(hSession);
	CPPUNIT_ASSERT(rv==CKR_OK);

	/////////////////////////////////
	// READ-WRITE & PUBLIC
	/////////////////////////////////

	// Open as read-write session but don't login.
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// [PKCS#11 v2.3 p97] seems to indicate CKR_OK while [PKCS#11 v2.3 p126] clearly indicates CKR_USER_NOT_LOGGED_IN
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv ==  CKR_USER_NOT_LOGGED_IN);

	// We should be allowed to create public token objects even when not logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv ==  CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should not be able to create private token objects because we are not logged in now
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// Close session
	rv = C_CloseSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	/////////////////////////////////
	// READ-WRITE & USER
	/////////////////////////////////

	// Open as read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login to the read-write session
	rv = C_Login(hSession,CKU_USER,pin,pinLength);
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should always be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be able allowed to create private session objects because we are logged in.
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be allowed to create public token objects even when not logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// We should be able to create private token objects because we are logged in now
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = C_CloseSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	/////////////////////////////////
	// READ-WRITE & SO
	/////////////////////////////////

	// Open as read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login to the read-write session
	rv = C_Login(hSession,CKU_SO,sopin,sopinLength);
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should always be allowed to create public session objects
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Only public objects can be created unless the normal user is logged in.
	rv = createDataObjectMinimal(hSession, IN_SESSION, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// We should be allowed to create public token objects even when not logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PUBLIC, hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_DestroyObject(hSession,hObject);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Only public objects can be created unless the normal user is logged in.
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObject);
	CPPUNIT_ASSERT(rv == CKR_USER_NOT_LOGGED_IN);

	// Close session
	rv = C_CloseSession(hSession);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testDestroyObject()
{
//    printf("\ntestDestroyObject\n");

	// [PKCS#11 v2.3 p124] When logout is successful...
	// a. Any of the application's handles to private objects become invalid.
	// b. Even if a user is later logged back into the token those handles remain invalid.
	// c. All private session objects from sessions belonging to the application area destroyed.

	// [PKCS#11 v2.3 p126]
	// Only session objects can be created during read-only session.
	// Only public objects can be created unless the normal user is logged in.

	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;
	CK_OBJECT_HANDLE hObjectSessionPrivate;
	CK_OBJECT_HANDLE hObjectTokenPublic;
	CK_OBJECT_HANDLE hObjectTokenPrivate;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Open read-only session on when the token is not initialized should fail
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Try to destroy an invalid object using an invalid session
	rv = C_DestroyObject(hSessionRO,CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	// Create a read-only session.
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Trying to destroy an invalid object in a read-only session
	rv = C_DestroyObject(hSessionRO,CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// Create a read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Trying to destroy an invalid object in a read-write session
	rv = C_DestroyObject(hSessionRO,CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// Login USER into the sessions so we can create a private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
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

	// On a read-only session we should not be able to destroy the public token object
	rv = C_DestroyObject(hSessionRO,hObjectTokenPublic);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	// On a read-only session we should not be able to destroy the private token object
	rv = C_DestroyObject(hSessionRO,hObjectTokenPrivate);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);

	// Logout with a different session than the one used for login should be fine.
	rv = C_Logout(hSessionRW);
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Login USER into the sessions so we can destroy private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
	CPPUNIT_ASSERT(rv==CKR_OK);

	// We should be able to destroy the public session object from a read-only session.
	rv = C_DestroyObject(hSessionRO,hObjectSessionPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// All private session objects should have been destroyed when logging out.
	rv = C_DestroyObject(hSessionRW,hObjectSessionPrivate);
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// We should be able to destroy the public token object now.
	rv = C_DestroyObject(hSessionRW,hObjectTokenPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// All handles to private token objects should have been invalidated when logging out.
	rv = C_DestroyObject(hSessionRW,hObjectTokenPrivate);
	CPPUNIT_ASSERT(rv == CKR_OBJECT_HANDLE_INVALID);

	// Close session
	rv = C_CloseSession(hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = C_CloseSession(hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testGetAttributeValue()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Open read-only session on when the token is not initialized should fail
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Try to destroy an invalid object using an invalid session
	rv = C_GetAttributeValue(hSessionRO,CK_INVALID_HANDLE,NULL,1);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	// Create all permutations of session/token, public/private objects
	rv = createDataObjectMinimal(hSessionRO, IN_SESSION, IS_PUBLIC, hObjectSessionPublic);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_CLASS cClass = CKO_VENDOR_DEFINED;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_CLASS, &cClass, sizeof(cClass) }
	};

	rv = C_GetAttributeValue (hSessionRO,hObjectSessionPublic,&attribs[0],1);//sizeof(attribs)/sizeof(CK_ATTRIBUTE));
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = C_CloseSession(hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = C_CloseSession(hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testSetAttributeValue()
{
	// [PKCS#11 v2.3 pg. 61]

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
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;
	CK_OBJECT_HANDLE hObjectSessionPrivate;
	CK_OBJECT_HANDLE hObjectTokenPublic;
	CK_OBJECT_HANDLE hObjectTokenPrivate;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Open read-only session on when the token is not initialized should fail
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
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

	// Check that label can be modified on all combintations of session/token and public/private objects
	const char  *pLabel = "Label modified via C_SetAttributeValue";
	CK_ATTRIBUTE attribs[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)pLabel, strlen(pLabel) }
	};

	rv = C_SetAttributeValue (hSessionRO,hObjectSessionPublic,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_SetAttributeValue (hSessionRO,hObjectSessionPrivate,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_SetAttributeValue (hSessionRO,hObjectTokenPublic,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);
	rv = C_SetAttributeValue (hSessionRW,hObjectTokenPublic,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_SetAttributeValue (hSessionRO,hObjectTokenPrivate,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_SESSION_READ_ONLY);
	rv = C_SetAttributeValue (hSessionRW,hObjectTokenPrivate,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);

	attribs[0].pValue = NULL_PTR;
	rv = C_GetAttributeValue(hSessionRO,hObjectSessionPublic,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == strlen(pLabel));

	char pStoredLabel[64];
	attribs[0].pValue = &pStoredLabel[0];
	attribs[0].ulValueLen = 64;
	rv = C_GetAttributeValue(hSessionRO,hObjectSessionPublic,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(attribs[0].ulValueLen == strlen(pLabel));
	CPPUNIT_ASSERT(memcmp(pLabel,pStoredLabel,strlen(pLabel)) == 0);


	// Close session
	rv = C_CloseSession(hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Close session
	rv = C_CloseSession(hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ObjectTests::testFindObjects()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
	CK_OBJECT_HANDLE hObjectSessionPublic;
	CK_OBJECT_HANDLE hObjectSessionPrivate;
	CK_OBJECT_HANDLE hObjectTokenPublic;
	CK_OBJECT_HANDLE hObjectTokenPrivate;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Open read-only session on when the token is not initialized should fail
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
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
	rv = C_SetAttributeValue (hSessionRO,hObjectSessionPublic,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_SetAttributeValue (hSessionRO,hObjectSessionPrivate,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_SetAttributeValue (hSessionRW,hObjectTokenPublic,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_SetAttributeValue (hSessionRW,hObjectTokenPrivate,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now find the objects while logged in should find them all.
	rv = C_FindObjectsInit(hSessionRO,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_OBJECT_HANDLE hObjects[16];
	CK_ULONG ulObjectCount = 0;
	rv = C_FindObjects(hSessionRO,&hObjects[0],16,&ulObjectCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(4 == ulObjectCount);
	rv = C_FindObjectsFinal(hSessionRO);


	rv = C_Logout(hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now find the objects while no longer logged in should find only 2
	rv = C_FindObjectsInit(hSessionRO,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_FindObjects(hSessionRO,&hObjects[0],16,&ulObjectCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(2 == ulObjectCount);
	rv = C_FindObjectsFinal(hSessionRO);

	// Close the session used to create the session objects, should also destroy the session objects.
	rv = C_CloseSession(hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now find just the public token object as public session object should be gone now.
	rv = C_FindObjectsInit(hSessionRW,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_FindObjects(hSessionRW,&hObjects[0],16,&ulObjectCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(1 == ulObjectCount);
	rv = C_FindObjectsFinal(hSessionRW);

	// Login USER into the sessions so we can gain access to private objects
	rv = C_Login(hSessionRW,CKU_USER,pin,pinLength);
	CPPUNIT_ASSERT(rv==CKR_OK);

	// Now find just the public token object as public session object should be gone now.
	rv = C_FindObjectsInit(hSessionRW,&attribs[0],1);
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = C_FindObjects(hSessionRW,&hObjects[0],16,&ulObjectCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(2 == ulObjectCount);
	rv = C_FindObjectsFinal(hSessionRW);
}


void ObjectTests::testGenerateKeys()
{
	CK_RV rv;
	CK_UTF8CHAR pin[] = SLOT_0_USER1_PIN;
	CK_ULONG pinLength = sizeof(pin) - 1;
	CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	C_Finalize(NULL_PTR);

	// Open read-only session on when the token is not initialized should fail
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = C_OpenSession(SLOT_INIT_TOKEN, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = C_Login(hSessionRO,CKU_USER,pin,pinLength);
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
