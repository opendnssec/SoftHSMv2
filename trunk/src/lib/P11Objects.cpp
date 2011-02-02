/* $Id$ */

/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation)
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
 P11Objects.cpp

 This class respresent a PKCS#11 object
 *****************************************************************************/

#include "config.h"
#include "P11Objects.h"
#include <stdio.h>
#include <stdlib.h>

// Destructor
P11Object::~P11Object()
{
	std::map<CK_ATTRIBUTE_TYPE, P11Attribute*> cleanUp = attributes;
	attributes.clear();

	for (std::map<CK_ATTRIBUTE_TYPE, P11Attribute*>::iterator i = cleanUp.begin(); i != cleanUp.end(); i++)
	{
		if (i->second == NULL)
		{
			continue;
		}

		delete i->second;
		i->second = NULL;
	}
}

// Add attributes
bool P11Object::build()
{
	// Create attributes
	P11Attribute *attrClass = new P11AttrClass(osobject);
	P11Attribute *attrToken = new P11AttrToken(osobject);
	P11Attribute *attrPrivate = new P11AttrPrivate(osobject);
	P11Attribute *attrModifiable = new P11AttrModifiable(osobject);
	P11Attribute *attrLabel = new P11AttrLabel(osobject);

	// Initialize the attributes
	if
	(
		!attrClass->init() ||
		!attrToken->init() ||
		!attrPrivate->init() ||
		!attrModifiable->init() ||
		!attrLabel->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		return false;
	}

	// Add them to the map
	attributes[attrClass->getType()] = attrClass;
	attributes[attrToken->getType()] = attrToken;
	attributes[attrPrivate->getType()] = attrPrivate;
	attributes[attrModifiable->getType()] = attrModifiable;
	attributes[attrLabel->getType()] = attrLabel;

	return true;
}

// Add attributes
bool P11DataObj::build()
{
	// Create parent
	if (!P11Object::build()) return false;

	// Create attributes
	P11Attribute *attrApplication = new P11AttrApplication(osobject);
	P11Attribute *attrObjectID = new P11AttrObjectID(osobject);
	P11Attribute *attrValue = new P11AttrValue(osobject);

	// Initialize the attributes
	if
	(
		!attrApplication->init() ||
		!attrObjectID->init() ||
		!attrValue->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		return false;
	}

	// Add them to the map
	attributes[attrApplication->getType()] = attrApplication;
	attributes[attrObjectID->getType()] = attrObjectID;
	attributes[attrValue->getType()] = attrValue;

	return true;
}

// Add attributes
bool P11CertificateObj::build()
{
	// Create parent
	if (!P11Object::build()) return false;

	// Create attributes
	P11Attribute *attrCertificateType = new P11AttrCertificateType(osobject);
	P11Attribute *attrTrusted = new P11AttrTrusted(osobject);
	P11Attribute *attrCertificateCategory = new P11AttrCertificateCategory(osobject);
	P11Attribute *attrCheckValue = new P11AttrCheckValue(osobject);
	P11Attribute *attrStartDate = new P11AttrStartDate(osobject);
	P11Attribute *attrEndDate = new P11AttrEndDate(osobject);

	// Initialize the attributes
	if
	(
		!attrCertificateType->init() ||
		!attrTrusted->init() ||
		!attrCertificateCategory->init() ||
		!attrCheckValue->init() ||
		!attrStartDate->init() ||
		!attrEndDate->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		return false;
	}

	// Add them to the map
	attributes[attrCertificateType->getType()] = attrCertificateType;
	attributes[attrTrusted->getType()] = attrTrusted;
	attributes[attrCertificateCategory->getType()] = attrCertificateCategory;
	attributes[attrCheckValue->getType()] = attrCheckValue;
	attributes[attrStartDate->getType()] = attrStartDate;
	attributes[attrEndDate->getType()] = attrEndDate;

	return true;
}

// Add attributes
bool P11KeyObj::build()
{
	// Create parent
	if (!P11Object::build()) return false;

	// Create attributes
	P11Attribute *attrKeyType = new P11AttrKeyType(osobject);
	P11Attribute *attrID = new P11AttrID(osobject);
	P11Attribute *attrStartDate = new P11AttrStartDate(osobject);
	P11Attribute *attrEndDate = new P11AttrEndDate(osobject);
	P11Attribute *attrDerive = new P11AttrDerive(osobject);
	P11Attribute *attrLocal = new P11AttrLocal(osobject);
	P11Attribute *attrKeyGenMechanism = new P11AttrKeyGenMechanism(osobject);
	// CKA_ALLOWED_MECHANISMS is not supported

	// Initialize the attributes
	if
	(
		!attrKeyType->init() ||
		!attrID->init() ||
		!attrStartDate->init() ||
		!attrEndDate->init() ||
		!attrDerive->init() ||
		!attrLocal->init() ||
		!attrKeyGenMechanism->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		return false;
	}

	// Add them to the map
	attributes[attrKeyType->getType()] = attrKeyType;
	attributes[attrID->getType()] = attrID;
	attributes[attrStartDate->getType()] = attrStartDate;
	attributes[attrEndDate->getType()] = attrEndDate;
	attributes[attrDerive->getType()] = attrDerive;
	attributes[attrLocal->getType()] = attrLocal;
	attributes[attrKeyGenMechanism->getType()] = attrKeyGenMechanism;

	return true;
}

// Add attributes
bool P11PublicKeyObj::build()
{
	// Create parent
	if (!P11KeyObj::build()) return false;

	// Create attributes

	P11Attribute *attrSubject = new P11AttrSubject(osobject);
	P11Attribute *attrEncrypt = new P11AttrEncrypt(osobject);
	P11Attribute *attrVerify = new P11AttrVerify(osobject);
	P11Attribute *attrVerifyRecover = new P11AttrVerifyRecover(osobject);
	P11Attribute *attrWrap = new P11AttrWrap(osobject);
	P11Attribute *attrTrusted = new P11AttrTrusted(osobject);
        // CKA_WRAP_TEMPLATE is not supported

	// Initialize the attributes
	if
	(
		!attrSubject->init() ||
		!attrEncrypt->init() ||
		!attrVerify->init() ||
		!attrVerifyRecover->init() ||
		!attrWrap->init() ||
		!attrTrusted->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		return false;
	}

	// Add them to the map
	attributes[attrSubject->getType()] = attrSubject;
	attributes[attrEncrypt->getType()] = attrEncrypt;
	attributes[attrVerify->getType()] = attrVerify;
	attributes[attrVerifyRecover->getType()] = attrVerifyRecover;
	attributes[attrWrap->getType()] = attrWrap;
	attributes[attrTrusted->getType()] = attrTrusted;

	return true;
}

// Add attributes
bool P11PrivateKeyObj::build()
{
	// Create parent
	if (!P11KeyObj::build()) return false;

	// Create attributes

	P11Attribute *attrSubject = new P11AttrSubject(osobject);
	P11Attribute *attrSensitive = new P11AttrSensitive(osobject);
	P11Attribute *attrDecrypt = new P11AttrDecrypt(osobject);
	P11Attribute *attrSign = new P11AttrSign(osobject);
	P11Attribute *attrSignRecover = new P11AttrSignRecover(osobject);
	P11Attribute *attrUnwrap = new P11AttrUnwrap(osobject);
	P11Attribute *attrExtractable = new P11AttrExtractable(osobject);
	P11Attribute *attrAlwaysSensitive = new P11AttrAlwaysSensitive(osobject);
	P11Attribute *attrNeverExtractable = new P11AttrNeverExtractable(osobject);
	P11Attribute *attrWrapWithTrusted = new P11AttrWrapWithTrusted(osobject);
        // CKA_UNWRAP_TEMPLATE is not supported
	P11Attribute *attrAlwaysAuthenticate = new P11AttrAlwaysAuthenticate(osobject);

	// Initialize the attributes
	if
	(
		!attrSubject->init() ||
		!attrSensitive->init() ||
		!attrDecrypt->init() ||
		!attrSign->init() ||
		!attrSignRecover->init() ||
		!attrUnwrap->init() ||
		!attrExtractable->init() ||
		!attrAlwaysSensitive->init() ||
		!attrNeverExtractable->init() ||
		!attrWrapWithTrusted->init() ||
		!attrAlwaysAuthenticate->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		return false;
	}

	// Add them to the map
	attributes[attrSubject->getType()] = attrSubject;
	attributes[attrSensitive->getType()] = attrSensitive;
	attributes[attrDecrypt->getType()] = attrDecrypt;
	attributes[attrSign->getType()] = attrSign;
	attributes[attrSignRecover->getType()] = attrSignRecover;
	attributes[attrUnwrap->getType()] = attrUnwrap;
	attributes[attrExtractable->getType()] = attrExtractable;
	attributes[attrAlwaysSensitive->getType()] = attrAlwaysSensitive;
	attributes[attrNeverExtractable->getType()] = attrNeverExtractable;
	attributes[attrWrapWithTrusted->getType()] = attrWrapWithTrusted;
	attributes[attrAlwaysAuthenticate->getType()] = attrAlwaysAuthenticate;

	return true;
}

/*****************************************
 * Old code that will be migrated
 *****************************************

// Save generated key
CK_RV OSObjectControl::saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, RSAPublicKey *rsa)
{
	if (osobject == NULL) return CKR_GENERAL_ERROR;
	if (osobject->startTransaction() == false) return CKR_GENERAL_ERROR;

	operationType = GENERATE;

	// Set default values
	setStorageDefaults();
	setKeyDefaults();
	setPublicKeyDefaults();
	setRsaPublicKeyDefaults();

	// General information that we need to update
	OSAttribute attrClass((unsigned long)CKO_PUBLIC_KEY);
	OSAttribute attrKeyType((unsigned long)CKK_RSA);
	OSAttribute attrMechType((unsigned long)CKM_RSA_PKCS_KEY_PAIR_GEN);
	OSAttribute attrLocal(true);
	osobject->setAttribute(CKA_CLASS, attrClass);
	osobject->setAttribute(CKA_KEY_TYPE, attrKeyType);
	osobject->setAttribute(CKA_KEY_GEN_MECHANISM, attrMechType);
	osobject->setAttribute(CKA_LOCAL, attrLocal);

	// TODO: Save key

	// Save template
	for (CK_ULONG i = 0; i < ulKeyAttributeCount; i++)
	{
		CK_RV rv = saveAttribute(pKeyTemplate[i]);
		if (rv != CKR_OK)
		{
			osobject->abortTransaction();
			return rv;
		}
	}

	if (osobject->commitTransaction() == false) return CKR_GENERAL_ERROR;

	return CKR_OK;
}

CK_RV OSObjectControl::saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, RSAPrivateKey *rsa)
{
	return CKR_OK;
}

CK_RV OSObjectControl::saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, DSAPublicKey *dsa)
{
	return CKR_OK;
}

CK_RV OSObjectControl::saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, DSAPrivateKey *dsa)
{
	return CKR_OK;
}

// Default storage attributes
void OSObjectControl::setStorageDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);
	OSAttribute attrClass((unsigned long)CKO_VENDOR_DEFINED);

	// CKA_CLASS must be updated when creating the object
	osobject->setAttribute(CKA_CLASS, attrClass);
	osobject->setAttribute(CKA_TOKEN, attrFalse);
	osobject->setAttribute(CKA_PRIVATE, attrTrue);
	osobject->setAttribute(CKA_MODIFIABLE, attrTrue);
	osobject->setAttribute(CKA_LABEL, attrEmpty);
}

// Default data attributes
void OSObjectControl::setDataDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));

	osobject->setAttribute(CKA_APPLICATION, attrEmpty);
	osobject->setAttribute(CKA_OBJECT_ID, attrEmpty);
	osobject->setAttribute(CKA_VALUE, attrEmpty);
}

// Default certificate attributes
void OSObjectControl::setCertificateDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));
	OSAttribute attrFalse(false);
	OSAttribute attrZero((unsigned long)0);
	OSAttribute attrType((unsigned long)CKC_VENDOR_DEFINED);

	// CKA_CERTIFICATE_TYPE must be updated when creating the object
	osobject->setAttribute(CKA_CERTIFICATE_TYPE, attrType);
	osobject->setAttribute(CKA_TRUSTED, attrFalse);
	osobject->setAttribute(CKA_CERTIFICATE_CATEGORY, attrZero);
	osobject->setAttribute(CKA_CHECK_VALUE, attrEmpty);
	osobject->setAttribute(CKA_START_DATE, attrEmpty);
	osobject->setAttribute(CKA_END_DATE, attrEmpty);
}

// Default key attributes
void OSObjectControl::setKeyDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));
	OSAttribute attrFalse(false);
	OSAttribute attrType((unsigned long)CKK_VENDOR_DEFINED);
	OSAttribute attrMech((unsigned long)CK_UNAVAILABLE_INFORMATION);

	// CKA_KEY_TYPE must be updated when creating the object
	osobject->setAttribute(CKA_KEY_TYPE, attrType);
	osobject->setAttribute(CKA_ID, attrEmpty);
	osobject->setAttribute(CKA_START_DATE, attrEmpty);
	osobject->setAttribute(CKA_END_DATE, attrEmpty);
	osobject->setAttribute(CKA_DERIVE, attrFalse);
	// CKA_LOCAL must be updated when creating the object
	osobject->setAttribute(CKA_LOCAL, attrFalse);
	// CKA_KEY_GEN_MECHANISM must be updated when creating the object
	osobject->setAttribute(CKA_KEY_GEN_MECHANISM, attrMech);
	// CKA_ALLOWED_MECHANISMS is not supported
}

// Default public key attributes
void OSObjectControl::setPublicKeyDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));
	OSAttribute attrFalse(false);
	OSAttribute attrTrue(true);

	osobject->setAttribute(CKA_SUBJECT, attrEmpty);
	osobject->setAttribute(CKA_ENCRYPT, attrTrue);
	osobject->setAttribute(CKA_VERIFY, attrTrue);
	osobject->setAttribute(CKA_VERIFY_RECOVER, attrTrue);
	osobject->setAttribute(CKA_WRAP, attrTrue);
	osobject->setAttribute(CKA_TRUSTED, attrFalse);
	// CKA_WRAP_TEMPLATE is not supported
}

// Default RSA public key attributes
void OSObjectControl::setRsaPublicKeyDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));
	OSAttribute attrZero((unsigned long)0);

	// These attributes are either set by the template or the key

	osobject->setAttribute(CKA_MODULUS, attrEmpty);
	osobject->setAttribute(CKA_MODULUS_BITS, attrZero);
	osobject->setAttribute(CKA_PUBLIC_EXPONENT, attrEmpty);
}

// Default private key attributes
void OSObjectControl::setPrivateKeyDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));
	OSAttribute attrFalse(false);
	OSAttribute attrTrue(true);

	osobject->setAttribute(CKA_SUBJECT, attrEmpty);
	osobject->setAttribute(CKA_SENSITIVE, attrTrue);
	osobject->setAttribute(CKA_DECRYPT, attrTrue);
	osobject->setAttribute(CKA_SIGN, attrTrue);
	osobject->setAttribute(CKA_SIGN_RECOVER, attrTrue);
	osobject->setAttribute(CKA_UNWRAP, attrTrue);
	osobject->setAttribute(CKA_EXTRACTABLE, attrFalse);
	osobject->setAttribute(CKA_ALWAYS_SENSITIVE, attrTrue);
	osobject->setAttribute(CKA_NEVER_EXTRACTABLE, attrTrue);
	osobject->setAttribute(CKA_WRAP_WITH_TRUSTED, attrFalse);
	// CKA_UNWRAP_TEMPLATE is not supported
	osobject->setAttribute(CKA_ALWAYS_AUTHENTICATE, attrFalse);
}

// Default RSA private key attributes
void OSObjectControl::setRsaPrivateKeyDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));

	// These attributes are either set by the template or the key

	osobject->setAttribute(CKA_MODULUS, attrEmpty);
	osobject->setAttribute(CKA_PUBLIC_EXPONENT, attrEmpty);
	osobject->setAttribute(CKA_PRIVATE_EXPONENT, attrEmpty);
	osobject->setAttribute(CKA_PRIME_1, attrEmpty);
	osobject->setAttribute(CKA_PRIME_2, attrEmpty);
	osobject->setAttribute(CKA_EXPONENT_1, attrEmpty);
	osobject->setAttribute(CKA_EXPONENT_2, attrEmpty);
	osobject->setAttribute(CKA_COEFFICIENT, attrEmpty);
}

// Default secret key attributes
void OSObjectControl::setSecretKeyDefaults()
{
	if (osobject == NULL) return;

	OSAttribute attrEmpty(ByteString(""));
	OSAttribute attrFalse(false);
	OSAttribute attrTrue(true);

	osobject->setAttribute(CKA_SENSITIVE, attrFalse);
	osobject->setAttribute(CKA_ENCRYPT, attrTrue);
	osobject->setAttribute(CKA_DECRYPT, attrTrue);
	osobject->setAttribute(CKA_SIGN, attrTrue);
	osobject->setAttribute(CKA_VERIFY, attrTrue);
	osobject->setAttribute(CKA_WRAP, attrTrue);
	osobject->setAttribute(CKA_UNWRAP, attrTrue);
	osobject->setAttribute(CKA_EXTRACTABLE, attrFalse);
	osobject->setAttribute(CKA_ALWAYS_SENSITIVE, attrFalse);
	osobject->setAttribute(CKA_NEVER_EXTRACTABLE, attrTrue);
	osobject->setAttribute(CKA_CHECK_VALUE, attrEmpty);
	osobject->setAttribute(CKA_WRAP_WITH_TRUSTED, attrFalse);
	osobject->setAttribute(CKA_TRUSTED, attrFalse);
	// CKA_WRAP_TEMPLATE is not supported
	// CKA_UNWRAP_TEMPLATE is not supported
}

// Default domain parameter attributes
void OSObjectControl::setDomainDefaults()
{
	OSAttribute attrFalse(false);
	OSAttribute attrType((unsigned long)CKK_VENDOR_DEFINED);

	// CKA_KEY_TYPE must be updated when creating the object
	osobject->setAttribute(CKA_KEY_TYPE, attrType);
	// CKA_LOCAL must be updated when creating the object
	osobject->setAttribute(CKA_LOCAL, attrFalse);
}

*/
