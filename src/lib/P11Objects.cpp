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

// Constructor
P11Object::P11Object()
{
	initialized = false;
	osobject = NULL;
}

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
bool P11Object::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	osobject = inobject;

	// Create attributes
	P11Attribute* attrClass = new P11AttrClass(osobject);
	P11Attribute* attrToken = new P11AttrToken(osobject);
	P11Attribute* attrPrivate = new P11AttrPrivate(osobject);
	P11Attribute* attrModifiable = new P11AttrModifiable(osobject);
	P11Attribute* attrLabel = new P11AttrLabel(osobject);
	P11Attribute* attrCopyable = new P11AttrCopyable(osobject);
	P11Attribute* attrDestroyable = new P11AttrDestroyable(osobject);

	// Initialize the attributes
	if
	(
		!attrClass->init() ||
		!attrToken->init() ||
		!attrPrivate->init() ||
		!attrModifiable->init() ||
		!attrLabel->init() ||
		!attrCopyable->init() ||
		!attrDestroyable->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrClass;
		delete attrToken;
		delete attrPrivate;
		delete attrModifiable;
		delete attrLabel;
		delete attrCopyable;
		delete attrDestroyable;
		return false;
	}

	// Add them to the map
	attributes[attrClass->getType()] = attrClass;
	attributes[attrToken->getType()] = attrToken;
	attributes[attrPrivate->getType()] = attrPrivate;
	attributes[attrModifiable->getType()] = attrModifiable;
	attributes[attrLabel->getType()] = attrLabel;
	attributes[attrCopyable->getType()] = attrCopyable;
	attributes[attrDestroyable->getType()] = attrDestroyable;

	initialized = true;
	return true;
}

CK_RV P11Object::loadTemplate(Token *token, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount)
{
	bool isPrivate = this->isPrivate();

	// [PKCS#11 v2.40, C_GetAttributeValue]
	// 1. If the specified attribute (i.e., the attribute specified by the
	//    type field) for the object cannot be revealed because the object
	//    is sensitive or unextractable, then the ulValueLen field in that
	//    triple is modified to hold the value CK_UNAVAILABLE_INFORMATION.
	//
	// 2. Otherwise, if the specified value for the object is invalid (the
	//    object does not possess such an attribute), then the ulValueLen
	//    field in that triple is modified to hold the value
	//    CK_UNAVAILABLE_INFORMATION.
	//
	// 3. Otherwise, if the pValue field has the value NULL_PTR, then the
	//    ulValueLen field is modified to hold the exact length of the
	//    specified attribute for the object.
	//
	// 4. Otherwise, if the length specified in ulValueLen is large enough
	//    to hold the value of the specified attribute for the object,
	//    then that attribute is copied into the buffer located at pValue,
	//    and the ulValueLen field is modified to hold the exact length of
	//    the attribute.
	//
	// 5. Otherwise, the ulValueLen field is modified to hold the value
	//    CK_UNAVAILABLE_INFORMATION.

	bool invalid = false, sensitive = false, buffer_too_small = false;

	// If case 3 or 4 applies to all the requested attributes, then the call will return CKR_OK.
	for (CK_ULONG i = 0; i < ulAttributeCount; ++i)
	{
		P11Attribute* attr = attributes[pTemplate[i].type];

		// case 2 of the attribute checks
		if (attr == NULL) {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			// If case 2 applies to any of the requested attributes, then the call should
			// return the value CKR_ATTRIBUTE_TYPE_INVALID.
			invalid = true;
			continue;
		}

		// case 1,3,4 and 5 of the attribute checks are done while retrieving the attribute itself.
		CK_RV retrieve_rv = attr->retrieve(token, isPrivate, pTemplate[i].pValue, &pTemplate[i].ulValueLen);
		if (retrieve_rv == CKR_ATTRIBUTE_SENSITIVE) {
			// If case 1 applies to any of the requested attributes, then the call should
			// return the value CKR_ATTRIBUTE_SENSITIVE.
			sensitive = true;
		} else if (retrieve_rv == CKR_BUFFER_TOO_SMALL) {
			// If case 5 applies to any of the requested attributes, then the call should
			// return the value CKR_BUFFER_TOO_SMALL.
			buffer_too_small = true;
		} else if (retrieve_rv != CKR_OK) {
		    return CKR_GENERAL_ERROR;
		}

	}

	// As usual if more than one of these error codes is applicable, Cryptoki may
	// return any of them. Only if none of them applies to any of the requested
	// attributes will CKR_OK be returned. We choose to return the errors in
	// the following priority, which is probably the most useful order.
	if (sensitive)
		return CKR_ATTRIBUTE_SENSITIVE;
	if (invalid)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	if (buffer_too_small)
		return CKR_BUFFER_TOO_SMALL;
	return CKR_OK;
}

// Save template
CK_RV P11Object::saveTemplate(Token *token, bool isPrivate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, int op)
{
	if (osobject == NULL)
		return CKR_GENERAL_ERROR;
	if (osobject->startTransaction() == false)
		return CKR_GENERAL_ERROR;

	if (op == OBJECT_OP_SET)
	{
		if (!isModifiable())
		{
			osobject->abortTransaction();
			return CKR_ACTION_PROHIBITED;
		}
	}

	// [PKCS#11 v2.40, 4.1.3 Copying objects] OBJECT_OP_COPY
	//    If the CKA_COPYABLE attribute of the object to be copied is set
	//    to CK_FALSE, C_CopyObject returns CKR_ACTION_PROHIBITED.
	if (op == OBJECT_OP_COPY)
	{
		if (!isCopyable())
		{
			osobject->abortTransaction();
			return CKR_ACTION_PROHIBITED;
		}
	}

	for (CK_ULONG i = 0; i < ulAttributeCount; i++)
	{
		// [PKCS#11 v2.40, 4.1.1 Creating objects] OBJECT_OP_CREATE | OBJECT_OP_SET | OBJECT_OP_COPY
		//    1. If the supplied template specifies a value for an invalid attribute, then the attempt
		//    should fail with the error code CKR_ATTRIBUTE_TYPE_INVALID. An attribute
		//    is valid if it is either one of the attributes described in the Cryptoki specification or an
		//    additional vendor-specific attribute supported by the library and token.
		P11Attribute* attr = attributes[pTemplate[i].type];

		if (attr == NULL)
		{
			osobject->abortTransaction();
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}

		// Additonal checks are done while updating the attributes themselves.
		CK_RV rv = attr->update(token,isPrivate, pTemplate[i].pValue, pTemplate[i].ulValueLen, op);
		if (rv != CKR_OK)
		{
			osobject->abortTransaction();
			return rv;
		}
	}

	// [PKCS#11 v2.40, 4.1.1 Creating objects]
	//    4. If the attribute values in the supplied template, together with any default attribute
	//    values and any attribute values contributed to the object by the object-creation
	//    function itself, are insufficient to fully specify the object to create, then the attempt
	//    should fail with the error code CKR_TEMPLATE_INCOMPLETE.

	// All attributes that have to be specified are marked as such in the specification.
	// The following checks are relevant here:
	for (std::map<CK_ATTRIBUTE_TYPE, P11Attribute*>::iterator i = attributes.begin(); i != attributes.end(); i++)
	{
		CK_ULONG checks = i->second->getChecks();

		//  ck1  MUST be specified when object is created with C_CreateObject.
		//  ck3  MUST be specified when object is generated with C_GenerateKey or C_GenerateKeyPair.
		//  ck5  MUST be specified when object is unwrapped with C_UnwrapKey.
		if (((checks & P11Attribute::ck1) == P11Attribute::ck1 && op == OBJECT_OP_CREATE) ||
		    ((checks & P11Attribute::ck3) == P11Attribute::ck3 && op == OBJECT_OP_GENERATE) ||
		    ((checks & P11Attribute::ck5) == P11Attribute::ck5 && op == OBJECT_OP_UNWRAP))
		{
			bool isSpecified = false;

			for (CK_ULONG n = 0; n < ulAttributeCount; n++)
			{
				if (i->first == pTemplate[n].type)
				{
					isSpecified = true;
					break;
				}
			}

			if (!isSpecified)
			{
				ERROR_MSG("Mandatory attribute (0x%08X) was not specified in template", (unsigned int)i->first);

				return CKR_TEMPLATE_INCOMPLETE;
			}
		}
	}

	// [PKCS#11 v2.40, 4.1.1 Creating objects]
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

	if (osobject->commitTransaction() == false)
	{
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

bool P11Object::isPrivate()
{
	// Get the CKA_PRIVATE attribute, when the attribute is
	// not present return the default value which we have
	// chosen to be CK_FALSE.
	if (!osobject->attributeExists(CKA_PRIVATE)) return false;

	return osobject->getBooleanValue(CKA_PRIVATE, false);
}

bool P11Object::isCopyable()
{
	// Get the CKA_COPYABLE attribute, when the attribute is not
	// present return the default value which is CK_TRUE.
	if (!osobject->attributeExists(CKA_COPYABLE)) return true;

	return osobject->getBooleanValue(CKA_COPYABLE, true);
}

bool P11Object::isModifiable()
{
	// Get the CKA_MODIFIABLE attribute, when the attribute is
	// not present return the default value which is CK_TRUE.
	if (!osobject->attributeExists(CKA_MODIFIABLE)) return true;

	return osobject->getBooleanValue(CKA_MODIFIABLE, true);
}

// Constructor
P11DataObj::P11DataObj()
{
	initialized = false;
}

// Add attributes
bool P11DataObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	// Set default values for attributes that will be introduced in the parent
	if (!inobject->attributeExists(CKA_CLASS) || inobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_DATA) {
		OSAttribute setClass((unsigned long)CKO_DATA);
		inobject->setAttribute(CKA_CLASS, setClass);
	}

	// Create parent
	if (!P11Object::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrApplication = new P11AttrApplication(osobject);
	P11Attribute* attrObjectID = new P11AttrObjectID(osobject);
	// NOTE: There is no mention in the PKCS#11 v2.40 spec that for a Data
	//  Object the CKA_VALUE attribute may be modified after creation!
	//  Therefore we assume it is not allowed to change the CKA_VALUE
	//  attribute of a Data Object.
	P11Attribute* attrValue = new P11AttrValue(osobject,0);

	// Initialize the attributes
	if
	(
		!attrApplication->init() ||
		!attrObjectID->init() ||
		!attrValue->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrApplication;
		delete attrObjectID;
		delete attrValue;
		return false;
	}

	// Add them to the map
	attributes[attrApplication->getType()] = attrApplication;
	attributes[attrObjectID->getType()] = attrObjectID;
	attributes[attrValue->getType()] = attrValue;

	initialized = true;
	return true;
}

// Constructor
P11CertificateObj::P11CertificateObj()
{
	initialized = false;
}

// Add attributes
bool P11CertificateObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	// Set default values for attributes that will be introduced in the parent
	if (!inobject->attributeExists(CKA_CLASS) || inobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_CERTIFICATE) {
		OSAttribute setClass((unsigned long)CKO_CERTIFICATE);
		inobject->setAttribute(CKA_CLASS, setClass);
	}
	// Make certificates public
	if (!inobject->attributeExists(CKA_PRIVATE)) {
		OSAttribute setPrivate(false);
		inobject->setAttribute(CKA_PRIVATE, setPrivate);
	}

	// Create parent
	if (!P11Object::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrCertificateType = new P11AttrCertificateType(osobject);
	P11Attribute* attrTrusted = new P11AttrTrusted(osobject);
	P11Attribute* attrCertificateCategory = new P11AttrCertificateCategory(osobject);
	// NOTE: Because these attributes are used in a certificate object
	//  where the CKA_VALUE containing the certificate data is not
	//  modifiable, we assume that this attribute is also not modifiable.
	//  There is also no explicit mention of these attributes being modifiable.
	P11Attribute* attrCheckValue = new P11AttrCheckValue(osobject, 0);
	P11Attribute* attrStartDate = new P11AttrStartDate(osobject,0);
	P11Attribute* attrEndDate = new P11AttrEndDate(osobject,0);
	// TODO: CKA_PUBLIC_KEY_INFO is accepted, but we do not calculate it.
	P11Attribute* attrPublicKeyInfo = new P11AttrPublicKeyInfo(osobject,0);

	// Initialize the attributes
	if
	(
		!attrCertificateType->init() ||
		!attrTrusted->init() ||
		!attrCertificateCategory->init() ||
		!attrCheckValue->init() ||
		!attrStartDate->init() ||
		!attrEndDate->init() ||
		!attrPublicKeyInfo->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrCertificateType;
		delete attrTrusted;
		delete attrCertificateCategory;
		delete attrCheckValue;
		delete attrStartDate;
		delete attrEndDate;
		delete attrPublicKeyInfo;
		return false;
	}

	// Add them to the map
	attributes[attrCertificateType->getType()] = attrCertificateType;
	attributes[attrTrusted->getType()] = attrTrusted;
	attributes[attrCertificateCategory->getType()] = attrCertificateCategory;
	attributes[attrCheckValue->getType()] = attrCheckValue;
	attributes[attrStartDate->getType()] = attrStartDate;
	attributes[attrEndDate->getType()] = attrEndDate;
	attributes[attrPublicKeyInfo->getType()] = attrPublicKeyInfo;

	initialized = true;
	return true;
}

// Constructor
P11X509CertificateObj::P11X509CertificateObj()
{
	initialized = false;
}

// Add attributes
bool P11X509CertificateObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	// Set default values for attributes that will be introduced in the parent
	if (!inobject->attributeExists(CKA_CERTIFICATE_TYPE) || inobject->getUnsignedLongValue(CKA_CERTIFICATE_TYPE, CKC_VENDOR_DEFINED) != CKC_X_509) {
		OSAttribute setCertType((unsigned long)CKC_X_509);
		inobject->setAttribute(CKA_CERTIFICATE_TYPE, setCertType);
	}

	// Create parent
	if (!P11CertificateObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrSubject = new P11AttrSubject(osobject,P11Attribute::ck1);
	P11Attribute* attrID = new P11AttrID(osobject);
	P11Attribute* attrIssuer = new P11AttrIssuer(osobject);
	P11Attribute* attrSerialNumber = new P11AttrSerialNumber(osobject);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck14);
	P11Attribute* attrURL = new P11AttrURL(osobject);
	P11Attribute* attrHashOfSubjectPublicKey = new P11AttrHashOfSubjectPublicKey(osobject);
	P11Attribute* attrHashOfIssuerPublicKey = new P11AttrHashOfIssuerPublicKey(osobject);
	P11Attribute* attrJavaMidpSecurityDomain = new P11AttrJavaMidpSecurityDomain(osobject);
	P11Attribute* attrNameHashAlgorithm = new P11AttrNameHashAlgorithm(osobject);

	// Initialize the attributes
	if
	(
		!attrSubject->init() ||
		!attrID->init() ||
		!attrIssuer->init() ||
		!attrSerialNumber->init() ||
		!attrValue->init() ||
		!attrURL->init() ||
		!attrHashOfSubjectPublicKey->init() ||
		!attrHashOfIssuerPublicKey->init() ||
		!attrJavaMidpSecurityDomain->init() ||
		!attrNameHashAlgorithm->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrSubject;
		delete attrID;
		delete attrIssuer;
		delete attrSerialNumber;
		delete attrValue;
		delete attrURL;
		delete attrHashOfSubjectPublicKey;
		delete attrHashOfIssuerPublicKey;
		delete attrJavaMidpSecurityDomain;
		delete attrNameHashAlgorithm;
		return false;
	}

	// Add them to the map
	attributes[attrSubject->getType()] = attrSubject;
	attributes[attrID->getType()] = attrID;
	attributes[attrIssuer->getType()] = attrIssuer;
	attributes[attrSerialNumber->getType()] = attrSerialNumber;
	attributes[attrValue->getType()] = attrValue;
	attributes[attrURL->getType()] = attrURL;
	attributes[attrHashOfSubjectPublicKey->getType()] = attrHashOfSubjectPublicKey;
	attributes[attrHashOfIssuerPublicKey->getType()] = attrHashOfIssuerPublicKey;
	attributes[attrJavaMidpSecurityDomain->getType()] = attrJavaMidpSecurityDomain;
	attributes[attrNameHashAlgorithm->getType()] = attrNameHashAlgorithm;

	return true;
}

// Constructor
P11OpenPGPPublicKeyObj::P11OpenPGPPublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11OpenPGPPublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	// Set default values for attributes that will be introduced in the parent
	if (!inobject->attributeExists(CKA_CERTIFICATE_TYPE) || inobject->getUnsignedLongValue(CKA_CERTIFICATE_TYPE, CKC_VENDOR_DEFINED) != CKC_OPENPGP) {
		OSAttribute setCertType((unsigned long)CKC_OPENPGP);
		inobject->setAttribute(CKA_CERTIFICATE_TYPE, setCertType);
	}

	// Create parent
	if (!P11CertificateObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrSubject = new P11AttrSubject(osobject,P11Attribute::ck1);
	P11Attribute* attrID = new P11AttrID(osobject);
	P11Attribute* attrIssuer = new P11AttrIssuer(osobject);
	P11Attribute* attrSerialNumber = new P11AttrSerialNumber(osobject);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck14);
	P11Attribute* attrURL = new P11AttrURL(osobject);

	// Initialize the attributes
	if
	(
		!attrSubject->init() ||
		!attrID->init() ||
		!attrIssuer->init() ||
		!attrSerialNumber->init() ||
		!attrValue->init() ||
		!attrURL->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrSubject;
		delete attrID;
		delete attrIssuer;
		delete attrSerialNumber;
		delete attrValue;
		delete attrURL;
		return false;
	}

	// Add them to the map
	attributes[attrSubject->getType()] = attrSubject;
	attributes[attrID->getType()] = attrID;
	attributes[attrIssuer->getType()] = attrIssuer;
	attributes[attrSerialNumber->getType()] = attrSerialNumber;
	attributes[attrValue->getType()] = attrValue;
	attributes[attrURL->getType()] = attrURL;

	return true;
}

// Constructor
P11KeyObj::P11KeyObj()
{
	initialized = false;
}

// Add attributes
bool P11KeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	// Create parent
	if (!P11Object::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrKeyType = new P11AttrKeyType(osobject,P11Attribute::ck5);
	P11Attribute* attrID = new P11AttrID(osobject);
	P11Attribute* attrStartDate = new P11AttrStartDate(osobject,P11Attribute::ck8);
	P11Attribute* attrEndDate = new P11AttrEndDate(osobject,P11Attribute::ck8);
	P11Attribute* attrDerive = new P11AttrDerive(osobject);
	P11Attribute* attrLocal = new P11AttrLocal(osobject,P11Attribute::ck6);
	P11Attribute* attrKeyGenMechanism = new P11AttrKeyGenMechanism(osobject);
	P11Attribute* attrAllowedMechanisms = new P11AttrAllowedMechanisms(osobject);

	// Initialize the attributes
	if
	(
		!attrKeyType->init() ||
		!attrID->init() ||
		!attrStartDate->init() ||
		!attrEndDate->init() ||
		!attrDerive->init() ||
		!attrLocal->init() ||
		!attrKeyGenMechanism->init() ||
		!attrAllowedMechanisms->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrKeyType;
		delete attrID;
		delete attrStartDate;
		delete attrEndDate;
		delete attrDerive;
		delete attrLocal;
		delete attrKeyGenMechanism;
		delete attrAllowedMechanisms;
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
	attributes[attrAllowedMechanisms->getType()] = attrAllowedMechanisms;

	initialized = true;
	return true;
}

// Constructor
P11PublicKeyObj::P11PublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11PublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	// Set default values for attributes that will be introduced in the parent
	if (!inobject->attributeExists(CKA_CLASS) || inobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PUBLIC_KEY) {
		OSAttribute setClass((unsigned long)CKO_PUBLIC_KEY);
		inobject->setAttribute(CKA_CLASS, setClass);
	}
	// Make public keys public
	if (!inobject->attributeExists(CKA_PRIVATE)) {
		OSAttribute setPrivate(false);
		inobject->setAttribute(CKA_PRIVATE, setPrivate);
	}

	// Create parent
	if (!P11KeyObj::init(inobject)) return false;

	if (initialized) return true;

	// Create attributes
	P11Attribute* attrSubject = new P11AttrSubject(osobject,P11Attribute::ck8);
	P11Attribute* attrEncrypt = new P11AttrEncrypt(osobject);
	P11Attribute* attrVerify = new P11AttrVerify(osobject);
	P11Attribute* attrVerifyRecover = new P11AttrVerifyRecover(osobject);
	P11Attribute* attrWrap = new P11AttrWrap(osobject);
	P11Attribute* attrTrusted = new P11AttrTrusted(osobject);
	P11Attribute* attrWrapTemplate = new P11AttrWrapTemplate(osobject);
	// TODO: CKA_PUBLIC_KEY_INFO is accepted, but we do not calculate it
	P11Attribute* attrPublicKeyInfo = new P11AttrPublicKeyInfo(osobject,0);

	// Initialize the attributes
	if
	(
		!attrSubject->init() ||
		!attrEncrypt->init() ||
		!attrVerify->init() ||
		!attrVerifyRecover->init() ||
		!attrWrap->init() ||
		!attrTrusted->init() ||
		!attrWrapTemplate->init() ||
		!attrPublicKeyInfo->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrSubject;
		delete attrEncrypt;
		delete attrVerify;
		delete attrVerifyRecover;
		delete attrWrap;
		delete attrTrusted;
		delete attrWrapTemplate;
		delete attrPublicKeyInfo;
		return false;
	}

	// Add them to the map
	attributes[attrSubject->getType()] = attrSubject;
	attributes[attrEncrypt->getType()] = attrEncrypt;
	attributes[attrVerify->getType()] = attrVerify;
	attributes[attrVerifyRecover->getType()] = attrVerifyRecover;
	attributes[attrWrap->getType()] = attrWrap;
	attributes[attrTrusted->getType()] = attrTrusted;
	attributes[attrWrapTemplate->getType()] = attrWrapTemplate;
	attributes[attrPublicKeyInfo->getType()] = attrPublicKeyInfo;

	initialized = true;
	return true;
}

// Constructor
P11RSAPublicKeyObj::P11RSAPublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11RSAPublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA) {
		OSAttribute setKeyType((unsigned long)CKK_RSA);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PublicKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrModulus = new P11AttrModulus(osobject);
	P11Attribute* attrModulusBits = new P11AttrModulusBits(osobject);
	P11Attribute* attrPublicExponent = new P11AttrPublicExponent(osobject,P11Attribute::ck1);

	// Initialize the attributes
	if
	(
		!attrModulus->init() ||
		!attrModulusBits->init() ||
		!attrPublicExponent->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrModulus;
		delete attrModulusBits;
		delete attrPublicExponent;
		return false;
	}

	// Add them to the map
	attributes[attrModulus->getType()] = attrModulus;
	attributes[attrModulusBits->getType()] = attrModulusBits;
	attributes[attrPublicExponent->getType()] = attrPublicExponent;

	initialized = true;
	return true;
}

// Constructor
P11DSAPublicKeyObj::P11DSAPublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11DSAPublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_DSA) {
		OSAttribute setKeyType((unsigned long)CKK_DSA);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PublicKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrPrime = new P11AttrPrime(osobject,P11Attribute::ck3);
	P11Attribute* attrSubPrime = new P11AttrSubPrime(osobject,P11Attribute::ck3);
	P11Attribute* attrBase = new P11AttrBase(osobject,P11Attribute::ck3);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4);

	// Initialize the attributes
	if
	(
		!attrPrime->init() ||
		!attrSubPrime->init() ||
		!attrBase->init() ||
		!attrValue->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrPrime;
		delete attrSubPrime;
		delete attrBase;
		delete attrValue;
		return false;
	}

	// Add them to the map
	attributes[attrPrime->getType()] = attrPrime;
	attributes[attrSubPrime->getType()] = attrSubPrime;
	attributes[attrBase->getType()] = attrBase;
	attributes[attrValue->getType()] = attrValue;

	initialized = true;
	return true;
}

// Constructor
P11ECPublicKeyObj::P11ECPublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11ECPublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_EC) {
		OSAttribute setKeyType((unsigned long)CKK_EC);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PublicKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrEcParams = new P11AttrEcParams(osobject,P11Attribute::ck3);
	P11Attribute* attrEcPoint = new P11AttrEcPoint(osobject);

	// Initialize the attributes
	if
	(
		!attrEcParams->init() ||
		!attrEcPoint->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrEcParams;
		delete attrEcPoint;
		return false;
	}

	// Add them to the map
	attributes[attrEcParams->getType()] = attrEcParams;
	attributes[attrEcPoint->getType()] = attrEcPoint;

	initialized = true;
	return true;
}

// Constructor
P11EDPublicKeyObj::P11EDPublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11EDPublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_EC_EDWARDS) {
		OSAttribute setKeyType((unsigned long)CKK_EC_EDWARDS);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PublicKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrEcParams = new P11AttrEcParams(osobject,P11Attribute::ck3);
	P11Attribute* attrEcPoint = new P11AttrEcPoint(osobject);

	// Initialize the attributes
	if
	(
		!attrEcParams->init() ||
		!attrEcPoint->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrEcParams;
		delete attrEcPoint;
		return false;
	}

	// Add them to the map
	attributes[attrEcParams->getType()] = attrEcParams;
	attributes[attrEcPoint->getType()] = attrEcPoint;

	initialized = true;
	return true;
}

// Constructor
P11DHPublicKeyObj::P11DHPublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11DHPublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_DH) {
		OSAttribute setKeyType((unsigned long)CKK_DH);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PublicKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrPrime = new P11AttrPrime(osobject,P11Attribute::ck3);
	P11Attribute* attrBase = new P11AttrBase(osobject,P11Attribute::ck3);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4);

	// Initialize the attributes
	if
	(
		!attrPrime->init() ||
		!attrBase->init() ||
		!attrValue->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrPrime;
		delete attrBase;
		delete attrValue;
		return false;
	}

	// Add them to the map
	attributes[attrPrime->getType()] = attrPrime;
	attributes[attrBase->getType()] = attrBase;
	attributes[attrValue->getType()] = attrValue;

	initialized = true;
	return true;
}

// Constructor
P11GOSTPublicKeyObj::P11GOSTPublicKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11GOSTPublicKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_GOSTR3410) {
		OSAttribute setKeyType((unsigned long)CKK_GOSTR3410);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PublicKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4);
	P11Attribute* attrGostR3410Params = new P11AttrGostR3410Params(osobject,P11Attribute::ck3);
	P11Attribute* attrGostR3411Params = new P11AttrGostR3411Params(osobject,P11Attribute::ck3);
	P11Attribute* attrGost28147Params = new P11AttrGost28147Params(osobject,P11Attribute::ck8);

	// Initialize the attributes
	if
	(
		!attrValue->init() ||
		!attrGostR3410Params->init() ||
		!attrGostR3411Params->init() ||
		!attrGost28147Params->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrValue;
		delete attrGostR3410Params;
		delete attrGostR3411Params;
		delete attrGost28147Params;
		return false;
	}

	// Add them to the map
	attributes[attrValue->getType()] = attrValue;
	attributes[attrGostR3410Params->getType()] = attrGostR3410Params;
	attributes[attrGostR3411Params->getType()] = attrGostR3411Params;
	attributes[attrGost28147Params->getType()] = attrGost28147Params;

	initialized = true;
	return true;
}

//constructor
P11PrivateKeyObj::P11PrivateKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11PrivateKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_CLASS) || inobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY) {
		OSAttribute setClass((unsigned long)CKO_PRIVATE_KEY);
		inobject->setAttribute(CKA_CLASS, setClass);
	}

	// Create parent
	if (!P11KeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrSubject = new P11AttrSubject(osobject,P11Attribute::ck8);
	P11Attribute* attrSensitive = new P11AttrSensitive(osobject);
	P11Attribute* attrDecrypt = new P11AttrDecrypt(osobject);
	P11Attribute* attrSign = new P11AttrSign(osobject);
	P11Attribute* attrSignRecover = new P11AttrSignRecover(osobject);
	P11Attribute* attrUnwrap = new P11AttrUnwrap(osobject);
	P11Attribute* attrExtractable = new P11AttrExtractable(osobject);
	P11Attribute* attrAlwaysSensitive = new P11AttrAlwaysSensitive(osobject);
	P11Attribute* attrNeverExtractable = new P11AttrNeverExtractable(osobject);
	P11Attribute* attrWrapWithTrusted = new P11AttrWrapWithTrusted(osobject);
	P11Attribute* attrUnwrapTemplate = new P11AttrUnwrapTemplate(osobject);
	// TODO: CKA_ALWAYS_AUTHENTICATE is accepted, but we do not use it
	P11Attribute* attrAlwaysAuthenticate = new P11AttrAlwaysAuthenticate(osobject);
	// TODO: CKA_PUBLIC_KEY_INFO is accepted, but we do not calculate it
	P11Attribute* attrPublicKeyInfo = new P11AttrPublicKeyInfo(osobject,P11Attribute::ck8);

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
		!attrUnwrapTemplate->init() ||
		!attrAlwaysAuthenticate->init() ||
		!attrPublicKeyInfo->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrSubject;
		delete attrSensitive;
		delete attrDecrypt;
		delete attrSign;
		delete attrSignRecover;
		delete attrUnwrap;
		delete attrExtractable;
		delete attrAlwaysSensitive;
		delete attrNeverExtractable;
		delete attrWrapWithTrusted;
		delete attrUnwrapTemplate;
		delete attrAlwaysAuthenticate;
		delete attrPublicKeyInfo;
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
	attributes[attrUnwrapTemplate->getType()] = attrUnwrapTemplate;
	attributes[attrAlwaysAuthenticate->getType()] = attrAlwaysAuthenticate;
	attributes[attrPublicKeyInfo->getType()] = attrPublicKeyInfo;

	initialized = true;
	return true;
}

// Constructor
P11RSAPrivateKeyObj::P11RSAPrivateKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11RSAPrivateKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA) {
		OSAttribute setKeyType((unsigned long)CKK_RSA);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PrivateKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrModulus = new P11AttrModulus(osobject,P11Attribute::ck6);
	P11Attribute* attrPublicExponent = new P11AttrPublicExponent(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrPrivateExponent = new P11AttrPrivateExponent(osobject);
	P11Attribute* attrPrime1 = new P11AttrPrime1(osobject);
	P11Attribute* attrPrime2 = new P11AttrPrime2(osobject);
	P11Attribute* attrExponent1 = new P11AttrExponent1(osobject);
	P11Attribute* attrExponent2 = new P11AttrExponent2(osobject);
	P11Attribute* attrCoefficient = new P11AttrCoefficient(osobject);

	// Initialize the attributes
	if
	(
		!attrModulus->init() ||
		!attrPublicExponent->init() ||
		!attrPrivateExponent->init() ||
		!attrPrime1->init() ||
		!attrPrime2->init() ||
		!attrExponent1->init() ||
		!attrExponent2->init() ||
		!attrCoefficient->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrModulus;
		delete attrPublicExponent;
		delete attrPrivateExponent;
		delete attrPrime1;
		delete attrPrime2;
		delete attrExponent1;
		delete attrExponent2;
		delete attrCoefficient;
		return false;
	}

	// Add them to the map
	attributes[attrModulus->getType()] = attrModulus;
	attributes[attrPublicExponent->getType()] = attrPublicExponent;
	attributes[attrPrivateExponent->getType()] = attrPrivateExponent;
	attributes[attrPrime1->getType()] = attrPrime1;
	attributes[attrPrime2->getType()] = attrPrime2;
	attributes[attrExponent1->getType()] = attrExponent1;
	attributes[attrExponent2->getType()] = attrExponent2;
	attributes[attrCoefficient->getType()] = attrCoefficient;

	initialized = true;
	return true;
}

// Constructor
P11DSAPrivateKeyObj::P11DSAPrivateKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11DSAPrivateKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_DSA) {
		OSAttribute setKeyType((unsigned long)CKK_DSA);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PrivateKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrPrime = new P11AttrPrime(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrSubPrime = new P11AttrSubPrime(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrBase = new P11AttrBase(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);

	// Initialize the attributes
	if
	(
		!attrPrime->init() ||
		!attrSubPrime->init() ||
		!attrBase->init() ||
		!attrValue->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrPrime;
		delete attrSubPrime;
		delete attrBase;
		delete attrValue;
		return false;
	}

	// Add them to the map
	attributes[attrPrime->getType()] = attrPrime;
	attributes[attrSubPrime->getType()] = attrSubPrime;
	attributes[attrBase->getType()] = attrBase;
	attributes[attrValue->getType()] = attrValue;

	initialized = true;
	return true;
}

// Constructor
P11ECPrivateKeyObj::P11ECPrivateKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11ECPrivateKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_EC) {
		OSAttribute setKeyType((unsigned long)CKK_EC);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PrivateKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrEcParams = new P11AttrEcParams(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);

	// Initialize the attributes
	if
	(
		!attrEcParams->init() ||
		!attrValue->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrEcParams;
		delete attrValue;
		return false;
	}

	// Add them to the map
	attributes[attrEcParams->getType()] = attrEcParams;
	attributes[attrValue->getType()] = attrValue;

	initialized = true;
	return true;
}

// Constructor
P11EDPrivateKeyObj::P11EDPrivateKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11EDPrivateKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_EC_EDWARDS) {
		OSAttribute setKeyType((unsigned long)CKK_EC_EDWARDS);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PrivateKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrEcParams = new P11AttrEcParams(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);

	// Initialize the attributes
	if
	(
		!attrEcParams->init() ||
		!attrValue->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrEcParams;
		delete attrValue;
		return false;
	}

	// Add them to the map
	attributes[attrEcParams->getType()] = attrEcParams;
	attributes[attrValue->getType()] = attrValue;

	initialized = true;
	return true;
}

// Constructor
P11DHPrivateKeyObj::P11DHPrivateKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11DHPrivateKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_DH) {
		OSAttribute setKeyType((unsigned long)CKK_DH);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PrivateKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrPrime = new P11AttrPrime(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrBase = new P11AttrBase(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);
	P11Attribute* attrValueBits = new P11AttrValueBits(osobject);

	// Initialize the attributes
	if
	(
		!attrPrime->init() ||
		!attrBase->init() ||
		!attrValue->init() ||
		!attrValueBits->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrPrime;
		delete attrBase;
		delete attrValue;
		delete attrValueBits;
		return false;
	}

	// Add them to the map
	attributes[attrPrime->getType()] = attrPrime;
	attributes[attrBase->getType()] = attrBase;
	attributes[attrValue->getType()] = attrValue;
	attributes[attrValueBits->getType()] = attrValueBits;

	initialized = true;
	return true;
}

// Constructor
P11GOSTPrivateKeyObj::P11GOSTPrivateKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11GOSTPrivateKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_GOSTR3410) {
		OSAttribute setKeyType((unsigned long)CKK_GOSTR3410);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11PrivateKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);
	P11Attribute* attrGostR3410Params = new P11AttrGostR3410Params(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrGostR3411Params = new P11AttrGostR3411Params(osobject,P11Attribute::ck4|P11Attribute::ck6);
	P11Attribute* attrGost28147Params = new P11AttrGost28147Params(osobject,P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck8);

	// Initialize the attributes
	if
	(
		!attrValue->init() ||
		!attrGostR3410Params->init() ||
		!attrGostR3411Params->init() ||
		!attrGost28147Params->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrValue;
		delete attrGostR3410Params;
		delete attrGostR3411Params;
		delete attrGost28147Params;
		return false;
	}

	// Add them to the map
	attributes[attrValue->getType()] = attrValue;
	attributes[attrGostR3410Params->getType()] = attrGostR3410Params;
	attributes[attrGostR3411Params->getType()] = attrGostR3411Params;
	attributes[attrGost28147Params->getType()] = attrGost28147Params;

	initialized = true;
	return true;
}

// Constructor
P11SecretKeyObj::P11SecretKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11SecretKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_CLASS) || inobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY) {
		OSAttribute setClass((unsigned long)CKO_SECRET_KEY);
		inobject->setAttribute(CKA_CLASS, setClass);
	}

	// Create parent
	if (!P11KeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrSensitive = new P11AttrSensitive(osobject);
	P11Attribute* attrEncrypt = new P11AttrEncrypt(osobject);
	P11Attribute* attrDecrypt = new P11AttrDecrypt(osobject);
	P11Attribute* attrSign = new P11AttrSign(osobject);
	P11Attribute* attrVerify = new P11AttrVerify(osobject);
	P11Attribute* attrWrap = new P11AttrWrap(osobject);
	P11Attribute* attrUnwrap = new P11AttrUnwrap(osobject);
	P11Attribute* attrExtractable = new P11AttrExtractable(osobject);
	P11Attribute* attrAlwaysSensitive = new P11AttrAlwaysSensitive(osobject);
	P11Attribute* attrNeverExtractable = new P11AttrNeverExtractable(osobject);
	P11Attribute* attrCheckValue = new P11AttrCheckValue(osobject, P11Attribute::ck8);
	P11Attribute* attrWrapWithTrusted = new P11AttrWrapWithTrusted(osobject);
	P11Attribute* attrTrusted = new P11AttrTrusted(osobject);
	P11Attribute* attrWrapTemplate = new P11AttrWrapTemplate(osobject);
	P11Attribute* attrUnwrapTemplate = new P11AttrUnwrapTemplate(osobject);

	// Initialize the attributes
	if
	(
		!attrSensitive->init() ||
		!attrEncrypt->init() ||
		!attrDecrypt->init() ||
		!attrSign->init() ||
		!attrVerify->init() ||
		!attrWrap->init() ||
		!attrUnwrap->init() ||
		!attrExtractable->init() ||
		!attrAlwaysSensitive->init() ||
		!attrNeverExtractable->init() ||
		!attrCheckValue->init() ||
		!attrWrapWithTrusted->init() ||
		!attrTrusted->init() ||
		!attrWrapTemplate->init() ||
		!attrUnwrapTemplate->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrSensitive;
		delete attrEncrypt;
		delete attrDecrypt;
		delete attrSign;
		delete attrVerify;
		delete attrWrap;
		delete attrUnwrap;
		delete attrExtractable;
		delete attrAlwaysSensitive;
		delete attrNeverExtractable;
		delete attrCheckValue;
		delete attrWrapWithTrusted;
		delete attrTrusted;
		delete attrWrapTemplate;
		delete attrUnwrapTemplate;
		return false;
	}

	// Add them to the map
	attributes[attrSensitive->getType()] = attrSensitive;
	attributes[attrEncrypt->getType()] = attrEncrypt;
	attributes[attrDecrypt->getType()] = attrDecrypt;
	attributes[attrSign->getType()] = attrSign;
	attributes[attrVerify->getType()] = attrVerify;
	attributes[attrWrap->getType()] = attrWrap;
	attributes[attrUnwrap->getType()] = attrUnwrap;
	attributes[attrExtractable->getType()] = attrExtractable;
	attributes[attrAlwaysSensitive->getType()] = attrAlwaysSensitive;
	attributes[attrNeverExtractable->getType()] = attrNeverExtractable;
	attributes[attrCheckValue->getType()] = attrCheckValue;
	attributes[attrWrapWithTrusted->getType()] = attrWrapWithTrusted;
	attributes[attrTrusted->getType()] = attrTrusted;
	attributes[attrWrapTemplate->getType()] = attrWrapTemplate;
	attributes[attrUnwrapTemplate->getType()] = attrUnwrapTemplate;

	initialized = true;
	return true;
}

// Constructor
P11GenericSecretKeyObj::P11GenericSecretKeyObj()
{
	initialized = false;
	keytype = CKK_VENDOR_DEFINED;
}

// Add attributes
bool P11GenericSecretKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != keytype) {
		OSAttribute setKeyType(keytype);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11SecretKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);
	P11Attribute* attrValueLen = new P11AttrValueLen(osobject);

	// Initialize the attributes
	if
	(
		!attrValue->init() ||
		!attrValueLen->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrValue;
		delete attrValueLen;
		return false;
	}

	// Add them to the map
	attributes[attrValue->getType()] = attrValue;
	attributes[attrValueLen->getType()] = attrValueLen;

	initialized = true;
	return true;
}

// Set Key Type
bool P11GenericSecretKeyObj::setKeyType(CK_KEY_TYPE inKeytype)
{
	if (!initialized)
	{
		keytype = inKeytype;
		return true;
	}
	else
		return false;
}

// Get Key Type
CK_KEY_TYPE P11GenericSecretKeyObj::getKeyType()
{
	return keytype;
}

// Constructor
P11AESSecretKeyObj::P11AESSecretKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11AESSecretKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES) {
		OSAttribute setKeyType((unsigned long)CKK_AES);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11SecretKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);
	P11Attribute* attrValueLen = new P11AttrValueLen(osobject,P11Attribute::ck6);

	// Initialize the attributes
	if
	(
		!attrValue->init() ||
		!attrValueLen->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrValue;
		delete attrValueLen;
		return false;
	}

	// Add them to the map
	attributes[attrValue->getType()] = attrValue;
	attributes[attrValueLen->getType()] = attrValueLen;

	initialized = true;
	return true;
}

// Constructor
P11DESSecretKeyObj::P11DESSecretKeyObj()
{
	initialized = false;
	keytype = CKK_VENDOR_DEFINED;
}

// Add attributes
bool P11DESSecretKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != keytype) {
		OSAttribute setKeyType(keytype);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11SecretKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);

	// Initialize the attributes
	if (!attrValue->init())
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrValue;
		return false;
	}

	// Add them to the map
	attributes[attrValue->getType()] = attrValue;

	initialized = true;
	return true;
}

// Set Key Type
bool P11DESSecretKeyObj::setKeyType(CK_KEY_TYPE inKeytype)
{
	if (!initialized)
	{
		keytype = inKeytype;
		return true;
	}
	else
		return false;
}

// Get Key Type
CK_KEY_TYPE P11DESSecretKeyObj::getKeyType()
{
	return keytype;
}

// Constructor
P11GOSTSecretKeyObj::P11GOSTSecretKeyObj()
{
	initialized = false;
}

// Add attributes
bool P11GOSTSecretKeyObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_GOST28147) {
		OSAttribute setKeyType((unsigned long)CKK_GOST28147);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11SecretKeyObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrValue = new P11AttrValue(osobject,P11Attribute::ck1|P11Attribute::ck4|P11Attribute::ck6|P11Attribute::ck7);
	P11Attribute* attrGost28147Params = new P11AttrGost28147Params(osobject,P11Attribute::ck1|P11Attribute::ck3|P11Attribute::ck5);

	// Initialize the attributes
	if
	(
		!attrValue->init() ||
		!attrGost28147Params->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrValue;
		delete attrGost28147Params;
		return false;
	}

	// Add them to the map
	attributes[attrValue->getType()] = attrValue;
	attributes[attrGost28147Params->getType()] = attrGost28147Params;

	initialized = true;
	return true;
}

// Constructor
P11DomainObj::P11DomainObj()
{
	initialized = false;
}

// Add attributes
bool P11DomainObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_CLASS) || inobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_DOMAIN_PARAMETERS) {
		OSAttribute setClass((unsigned long)CKO_DOMAIN_PARAMETERS);
		inobject->setAttribute(CKA_CLASS, setClass);
	}

	// Create parent
	if (!P11Object::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrKeyType = new P11AttrKeyType(osobject);
	P11Attribute* attrLocal = new P11AttrLocal(osobject);

	// Initialize the attributes
	if
	(
		!attrKeyType->init() ||
		!attrLocal->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrKeyType;
		delete attrLocal;
		return false;
	}

	// Add them to the map
	attributes[attrKeyType->getType()] = attrKeyType;
	attributes[attrLocal->getType()] = attrLocal;

	initialized = true;
	return true;
}

// Constructor
P11DSADomainObj::P11DSADomainObj()
{
	initialized = false;
}

// Add attributes
bool P11DSADomainObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_DSA) {
		OSAttribute setKeyType((unsigned long)CKK_DSA);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11DomainObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrPrime = new P11AttrPrime(osobject,P11Attribute::ck4);
	P11Attribute* attrSubPrime = new P11AttrSubPrime(osobject,P11Attribute::ck4);
	P11Attribute* attrBase = new P11AttrBase(osobject,P11Attribute::ck4);
	P11Attribute* attrPrimeBits = new P11AttrPrimeBits(osobject);

	// Initialize the attributes
	if
	(
		!attrPrime->init() ||
		!attrSubPrime->init() ||
		!attrBase->init() ||
		!attrPrimeBits->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrPrime;
		delete attrSubPrime;
		delete attrBase;
		delete attrPrimeBits;
		return false;
	}

	// Add them to the map
	attributes[attrPrime->getType()] = attrPrime;
	attributes[attrSubPrime->getType()] = attrSubPrime;
	attributes[attrBase->getType()] = attrBase;
	attributes[attrPrimeBits->getType()] = attrPrimeBits;

	initialized = true;
	return true;
}

// Constructor
P11DHDomainObj::P11DHDomainObj()
{
	initialized = false;
}

// Add attributes
bool P11DHDomainObj::init(OSObject *inobject)
{
	if (initialized) return true;
	if (inobject == NULL) return false;

	if (!inobject->attributeExists(CKA_KEY_TYPE) || inobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_DH) {
		OSAttribute setKeyType((unsigned long)CKK_DH);
		inobject->setAttribute(CKA_KEY_TYPE, setKeyType);
	}

	// Create parent
	if (!P11DomainObj::init(inobject)) return false;

	// Create attributes
	P11Attribute* attrPrime = new P11AttrPrime(osobject,P11Attribute::ck4);
	P11Attribute* attrBase = new P11AttrBase(osobject,P11Attribute::ck4);
	P11Attribute* attrPrimeBits = new P11AttrPrimeBits(osobject);

	// Initialize the attributes
	if
	(
		!attrPrime->init() ||
		!attrBase->init() ||
		!attrPrimeBits->init()
	)
	{
		ERROR_MSG("Could not initialize the attribute");
		delete attrPrime;
		delete attrBase;
		delete attrPrimeBits;
		return false;
	}

	// Add them to the map
	attributes[attrPrime->getType()] = attrPrime;
	attributes[attrBase->getType()] = attrBase;
	attributes[attrPrimeBits->getType()] = attrPrimeBits;

	initialized = true;
	return true;
}
