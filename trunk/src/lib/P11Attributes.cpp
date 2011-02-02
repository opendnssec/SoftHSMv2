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
 P11Attributes.h

 This file contains classes for controlling attributes
 *****************************************************************************/

#include "config.h"
#include "P11Attributes.h"
#include "ByteString.h"
#include <stdio.h>
#include <stdlib.h>

// Constructor
P11Attribute::P11Attribute(OSObject *osobject)
{
	this->osobject = osobject;
	type = CKA_VENDOR_DEFINED;
}

// Destructor
P11Attribute::~P11Attribute()
{
}

// Check attribute from user
CK_RV P11Attribute::checkPtr(CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{
	// Check pointers
	if (ulValueLen != 0 && pValue == NULL_PTR)
	{
		ERROR_MSG("The attribute is a NULL_PTR but have a non-zero length")
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

// Check if we are allowed to modify the data
CK_RV P11Attribute::canModify(int op)
{
	OSAttribute *attrModifiable = NULL;
	OSAttribute *attrClass = NULL;
	OSAttribute *attrTrusted = NULL;

	// We only do these checks if we are called by C_SetAttributeValue
	if (op != OBJECT_OP_SET) return CKR_OK;
	if (osobject == NULL) return CKR_GENERAL_ERROR;

	// The attribute cannot be changed if CKA_MODIFIABLE is set to false
	attrModifiable = osobject->getAttribute(CKA_MODIFIABLE);
	if (attrModifiable != NULL && attrModifiable->getBooleanValue() == false)
	{
		ERROR_MSG("The object is not modifiable");
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// A trusted certificate cannot be modified
	attrClass = osobject->getAttribute(CKA_CLASS);
	attrTrusted = osobject->getAttribute(CKA_TRUSTED);
	if
	(
		attrClass != NULL && attrTrusted != NULL &&
		attrClass->getUnsignedLongValue() == CKO_CERTIFICATE &&
		attrTrusted->getBooleanValue() == true
	)
	{
		ERROR_MSG("A trusted certificate cannot be modified");
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	return CKR_OK;
}

// Initialize the attribute
bool P11Attribute::init()
{
	if (osobject == NULL) return false;

	// Create a default value if the attribute does not exist
	if (osobject->attributeExists(type) == false)
	{
		return setDefault();
	}

	return true;
}

// Return the attribute type
CK_ATTRIBUTE_TYPE P11Attribute::getType()
{
	return type;
}

// Update the value if allowed
CK_RV P11Attribute::update(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	CK_RV rv;

	if (osobject == NULL) return CKR_GENERAL_ERROR;

	// Validate the attribute from the user
	rv = checkPtr(pValue, ulValueLen);
	if (rv != CKR_OK) return rv;

	// Check if we are allowed to modify the data
	rv = canModify(op);
	if (rv != CKR_OK) return rv;

	return updateAttr(pValue, ulValueLen, op, isSO);
}

/*****************************************
 * CKA_CLASS
 *****************************************/

// Set default value
bool P11AttrClass::setDefault()
{
	OSAttribute attrClass((unsigned long)CKO_VENDOR_DEFINED);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	// CKA_CLASS must be updated when creating the object
	return osobject->setAttribute(type, attrClass);
}

// Update the value if allowed
CK_RV P11AttrClass::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute *attr = NULL;

	// Attribute specific checks

	if (op == OBJECT_OP_SET)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	attr = osobject->getAttribute(type);
	if (attr == NULL) return CKR_GENERAL_ERROR;
	if (attr->getUnsignedLongValue() != *(CK_ULONG*)pValue)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

/*****************************************
 * CKA_KEY_TYPE
 *****************************************/

// Set default value
bool P11AttrKeyType::setDefault()
{
	OSAttribute attr((unsigned long)CKK_VENDOR_DEFINED);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	// CKA_KEY_TYPE must be updated when creating the object
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrKeyType::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute *attr = NULL;

	// Attribute specific checks

	if (op == OBJECT_OP_SET)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

        attr = osobject->getAttribute(type);
	if (attr == NULL) return CKR_GENERAL_ERROR;
	if (attr->getUnsignedLongValue() != *(CK_ULONG*)pValue)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

/*****************************************
 * CKA_CERTIFICATE_TYPE
 *****************************************/

// Set default value
bool P11AttrCertificateType::setDefault()
{
	OSAttribute attr((unsigned long)CKC_VENDOR_DEFINED);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	// CKA_CERTIFICATE_TYPE must be updated when creating the object
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCertificateType::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute *attr = NULL;

	// Attribute specific checks

	if (op == OBJECT_OP_SET)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	attr = osobject->getAttribute(type);
	if (attr == NULL) return CKR_GENERAL_ERROR;
	if (attr->getUnsignedLongValue() != *(CK_ULONG*)pValue)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

/*****************************************
 * CKA_TOKEN
 *****************************************/

// Set default value
bool P11AttrToken::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrToken::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op != OBJECT_OP_GENERATE && op != OBJECT_OP_CREATE && op != OBJECT_OP_COPY)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_PRIVATE
 *****************************************/

// Set default value
bool P11AttrPrivate::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPrivate::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op != OBJECT_OP_GENERATE && op != OBJECT_OP_CREATE && op != OBJECT_OP_COPY)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_MODIFIABLE
 *****************************************/

// Set default value
bool P11AttrModifiable::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrModifiable::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op != OBJECT_OP_GENERATE && op != OBJECT_OP_CREATE && op != OBJECT_OP_COPY)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_LABEL
 *****************************************/

// Set default value
bool P11AttrLabel::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrLabel::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks
	// No checks

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_APPLICATION
 *****************************************/

// Set default value
bool P11AttrApplication::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrApplication::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks
	// No checks

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_OBJECT_ID
 *****************************************/

// Set default value
bool P11AttrObjectID::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrObjectID::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks
	// No checks

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_CHECK_VALUE
 *****************************************/

// Set default value
bool P11AttrCheckValue::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCheckValue::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks
	// No checks

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_ID
 *****************************************/

// Set default value
bool P11AttrID::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrID::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks
	// No checks

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_VALUE
 *****************************************/

// Set default value
bool P11AttrValue::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrValue::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks
	// No checks

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_SUBJECT
 *****************************************/

// Set default value
bool P11AttrSubject::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrSubject::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks
	// No checks

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_TRUSTED
 *****************************************/

// Set default value
bool P11AttrTrusted::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrTrusted::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		if (isSO == false)
		{
			ERROR_MSG("CKA_TRUSTED can only be set to true by the SO");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_CERTIFICATE_CATEGORY
 *****************************************/

// Set default value
bool P11AttrCertificateCategory::setDefault()
{
	OSAttribute attr((unsigned long)0);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCertificateCategory::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_SET)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data
	osobject->setAttribute(type, *(CK_ULONG*)pValue);

	return CKR_OK;
}

/*****************************************
 * CKA_START_DATE
 *****************************************/

// Set default value
bool P11AttrStartDate::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrStartDate::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (ulValueLen != sizeof(CK_DATE) && ulValueLen != 0)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_END_DATE
 *****************************************/

// Set default value
bool P11AttrEndDate::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrEndDate::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (ulValueLen != sizeof(CK_DATE) && ulValueLen != 0)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_DERIVE
 *****************************************/

// Set default value
bool P11AttrDerive::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrDerive::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_ENCRYPT
 *****************************************/

// Set default value
bool P11AttrEncrypt::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrEncrypt::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_VERIFY
 *****************************************/

// Set default value
bool P11AttrVerify::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrVerify::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_VERIFY_RECOVER
 *****************************************/

// Set default value
bool P11AttrVerifyRecover::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrVerifyRecover::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_WRAP
 *****************************************/

// Set default value
bool P11AttrWrap::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrWrap::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_DECRYPT
 *****************************************/

// Set default value
bool P11AttrDecrypt::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrDecrypt::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_SIGN
 *****************************************/

// Set default value
bool P11AttrSign::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrSign::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_SIGN_RECOVER
 *****************************************/

// Set default value
bool P11AttrSignRecover::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrSignRecover::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_UNWRAP
 *****************************************/

// Set default value
bool P11AttrUnwrap::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrUnwrap::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_LOCAL
 *****************************************/

// Set default value
bool P11AttrLocal::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	// CKA_LOCAL must be updated when creating the object
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrLocal::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	return CKR_ATTRIBUTE_READ_ONLY;
}

/*****************************************
 * CKA_KEY_GEN_MECHANISM
 *****************************************/

// Set default value
bool P11AttrKeyGenMechanism::setDefault()
{
	OSAttribute attr((unsigned long)CK_UNAVAILABLE_INFORMATION);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	// CKA_KEY_GEN_MECHANISM must be updated when creating the object
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrKeyGenMechanism::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	return CKR_ATTRIBUTE_READ_ONLY;
}

/*****************************************
 * CKA_ALWAYS_SENSITIVE
 *****************************************/

// Set default value
bool P11AttrAlwaysSensitive::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrAlwaysSensitive::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	return CKR_ATTRIBUTE_READ_ONLY;
}

/*****************************************
 * CKA_NEVER_EXTRACTABLE
 *****************************************/

// Set default value
bool P11AttrNeverExtractable::setDefault()
{
	OSAttribute attr(true);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrNeverExtractable::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	return CKR_ATTRIBUTE_READ_ONLY;
}

/*****************************************
 * CKA_SENSITIVE
 *****************************************/

// Set default value
bool P11AttrSensitive::setDefault()
{
	// We default to false because we want to handle the secret keys in a corret way
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrSensitive::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op == OBJECT_OP_SET || op == OBJECT_OP_COPY)
	{
		if (osobject->getAttribute(type)->getBooleanValue())
		{
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
		osobject->setAttribute(CKA_ALWAYS_SENSITIVE, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);

		// This is so that generated keys get the correct value
		if (op == OBJECT_OP_GENERATE)
		{
			osobject->setAttribute(CKA_ALWAYS_SENSITIVE, attrTrue);
		}
	}

	return CKR_OK;
}

/*****************************************
 * CKA_EXTRACTABLE
 *****************************************/

// Set default value
bool P11AttrExtractable::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrExtractable::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op == OBJECT_OP_SET || op == OBJECT_OP_COPY)
	{
		if (osobject->getAttribute(type)->getBooleanValue() == false)
		{
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
		osobject->setAttribute(CKA_NEVER_EXTRACTABLE, attrFalse);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_WRAP_WITH_TRUSTED
 *****************************************/

// Set default value
bool P11AttrWrapWithTrusted::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrWrapWithTrusted::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op == OBJECT_OP_SET || op == OBJECT_OP_COPY)
	{
		if (osobject->getAttribute(type)->getBooleanValue())
		{
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_ALWAYS_AUTHENTICATE
 *****************************************/

// Set default value
bool P11AttrAlwaysAuthenticate::setDefault()
{
	OSAttribute attr(false);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrAlwaysAuthenticate::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen != sizeof(CK_BBOOL))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	if (*(CK_BBOOL*)pValue == CK_FALSE)
	{
		osobject->setAttribute(type, attrFalse);
	}
	else
	{
		if (osobject->getAttribute(CKA_PRIVATE)->getBooleanValue() == false)
		{
			return CKR_TEMPLATE_INCONSISTENT;
		}

		osobject->setAttribute(type, attrTrue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_MODULUS
 *****************************************/

// Set default value
bool P11AttrModulus::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrModulus::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_PUBLIC_EXPONENT
 *****************************************/

// Set default value
bool P11AttrPublicExponent::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPublicExponent::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_PRIVATE_EXPONENT
 *****************************************/

// Set default value
bool P11AttrPrivateExponent::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPrivateExponent::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_PRIME_1
 *****************************************/

// Set default value
bool P11AttrPrime1::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPrime1::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_PRIME_2
 *****************************************/

// Set default value
bool P11AttrPrime2::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPrime2::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_EXPONENT_1
 *****************************************/

// Set default value
bool P11AttrExponent1::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrExponent1::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_EXPONENT_2
 *****************************************/

// Set default value
bool P11AttrExponent2::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrExponent2::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_COEFFICIENT
 *****************************************/

// Set default value
bool P11AttrCoefficient::setDefault()
{
	OSAttribute attr(ByteString(""));

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCoefficient::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_CREATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Store data

	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_MODULUS_BITS
 *****************************************/

// Set default value
bool P11AttrModulusBits::setDefault()
{
	OSAttribute attr((unsigned long)0);

	// We do not check this because it is checked in init()
	// if (osobject == NULL) return false;

	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrModulusBits::updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO)
{
	// Attribute specific checks

	if (op != OBJECT_OP_GENERATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen != sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	osobject->setAttribute(type, *(CK_ULONG*)pValue);

	return CKR_OK;
}

/*****************************************
 * Old code that will be migrated
 *****************************************

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
