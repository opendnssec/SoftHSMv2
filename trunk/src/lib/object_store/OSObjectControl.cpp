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
 OSObjectControl.h

 This class can control what is written to the object
 *****************************************************************************/

#include "config.h"
#include "OSObjectControl.h"
#include "OSAttribute.h"
#include "ByteString.h"
#include <stdio.h>

// Constructor
OSObjectControl::OSObjectControl(OSObject *osobject, bool isSO)
{
	this->osobject = osobject;
	this->isSO = isSO;
	operationType = NONE;
}

// Destructor
OSObjectControl::~OSObjectControl()
{
}

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

CK_RV OSObjectControl::saveAttribute(CK_ATTRIBUTE attr)
{
	// Check pointers
	if (attr.ulValueLen != 0 && attr.pValue == NULL_PTR)
	{
		ERROR_MSG("The attribute is a NULL_PTR but have a non-zero length")
		return CKR_TEMPLATE_INCONSISTENT;
	}

	// Can only modify attributes that exist
	if (osobject->attributeExists(attr.type) == false)
	{
		ERROR_MSG("The attribute type is not valid");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	// Check if we are allowed to modify the data
	if (operationType == SET)
	{
		if
		(
			osobject->attributeExists(CKA_MODIFIABLE) &&
			osobject->getAttribute(CKA_MODIFIABLE)->getBooleanValue() == false
		)
		{
			ERROR_MSG("The object cannot be modified");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
		if
		(
			osobject->getAttribute(CKA_CLASS)->getUnsignedLongValue() == CKO_CERTIFICATE &&
			osobject->getAttribute(CKA_TRUSTED)->getBooleanValue() == true
		)
		{
			ERROR_MSG("The object cannot be modified");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	// Some attributes
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Check / save the attributes
	switch (attr.type)
	{
		case CKA_CLASS:
		case CKA_KEY_TYPE:
		case CKA_CERTIFICATE_TYPE:
			if (operationType == SET)
			{
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			if (attr.ulValueLen != sizeof(CK_ULONG))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (osobject->getAttribute(attr.type)->getUnsignedLongValue() != *(CK_ULONG*)attr.pValue)
			{
				return CKR_TEMPLATE_INCONSISTENT;
			}
			break;
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
			if (operationType != GENERATE && operationType != CREATE && operationType != COPY)
			{
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			if (attr.ulValueLen != sizeof(CK_BBOOL))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (*(CK_BBOOL*)attr.pValue == CK_FALSE)
			{
				osobject->setAttribute(attr.type, attrFalse);
			}
			else
			{
				osobject->setAttribute(attr.type, attrTrue);
			}
			break;
		case CKA_LABEL:
		case CKA_APPLICATION:
		case CKA_OBJECT_ID:
		case CKA_CHECK_VALUE:
		case CKA_VALUE:
		case CKA_SUBJECT:
			osobject->setAttribute(attr.type, ByteString((unsigned char*)attr.pValue, attr.ulValueLen));
			break;
		case CKA_TRUSTED:
			if (attr.ulValueLen != sizeof(CK_BBOOL))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (*(CK_BBOOL*)attr.pValue == CK_FALSE)
			{
				osobject->setAttribute(CKA_TRUSTED, attrFalse);
			}
			else
			{
				if (isSO == false)
				{
					ERROR_MSG("CKA_TRUSTED can only be set to true by the SO");
					return CKR_ATTRIBUTE_READ_ONLY;
				}
				osobject->setAttribute(CKA_TRUSTED, attrTrue);
			}
			break;
		case CKA_CERTIFICATE_CATEGORY:
			if (operationType == SET)
			{
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			if (attr.ulValueLen != sizeof(CK_ULONG))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			osobject->setAttribute(CKA_CERTIFICATE_CATEGORY, *(CK_ULONG*)attr.pValue);
			break;
		case CKA_START_DATE:
		case CKA_END_DATE:
			if (attr.ulValueLen != sizeof(CK_DATE) && attr.ulValueLen != 0)
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			osobject->setAttribute(attr.type, ByteString((unsigned char*)attr.pValue, attr.ulValueLen));
			break;
		case CKA_DERIVE:
		case CKA_ENCRYPT:
		case CKA_VERIFY:
		case CKA_VERIFY_RECOVER:
		case CKA_WRAP:
		case CKA_DECRYPT:
		case CKA_SIGN:
		case CKA_SIGN_RECOVER:
		case CKA_UNWRAP:
			if (attr.ulValueLen != sizeof(CK_BBOOL))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (*(CK_BBOOL*)attr.pValue == CK_FALSE)
			{
				osobject->setAttribute(attr.type, attrFalse);
			}
			else
			{
				osobject->setAttribute(attr.type, attrTrue);
			}
			break;
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
			return CKR_ATTRIBUTE_READ_ONLY;
		case CKA_SENSITIVE:
			if (operationType == SET || operationType == COPY)
			{
				if (osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue())
				{
					return CKR_ATTRIBUTE_READ_ONLY;
				}
			}
			if (attr.ulValueLen != sizeof(CK_BBOOL))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (*(CK_BBOOL*)attr.pValue == CK_FALSE)
			{
				osobject->setAttribute(CKA_SENSITIVE, attrFalse);
				osobject->setAttribute(CKA_ALWAYS_SENSITIVE, attrFalse);
			}
			else
			{
				osobject->setAttribute(CKA_SENSITIVE, attrTrue);
				// This is so that secret keys get the correct value
				if (operationType == GENERATE)
				{
					osobject->setAttribute(CKA_ALWAYS_SENSITIVE, attrTrue);
				}
			}
			break;
		case CKA_EXTRACTABLE:
			if (operationType == SET || operationType == COPY)
			{
				if (osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false)
				{
					return CKR_ATTRIBUTE_READ_ONLY;
				}
			}
			if (attr.ulValueLen != sizeof(CK_BBOOL))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (*(CK_BBOOL*)attr.pValue == CK_FALSE)
			{
				osobject->setAttribute(CKA_EXTRACTABLE, attrFalse);
			}
			else
			{
				osobject->setAttribute(CKA_EXTRACTABLE, attrTrue);
				osobject->setAttribute(CKA_NEVER_EXTRACTABLE, attrFalse);
			}
			break;
		case CKA_WRAP_WITH_TRUSTED:
			if (operationType == SET || operationType == COPY)
			{
				if (osobject->getAttribute(CKA_WRAP_WITH_TRUSTED)->getBooleanValue())
				{
					return CKR_ATTRIBUTE_READ_ONLY;
				}
			}
			if (attr.ulValueLen != sizeof(CK_BBOOL))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (*(CK_BBOOL*)attr.pValue == CK_FALSE)
			{
				osobject->setAttribute(CKA_WRAP_WITH_TRUSTED, attrFalse);
			}
			else
			{
				osobject->setAttribute(CKA_WRAP_WITH_TRUSTED, attrTrue);
			}
			break;
		case CKA_ALWAYS_AUTHENTICATE:
			if (attr.ulValueLen != sizeof(CK_BBOOL))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			if (*(CK_BBOOL*)attr.pValue == CK_FALSE)
			{
				osobject->setAttribute(CKA_ALWAYS_AUTHENTICATE, attrFalse);
			}
			else
			{
				if (osobject->getAttribute(CKA_PRIVATE)->getBooleanValue() == false)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				osobject->setAttribute(CKA_ALWAYS_AUTHENTICATE, attrTrue);
			}
			break;
		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
		case CKA_PRIVATE_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
			if (operationType != CREATE)
			{
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			osobject->setAttribute(attr.type, ByteString((unsigned char*)attr.pValue, attr.ulValueLen));
			break;
		case CKA_MODULUS_BITS:
			if (operationType != GENERATE)
			{
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			if (attr.ulValueLen != sizeof(CK_ULONG))
			{
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			osobject->setAttribute(attr.type, *(CK_ULONG*)attr.pValue);
			break;
		default:
			break;
	}

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

