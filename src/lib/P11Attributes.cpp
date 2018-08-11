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
#include "CryptoFactory.h"
#include "DESKey.h"
#include "AESKey.h"
#include <stdio.h>
#include <stdlib.h>

// Constructor
P11Attribute::P11Attribute(OSObject* inobject)
{
	osobject = inobject;
	type = CKA_VENDOR_DEFINED;
	size = (CK_ULONG)-1;
	checks = 0;
}

// Destructor
P11Attribute::~P11Attribute()
{
}

CK_RV P11Attribute::updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	ByteString value;
	if (isPrivate)
	{
		if (!token->encrypt(ByteString((unsigned char*)pValue, ulValueLen),value))
			return CKR_GENERAL_ERROR;
	}
	else
		value = ByteString((unsigned char*)pValue, ulValueLen);
	if (value.size() < ulValueLen)
		return CKR_GENERAL_ERROR;
	osobject->setAttribute(type, value);
	return CKR_OK;
}

bool P11Attribute::isModifiable()
{
	// Get the CKA_MODIFIABLE attribute, when the attribute is
	// not present return the default value which is CK_TRUE.
	if (!osobject->attributeExists(CKA_MODIFIABLE)) return true;

	return osobject->getBooleanValue(CKA_MODIFIABLE, true);
}

bool P11Attribute::isSensitive()
{
	// Get the CKA_SENSITIVE attribute, when the attribute is not present
	// assume the object is not sensitive.
	if (!osobject->attributeExists(CKA_SENSITIVE)) return false;

	return osobject->getBooleanValue(CKA_SENSITIVE, false);
}

bool P11Attribute::isExtractable()
{
	// Get the CKA_EXTRACTABLE attribute, when the attribute is
	// not present assume the object allows extraction.
	if (!osobject->attributeExists(CKA_EXTRACTABLE)) return true;

	return osobject->getBooleanValue(CKA_EXTRACTABLE, true);
}

bool P11Attribute::isTrusted()
{
	// Get the CKA_TRUSTED attribute, when the attribute is
	// not present assume the object is not trusted.
	if (!osobject->attributeExists(CKA_TRUSTED)) return false;

	return osobject->getBooleanValue(CKA_TRUSTED, false);
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

// Return the attribute checks
CK_ATTRIBUTE_TYPE P11Attribute::getChecks()
{
	return checks;
}

// Retrieve a template map
static CK_RV retrieveAttributeMap(CK_ATTRIBUTE_PTR pTemplate, const std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& map)
{
	size_t nullcnt = 0;

	for (size_t i = 0; i < map.size(); ++i)
	{
		if (pTemplate[i].pValue == NULL_PTR)
			++nullcnt;
	}

	// Caller wants type & size
	if (nullcnt == map.size())
	{
		std::map<CK_ATTRIBUTE_TYPE,OSAttribute>::const_iterator a = map.begin();
		for (size_t i = 0; i < map.size(); ++i, ++a)
		{
			pTemplate[i].type = a->first;
			const OSAttribute& attr = a->second;
			if (attr.isBooleanAttribute())
			{
				pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
			}
			else if (attr.isUnsignedLongAttribute())
			{
				pTemplate[i].ulValueLen = sizeof(CK_ULONG);
			}
			else if (attr.isByteStringAttribute())
			{
				pTemplate[i].ulValueLen = attr.getByteStringValue().size();
			}
			else
			{
				// Impossible
				ERROR_MSG("Internal error: bad attribute in attribute map");

				return CKR_GENERAL_ERROR;
			}
		}

		return CKR_OK;
	}

	// Callers wants to get values
	for (size_t i = 0; i < map.size(); ++i)
	{
		std::map<CK_ATTRIBUTE_TYPE,OSAttribute>::const_iterator a = map.find(pTemplate[i].type);
		if (a == map.end())
		{
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		const OSAttribute& attr = a->second;
		if (attr.isBooleanAttribute())
		{
			if (pTemplate[i].ulValueLen < sizeof(CK_BBOOL))
			{
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				return CKR_BUFFER_TOO_SMALL;
			}
			pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
			*(CK_BBOOL*)pTemplate[i].pValue = attr.getBooleanValue() ? CK_TRUE : CK_FALSE;
		}
		else if (attr.isUnsignedLongAttribute())
		{
			if (pTemplate[i].ulValueLen < sizeof(CK_ULONG))
			{
				pTemplate[i].ulValueLen= CK_UNAVAILABLE_INFORMATION;
				return CKR_BUFFER_TOO_SMALL;
			}
			pTemplate[i].ulValueLen = sizeof(CK_ULONG);
			*(CK_ULONG_PTR)pTemplate[i].pValue= attr.getUnsignedLongValue();
		}
		else if (attr.isByteStringAttribute())
		{
			ByteString value = attr.getByteStringValue();
			if (pTemplate[i].ulValueLen < value.size())
			{
				pTemplate[i].ulValueLen= CK_UNAVAILABLE_INFORMATION;
				return CKR_BUFFER_TOO_SMALL;
			}
			pTemplate[i].ulValueLen = value.size();
			memcpy(pTemplate[i].pValue, value.const_byte_str(), value.size());
		}
		else
		{
			// Impossible
			ERROR_MSG("Internal error: bad attribute in attribute map");

			return CKR_GENERAL_ERROR;
		}
	}

	return CKR_OK;
}

// Retrieve the value if allowed
CK_RV P11Attribute::retrieve(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen)
{

	if (osobject == NULL) {
		ERROR_MSG("Internal error: osobject field contains NULL_PTR");
		return CKR_GENERAL_ERROR;
	}

	if (pulValueLen == NULL) {
		ERROR_MSG("Internal error: pulValueLen contains NULL_PTR");
		return CKR_GENERAL_ERROR;
	}

	// [PKCS#11 v2.40, C_GetAttributeValue]
	// 1. If the specified attribute (i.e., the attribute specified by the
	//    type field) for the object cannot be revealed because the object
	//    is sensitive or unextractable, then the ulValueLen field in that
	//    triple is modified to hold the value CK_UNAVAILABLE_INFORMATION.
	//
	// [PKCS#11 v2.40, 4.2 Common attributes, table 10]
	//  7  Cannot be revealed if object has its CKA_SENSITIVE attribute
	//     set to CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE.
	if ((checks & ck7) == ck7 && (isSensitive() || !isExtractable())) {
		*pulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	// Retrieve the lower level attribute.
	if (!osobject->attributeExists(type)) {
		// Should be impossible.
		ERROR_MSG("Internal error: attribute not present");
		return CKR_GENERAL_ERROR;
	}
	OSAttribute attr = osobject->getAttribute(type);

	// Get the actual attribute size.
	CK_ULONG attrSize = size;
	if (size == (CK_ULONG)-1)
	{
		// We don't have a fixed size attribute so we need to consult
		// the lower level attribute for the exact size.

		// Lower level attribute has to be variable sized.
		if (attr.isByteStringAttribute())
		{
			if (isPrivate && attr.getByteStringValue().size() != 0)
			{
				ByteString value;
				if (!token->decrypt(attr.getByteStringValue(),value))
				{
					ERROR_MSG("Internal error: failed to decrypt private attribute value");
					return CKR_GENERAL_ERROR;
				}
				attrSize = value.size();
			}
			else
				attrSize = attr.getByteStringValue().size();
		}
		else if (attr.isMechanismTypeSetAttribute())
		{
			attrSize = attr.getMechanismTypeSetValue().size() * sizeof(CK_MECHANISM_TYPE);
		}
		else if (attr.isAttributeMapAttribute())
		{
			attrSize = attr.getAttributeMapValue().size() * sizeof(CK_ATTRIBUTE);
		}
		else
		{
			// Should be impossible.
			ERROR_MSG("Internal error: attribute has fixed size");
			return CKR_GENERAL_ERROR;
		}
	}

	// [PKCS#11 v2.40, C_GetAttributeValue]
	// 3. Otherwise, if the pValue field has the value NULL_PTR, then the
	//    ulValueLen field is modified to hold the exact length of the
	//    specified attribute for the object.
	if (pValue == NULL_PTR) {
		// Return the size of the attribute.
		*pulValueLen = attrSize;
		return CKR_OK;
	}

	// [PKCS#11 v2.40, C_GetAttributeValue]
	// 4. Otherwise, if the length specified in ulValueLen is large enough
	//    to hold the value of the specified attribute for the object, then
	//    that attribute is copied into the buffer located at pValue, and
	//    the ulValueLen field is modified to hold the exact length of the
	//    attribute.
	if (*pulValueLen >= attrSize)
	{
		// Only copy when there is actually something to copy
		CK_RV rv = CKR_OK;

		if (attr.isUnsignedLongAttribute()) {
			*(CK_ULONG_PTR)pValue = attr.getUnsignedLongValue();
		}
		else if (attr.isBooleanAttribute())
		{
			*(CK_BBOOL*)pValue = attr.getBooleanValue() ? CK_TRUE : CK_FALSE;
		}
		else if (attr.isByteStringAttribute())
		{
			if (isPrivate && attr.getByteStringValue().size() != 0)
			{
				ByteString value;
				if (!token->decrypt(attr.getByteStringValue(),value))
				{
					ERROR_MSG("Internal error: failed to decrypt private attribute value");
					return CKR_GENERAL_ERROR;
				}
				const unsigned char* attrPtr = value.const_byte_str();
				memcpy(pValue,attrPtr,attrSize);
			}
			else if (attr.getByteStringValue().size() != 0)
			{
				const unsigned char* attrPtr = attr.getByteStringValue().const_byte_str();
				memcpy(pValue,attrPtr,attrSize);
			}
		}
		else if (attr.isMechanismTypeSetAttribute())
		{
			CK_MECHANISM_TYPE_PTR pTemplate = (CK_MECHANISM_TYPE_PTR) pValue;
			size_t i = 0;

			std::set<CK_MECHANISM_TYPE> set = attr.getMechanismTypeSetValue();
			for (std::set<CK_MECHANISM_TYPE>::const_iterator it = set.begin(); it != set.end(); ++it)
				pTemplate[++i] = *it;
		}
		else
		{
			// attr is already retrieved and verified to be an Attribute Map
			rv = retrieveAttributeMap((CK_ATTRIBUTE_PTR)pValue, attr.getAttributeMapValue());
		}
		*pulValueLen = attrSize;
		return rv;
	}

	// [PKCS#11 v2.40, C_GetAttributeValue]
	// 5. Otherwise, the ulValueLen field is modified to hold the value CK_UNAVAILABLE_INFORMATION.
	*pulValueLen = CK_UNAVAILABLE_INFORMATION;
	return CKR_BUFFER_TOO_SMALL;
}

// Update the value if allowed
CK_RV P11Attribute::update(Token* token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	if (osobject == NULL) {
		ERROR_MSG("Internal error: osobject field contains NULL_PTR");
		return CKR_GENERAL_ERROR;
	}

	// [PKCS#11 v2.40, 4.1.1 Creating objects]
	//    2. If the supplied template specifies an invalid value for a valid attribute, then the
	//    attempt should fail with the error code CKR_ATTRIBUTE_VALUE_INVALID.
	//    The valid values for Cryptoki attributes are described in the Cryptoki specification.

	// Check for null pointers in values.
	if (pValue == NULL_PTR && ulValueLen != 0) {
		ERROR_MSG("The attribute is a NULL_PTR but has a non-zero length")
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// For fixed sized attributes check that the size matches.
	if (size != ((CK_ULONG)-1) && size != ulValueLen) {
		ERROR_MSG("The attribute size is different from the expected size")
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// [PKCS#11 v2.40, 4.1.1 Creating objects] OBJECT_OP_CREATE | OBJECT_OP_SET | OBJECT_OP_COPY
	//    3. If the supplied template specifies a value for a read-only attribute, then the attempt
	//    should fail with the error code CKR_ATTRIBUTE_READ_ONLY.
	//    Whether or not a given Cryptoki attribute is read-only is explicitly stated in the Cryptoki
	//    specification; however, a particular library and token may be even more restrictive than
	//    Cryptoki specifies. In other words, an attribute which Cryptoki says is not read-only may
	//    nonetheless be read-only under certain circumstances (i.e., in conjunction with some
	//    combinations of other attributes) for a particular library and token. Whether or not a
	//    given non-Cryptoki attribute is read-only is obviously outside the scope of Cryptoki.

	// Attributes cannot be changed if CKA_MODIFIABLE is set to false
	if (!isModifiable() && op != OBJECT_OP_GENERATE && op != OBJECT_OP_CREATE) {
		ERROR_MSG("An object is with CKA_MODIFIABLE set to false is not modifiable");
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	// Attributes cannot be modified if CKA_TRUSTED is true on a certificate object.
	if (isTrusted() && op != OBJECT_OP_GENERATE && op != OBJECT_OP_CREATE) {
		if (osobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_CERTIFICATE)
		{
			ERROR_MSG("A trusted certificate cannot be modified");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	//  ck2  MUST not be specified when object is created with C_CreateObject.
	if ((checks & ck2) == ck2)
	{
		if (OBJECT_OP_CREATE==op)
		{
			ERROR_MSG("Prohibited attribute was passed to object creation function");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	//  ck4  MUST not be specified when object is generated with C_GenerateKey or C_GenerateKeyPair.
	if ((checks & ck4) == ck4)
	{
		if (OBJECT_OP_GENERATE==op)
		{
			ERROR_MSG("Prohibited attribute was passed to key generation function");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	//  ck6  MUST not be specified when object is unwrapped with C_UnwrapKey.
	if ((checks & ck6) == ck6)
	{
		if (OBJECT_OP_UNWRAP==op)
		{
			ERROR_MSG("Prohibited attribute was passed to key unwrapping function");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	//  ck8  May be modified after object is created with a C_SetAttributeValue call
	//       or in the process of copying an object with a C_CopyObject call.
	//       However, it is possible that a particular token may not permit modification of
	//       the attribute during the course of a C_CopyObject call.
	if ((checks & ck8) == ck8)
	{
		if (OBJECT_OP_SET==op || OBJECT_OP_COPY==op)
		{
			return updateAttr(token, isPrivate, pValue, ulValueLen, op);
		}
	}

	// ck17  Can be changed in the process of copying the object using C_CopyObject.
	if ((checks & ck17) == ck17)
	{
		if (OBJECT_OP_COPY==op)
		{
			return updateAttr(token, isPrivate, pValue, ulValueLen, op);
		}
	}

	// For attributes that have not been explicitly excluded from modification
	// during create/derive/generate/unwrap, we allow them to be modified.
	if (OBJECT_OP_CREATE==op || OBJECT_OP_DERIVE==op || OBJECT_OP_GENERATE==op || OBJECT_OP_UNWRAP==op)
	{
		return updateAttr(token, isPrivate, pValue, ulValueLen, op);
	}

	return CKR_ATTRIBUTE_READ_ONLY;
}

/*****************************************
 * CKA_CLASS
 *****************************************/

// Set default value
bool P11AttrClass::setDefault()
{
	OSAttribute attrClass((unsigned long)CKO_VENDOR_DEFINED);
	return osobject->setAttribute(type, attrClass);
}

// Update the value if allowed
CK_RV P11AttrClass::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (osobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != *(CK_ULONG*)pValue)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrKeyType::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (osobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != *(CK_ULONG*)pValue)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

/*****************************************
 * CKA_CERTIFICATE_TYPE
 * footnote 1
 *  1  MUST be specified when object is created with C_CreateObject.
 *****************************************/

// Set default value
bool P11AttrCertificateType::setDefault()
{
	OSAttribute attr((unsigned long)CKC_VENDOR_DEFINED);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCertificateType::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (osobject->getUnsignedLongValue(CKA_CERTIFICATE_TYPE, CKC_VENDOR_DEFINED) != *(CK_ULONG*)pValue)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrToken::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPrivate::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrModifiable::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_COPYABLE
 *****************************************/

// Set default value
bool P11AttrCopyable::setDefault()
{
	OSAttribute attr(true);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCopyable::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
		if (osobject->getBooleanValue(CKA_COPYABLE, true) == false)
		{
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	return CKR_OK;
}

/*****************************************
 * CKA_DESTROYABLE
 *****************************************/

// Set default value
bool P11AttrDestroyable::setDefault()
{
	OSAttribute attr(true);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrDestroyable::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
 * CKA_APPLICATION
 *****************************************/

// Set default value
bool P11AttrApplication::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_OBJECT_ID
 *****************************************/

// Set default value
bool P11AttrObjectID::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_CHECK_VALUE
 *****************************************/

// Set default value
bool P11AttrCheckValue::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCheckValue::updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	ByteString plaintext((unsigned char*)pValue, ulValueLen);
	ByteString value;

	// Encrypt

	if (isPrivate)
	{
		if (!token->encrypt(plaintext, value))
			return CKR_GENERAL_ERROR;
	}
	else
		value = plaintext;

	// Attribute specific checks

	if (value.size() < ulValueLen)
		return CKR_GENERAL_ERROR;

	// Store data
	if (ulValueLen == 0)
	{
		osobject->setAttribute(type, value);
	}
	else
	{
		ByteString checkValue;
		ByteString keybits;
		if (isPrivate)
		{
			if (!token->decrypt(osobject->getByteStringValue(CKA_VALUE), keybits))
				return CKR_GENERAL_ERROR;
		}
		else
		{
			keybits = osobject->getByteStringValue(CKA_VALUE);
		}

		SymmetricKey key;
		AESKey aes;
		DESKey des;
		switch (osobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED))
		{
			case CKK_GENERIC_SECRET:
			case CKK_MD5_HMAC:
			case CKK_SHA_1_HMAC:
			case CKK_SHA224_HMAC:
			case CKK_SHA256_HMAC:
			case CKK_SHA384_HMAC:
			case CKK_SHA512_HMAC:
				key.setKeyBits(keybits);
				key.setBitLen(keybits.size() * 8);
				checkValue = key.getKeyCheckValue();
				break;
			case CKK_AES:
				aes.setKeyBits(keybits);
				aes.setBitLen(keybits.size() * 8);
				checkValue = aes.getKeyCheckValue();
				break;
			case CKK_DES:
			case CKK_DES2:
			case CKK_DES3:
				des.setKeyBits(keybits);
				des.setBitLen(keybits.size() * 7);
				checkValue = des.getKeyCheckValue();
				break;
			case CKK_GOST28147:
				// TODO: Encryption support for CKK_GOST28147
				// We do not calculate the KCV
				checkValue = plaintext;
				break;
			default:
				return CKR_GENERAL_ERROR;
		}

		if (plaintext != checkValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		osobject->setAttribute(type, value);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_PUBLIC_KEY_INFO
 *****************************************/

// Set default value
bool P11AttrPublicKeyInfo::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_ID
 *****************************************/

// Set default value
bool P11AttrID::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_VALUE
 *****************************************/

// Set default value
bool P11AttrValue::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrValue::updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	ByteString plaintext((unsigned char*)pValue, ulValueLen);
	ByteString value;

	// Encrypt

	if (isPrivate)
	{
		if (!token->encrypt(plaintext, value))
			return CKR_GENERAL_ERROR;
	}
	else
		value = plaintext;

	// Attribute specific checks

	if (value.size() < ulValueLen)
		return CKR_GENERAL_ERROR;

	// Store data

	osobject->setAttribute(type, value);

	// Set the size during C_CreateObject and C_UnwrapKey.

	if (op == OBJECT_OP_CREATE || op == OBJECT_OP_UNWRAP)
	{
		// Set the CKA_VALUE_LEN
		if (osobject->attributeExists(CKA_VALUE_LEN))
		{
			OSAttribute bytes((unsigned long)plaintext.size());
			osobject->setAttribute(CKA_VALUE_LEN, bytes);
		}

		// Set the CKA_VALUE_BITS
		if (osobject->attributeExists(CKA_VALUE_BITS))
		{
			OSAttribute bits((unsigned long)plaintext.bits());
			osobject->setAttribute(CKA_VALUE_BITS, bits);
		}
	}

	// Calculate the CKA_CHECK_VALUE for certificates
	if (osobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_CERTIFICATE)
	{
		HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA1);
		if (hash == NULL) return CKR_GENERAL_ERROR;

		ByteString digest;
		if (hash->hashInit() == false ||
		    hash->hashUpdate(plaintext) == false ||
		    hash->hashFinal(digest) == false)
		{
			CryptoFactory::i()->recycleHashAlgorithm(hash);
			return CKR_GENERAL_ERROR;
		}
		CryptoFactory::i()->recycleHashAlgorithm(hash);

		// First three bytes of the SHA-1 hash
		digest.resize(3);

		if (isPrivate)
		{
			ByteString encrypted;
			if (!token->encrypt(digest, encrypted))
				return CKR_GENERAL_ERROR;
			osobject->setAttribute(CKA_CHECK_VALUE, encrypted);
		}
		else
			osobject->setAttribute(CKA_CHECK_VALUE, digest);
	}

	// Calculate the CKA_CHECK_VALUE for secret keys
	if (op == OBJECT_OP_CREATE &&
	    osobject->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_SECRET_KEY)
	{
		SymmetricKey key;
		AESKey aes;
		DESKey des;
		ByteString checkValue;
		switch (osobject->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED))
		{
			case CKK_GENERIC_SECRET:
			case CKK_MD5_HMAC:
			case CKK_SHA_1_HMAC:
			case CKK_SHA224_HMAC:
			case CKK_SHA256_HMAC:
			case CKK_SHA384_HMAC:
			case CKK_SHA512_HMAC:
				key.setKeyBits(plaintext);
				key.setBitLen(plaintext.size() * 8);
				checkValue = key.getKeyCheckValue();
				break;
			case CKK_AES:
				aes.setKeyBits(plaintext);
				aes.setBitLen(plaintext.size() * 8);
				checkValue = aes.getKeyCheckValue();
				break;
			case CKK_DES:
			case CKK_DES2:
			case CKK_DES3:
				des.setKeyBits(plaintext);
				des.setBitLen(plaintext.size() * 7);
				checkValue = des.getKeyCheckValue();
				break;
			case CKK_GOST28147:
				// TODO: Encryption support for CKK_GOST28147
				// We do not calculate the KCV
				break;
			default:
				return CKR_GENERAL_ERROR;
		}

		if (isPrivate)
		{
			ByteString encrypted;
			if (!token->encrypt(checkValue, encrypted))
				return CKR_GENERAL_ERROR;
			osobject->setAttribute(CKA_CHECK_VALUE, encrypted);
		}
		else
			osobject->setAttribute(CKA_CHECK_VALUE, checkValue);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_SUBJECT
 *****************************************/

// Set default value
bool P11AttrSubject::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_ISSUER
 *****************************************/

// Set default value
bool P11AttrIssuer::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_TRUSTED
 *****************************************/

// Set default value
bool P11AttrTrusted::setDefault()
{
	OSAttribute attr(false);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrTrusted::updateAttr(Token *token, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
		if (!token->isSOLoggedIn())
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrCertificateCategory::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_ULONG))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrStartDate::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_DATE) && ulValueLen !=0)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrEndDate::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_DATE) && ulValueLen !=0)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data
	osobject->setAttribute(type, ByteString((unsigned char*)pValue, ulValueLen));

	return CKR_OK;
}

/*****************************************
 * CKA_SERIAL_NUMBER
 *****************************************/

// Set default value
bool P11AttrSerialNumber::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_URL
 *****************************************/

// Set default value
bool P11AttrURL::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_HASH_OF_SUBJECT_PUBLIC_KEY
 *****************************************/

// Set default value
bool P11AttrHashOfSubjectPublicKey::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_HASH_OF_ISSUER_PUBLIC_KEY
 *****************************************/

// Set default value
bool P11AttrHashOfIssuerPublicKey::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_JAVA_MIDP_SECURITY_DOMAIN
 *****************************************/

// Set default value
bool P11AttrJavaMidpSecurityDomain::setDefault()
{
	OSAttribute attr((unsigned long)0);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrJavaMidpSecurityDomain::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data
	osobject->setAttribute(type, *(CK_ULONG*)pValue);

	return CKR_OK;
}

/*****************************************
 * CKA_NAME_HASH_ALGORITHM
 *****************************************/

// Set default value
bool P11AttrNameHashAlgorithm::setDefault()
{
	OSAttribute attr((unsigned long)CKM_SHA_1);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrNameHashAlgorithm::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data
	osobject->setAttribute(type, *(CK_ULONG*)pValue);

	return CKR_OK;
}

/*****************************************
 * CKA_DERIVE
 *****************************************/

// Set default value
bool P11AttrDerive::setDefault()
{
	OSAttribute attr(false);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrDerive::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrEncrypt::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrVerify::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrVerifyRecover::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrWrap::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrDecrypt::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrSign::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrSignRecover::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrUnwrap::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrLocal::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR /*pValue*/, CK_ULONG /*ulValueLen*/, int /*op*/)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrKeyGenMechanism::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR /*pValue*/, CK_ULONG /*ulValueLen*/, int /*op*/)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrAlwaysSensitive::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR /*pValue*/, CK_ULONG /*ulValueLen*/, int /*op*/)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrNeverExtractable::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR /*pValue*/, CK_ULONG /*ulValueLen*/, int /*op*/)
{
	return CKR_ATTRIBUTE_READ_ONLY;
}

/*****************************************
 * CKA_SENSITIVE
 *****************************************/

// Set default value
bool P11AttrSensitive::setDefault()
{
	// We default to false because we want to handle the secret keys in a correct way
	OSAttribute attr(false);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrSensitive::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op == OBJECT_OP_SET || op == OBJECT_OP_COPY)
	{
		if (osobject->getBooleanValue(CKA_SENSITIVE, false))
		{
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	if (ulValueLen !=sizeof(CK_BBOOL))
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
		if (op == OBJECT_OP_GENERATE || op == OBJECT_OP_DERIVE)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrExtractable::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op == OBJECT_OP_SET || op == OBJECT_OP_COPY)
	{
		if (osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false)
		{
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrWrapWithTrusted::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (op == OBJECT_OP_SET || op == OBJECT_OP_COPY)
	{
		if (osobject->getBooleanValue(CKA_WRAP_WITH_TRUSTED, false))
		{
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	if (ulValueLen !=sizeof(CK_BBOOL))
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrAlwaysAuthenticate::updateAttr(Token* /*token*/, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	OSAttribute attrTrue(true);
	OSAttribute attrFalse(false);

	// Attribute specific checks

	if (ulValueLen !=sizeof(CK_BBOOL))
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
		if (!isPrivate)
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
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrModulus::updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	ByteString plaintext((unsigned char*)pValue, ulValueLen);
	ByteString value;

	// Encrypt

	if (isPrivate)
	{
		if (!token->encrypt(plaintext, value))
			return CKR_GENERAL_ERROR;
	}
	else
		value = plaintext;

	// Attribute specific checks

	if (value.size() < ulValueLen)
		return CKR_GENERAL_ERROR;

	// Store data

	osobject->setAttribute(type, value);

	// Set the CKA_MODULUS_BITS during C_CreateObject

	if (op == OBJECT_OP_CREATE && osobject->attributeExists(CKA_MODULUS_BITS))
	{
		OSAttribute bits((unsigned long)plaintext.bits());
		osobject->setAttribute(CKA_MODULUS_BITS, bits);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_PUBLIC_EXPONENT
 *****************************************/

// Set default value
bool P11AttrPublicExponent::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_PRIVATE_EXPONENT
 *****************************************/

// Set default value
bool P11AttrPrivateExponent::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_PRIME_1
 *****************************************/

// Set default value
bool P11AttrPrime1::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_PRIME_2
 *****************************************/

// Set default value
bool P11AttrPrime2::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_EXPONENT_1
 *****************************************/

// Set default value
bool P11AttrExponent1::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_EXPONENT_2
 *****************************************/

// Set default value
bool P11AttrExponent2::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_COEFFICIENT
 *****************************************/

// Set default value
bool P11AttrCoefficient::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_MODULUS_BITS
 *****************************************/

// Set default value
bool P11AttrModulusBits::setDefault()
{
	OSAttribute attr((unsigned long)0);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrModulusBits::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	// Attribute specific checks

	if (op != OBJECT_OP_GENERATE)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	if (ulValueLen !=sizeof(CK_ULONG))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Store data

	osobject->setAttribute(type, *(CK_ULONG*)pValue);

	return CKR_OK;
}

/*****************************************
 * CKA_PRIME
 *****************************************/

// Set default value
bool P11AttrPrime::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPrime::updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	ByteString plaintext((unsigned char*)pValue, ulValueLen);
	ByteString value;

	// Encrypt

	if (isPrivate)
	{
		if (!token->encrypt(plaintext, value))
			return CKR_GENERAL_ERROR;
	}
	else
		value = plaintext;

	// Attribute specific checks

	if (value.size() < ulValueLen)
		return CKR_GENERAL_ERROR;

	// Store data

	osobject->setAttribute(type, value);

	// Set the CKA_PRIME_BITS during C_CreateObject

	if (op == OBJECT_OP_CREATE && osobject->attributeExists(CKA_PRIME_BITS))
	{
		OSAttribute bits((unsigned long)plaintext.bits());
		osobject->setAttribute(CKA_PRIME_BITS, bits);
	}

	return CKR_OK;
}

/*****************************************
 * CKA_SUBPRIME
 *****************************************/

// Set default value
bool P11AttrSubPrime::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_BASE
 *****************************************/

// Set default value
bool P11AttrBase::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_PRIME_BITS
 *****************************************/

// Set default value
bool P11AttrPrimeBits::setDefault()
{
	OSAttribute attr((unsigned long)0);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrPrimeBits::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
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
 * CKA_VALUE_BITS
 *****************************************/

// Set default value
bool P11AttrValueBits::setDefault()
{
	OSAttribute attr((unsigned long)0);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrValueBits::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
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
 * CKA_EC_PARAMS
 *****************************************/

// Set default value
bool P11AttrEcParams::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_EC_POINT
 *****************************************/

// Set default value
bool P11AttrEcPoint::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_GOSTR3410_PARAMS
 *****************************************/

// Set default value
bool P11AttrGostR3410Params::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_GOSTR3411_PARAMS
 *****************************************/

// Set default value
bool P11AttrGostR3411Params::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_GOST28147_PARAMS
 *****************************************/

// Set default value
bool P11AttrGost28147Params::setDefault()
{
	OSAttribute attr(ByteString(""));
	return osobject->setAttribute(type, attr);
}

/*****************************************
 * CKA_VALUE_LEN
 *****************************************/

// Set default value
bool P11AttrValueLen::setDefault()
{
	OSAttribute attr((unsigned long)0);
	return osobject->setAttribute(type, attr);
}

// Update the value if allowed
CK_RV P11AttrValueLen::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op)
{
	// Attribute specific checks

	if (op != OBJECT_OP_GENERATE && op != OBJECT_OP_DERIVE)
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
 * CKA_WRAP_TEMPLATE
 *****************************************/

// Set default value
bool P11AttrWrapTemplate::setDefault()
{
	std::map<CK_ATTRIBUTE_TYPE,OSAttribute> empty;
	OSAttribute attr(empty);
	return osobject->setAttribute(type, attr);
}

// Update the value
CK_RV P11AttrWrapTemplate::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks
	if ((ulValueLen % sizeof(CK_ATTRIBUTE)) != 0)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Fill the template vector with elements
	CK_ATTRIBUTE_PTR attr = (CK_ATTRIBUTE_PTR) pValue;
	std::map<CK_ATTRIBUTE_TYPE,OSAttribute> data;
	for (size_t i = 0; i < ulValueLen / sizeof(CK_ATTRIBUTE); ++i, ++attr)
	// Specialization for known attributes
	switch (attr->type)
	{
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_COPYABLE:
	case CKA_TRUSTED:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_EXTRACTABLE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_SECONDARY_AUTH:
	case CKA_ALWAYS_AUTHENTICATE:
		{
			// CK_BBOOL
			if (attr->ulValueLen != sizeof(CK_BBOOL))
				return CKR_ATTRIBUTE_VALUE_INVALID;
			bool elem = (*(CK_BBOOL*)attr->pValue != CK_FALSE);
			data.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attr->type, elem));
		}
		break;

	case CKA_CLASS:
	case CKA_KEY_TYPE:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	case CKA_NAME_HASH_ALGORITHM:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_MODULUS_BITS:
	case CKA_PRIME_BITS:
	case CKA_SUB_PRIME_BITS:
	case CKA_VALUE_BITS:
	case CKA_VALUE_LEN:
	case CKA_AUTH_PIN_FLAGS:
		{
			// CK_ULONG
			if (attr->ulValueLen != sizeof(CK_ULONG))
				return CKR_ATTRIBUTE_VALUE_INVALID;
			unsigned long elem = *(CK_ULONG*)attr->pValue;
			data.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attr->type, elem));
		}
		break;

	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_VALUE_INVALID;

	default:
		{
			// CK_BYTE
			ByteString elem = ByteString((unsigned char*)attr->pValue, attr->ulValueLen);
			data.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attr->type, elem));
		}
	}

	// Store data
	osobject->setAttribute(type, data);

	return CKR_OK;
}

/*****************************************
 * CKA_UNWRAP_TEMPLATE
 *****************************************/

// Set default value
bool P11AttrUnwrapTemplate::setDefault()
{
	std::map<CK_ATTRIBUTE_TYPE,OSAttribute> empty;
	OSAttribute attr(empty);
	return osobject->setAttribute(type, attr);
}

// Update the value
CK_RV P11AttrUnwrapTemplate::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	// Attribute specific checks
	if ((ulValueLen % sizeof(CK_ATTRIBUTE)) != 0)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Fill the template vector with elements
	CK_ATTRIBUTE_PTR attr = (CK_ATTRIBUTE_PTR) pValue;
	std::map<CK_ATTRIBUTE_TYPE,OSAttribute> data;
	for (size_t i = 0; i < ulValueLen / sizeof(CK_ATTRIBUTE); ++i, ++attr)
	// Specialization for known attributes
	switch (attr->type)
	{
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_COPYABLE:
	case CKA_TRUSTED:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_EXTRACTABLE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_SECONDARY_AUTH:
	case CKA_ALWAYS_AUTHENTICATE:
		{
			// CK_BBOOL
			if (attr->ulValueLen != sizeof(CK_BBOOL))
				return CKR_ATTRIBUTE_VALUE_INVALID;
			bool elem = (*(CK_BBOOL*)attr->pValue != CK_FALSE);
			data.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attr->type, elem));
		}
		break;

	case CKA_CLASS:
	case CKA_KEY_TYPE:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	case CKA_NAME_HASH_ALGORITHM:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_MODULUS_BITS:
	case CKA_PRIME_BITS:
	case CKA_SUB_PRIME_BITS:
	case CKA_VALUE_BITS:
	case CKA_VALUE_LEN:
	case CKA_AUTH_PIN_FLAGS:
		{
			// CK_ULONG
			if (attr->ulValueLen != sizeof(CK_ULONG))
				return CKR_ATTRIBUTE_VALUE_INVALID;
			unsigned long elem = *(CK_ULONG*)attr->pValue;
			data.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attr->type, elem));
		}
		break;

	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_VALUE_INVALID;

	default:
		{
			// CK_BYTE
			ByteString elem = ByteString((unsigned char*)attr->pValue, attr->ulValueLen);
			data.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attr->type, elem));
		}
	}

	// Store data
	osobject->setAttribute(type, data);

	return CKR_OK;
}

/*****************************************
 * CKA_ALLOWED_MECHANISMS
 *****************************************/

// Set default value
bool P11AttrAllowedMechanisms::setDefault()
{
	std::set<CK_MECHANISM_TYPE> emptyMap;
	return osobject->setAttribute(type, OSAttribute(emptyMap));
}

// Update the value if allowed
CK_RV P11AttrAllowedMechanisms::updateAttr(Token* /*token*/, bool /*isPrivate*/, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int /*op*/)
{
	if (ulValueLen == 0 || (ulValueLen % sizeof(CK_MECHANISM_TYPE)) != 0)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	CK_MECHANISM_TYPE_PTR mechType = (CK_MECHANISM_TYPE_PTR) pValue;

	// Fill the set with values
	std::set<CK_MECHANISM_TYPE> data;
	for (size_t i = 0; i < ulValueLen / sizeof(CK_MECHANISM_TYPE); ++i, ++mechType)
	{
		data.insert(*mechType);
	}

	// Store data
	osobject->setAttribute(type, OSAttribute(data));
	return CKR_OK;
}
