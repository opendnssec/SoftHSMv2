/*
 * Copyright (c) 2010 SURFnet bv
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
 OSAttribute.h

 This class represents the object store view on an object's attribute
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSATTRIBUTE_H
#define _SOFTHSM_V2_OSATTRIBUTE_H

#include "config.h"
#include "ByteString.h"
#include <map>
#include <set>

class OSAttribute
{
public:
	// Copy constructor
	OSAttribute(const OSAttribute& in);

	// Constructor for a boolean type attribute
	OSAttribute(const bool value);

	// Constructor for an unsigned long type attribute
	OSAttribute(const unsigned long value);

	// Constructor for a byte string type attribute
	OSAttribute(const ByteString& value);

	// Constructor for a mechanism type set type attribute
	OSAttribute(const std::set<CK_MECHANISM_TYPE>& value);

	// Constructor for an attribute map type attribute
	OSAttribute(const std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& value);

	// Destructor
	virtual ~OSAttribute() { }

	// Check the attribute type
	bool isBooleanAttribute() const;
	bool isUnsignedLongAttribute() const;
	bool isByteStringAttribute() const;
	bool isMechanismTypeSetAttribute() const;
	bool isAttributeMapAttribute() const;

	// Retrieve the attribute value
	bool getBooleanValue() const;
	unsigned long getUnsignedLongValue() const;
	const ByteString& getByteStringValue() const;
	const std::set<CK_MECHANISM_TYPE>& getMechanismTypeSetValue() const;
	const std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& getAttributeMapValue() const;

	// Helper for template (aka array) matching
	bool peekValue(ByteString& value) const;

private:
	// The attribute type
	enum
	{
		BOOL,
		ULONG,
		BYTESTR,
		MECHSET,
		ATTRMAP
	}
	attributeType;

	// The attribute value
	bool boolValue;
	unsigned long ulongValue;
	ByteString byteStrValue;
	std::set<CK_MECHANISM_TYPE> mechSetValue;
	std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrMapValue;
};

#endif // !_SOFTHSM_V2_OSATTRIBUTE_H

