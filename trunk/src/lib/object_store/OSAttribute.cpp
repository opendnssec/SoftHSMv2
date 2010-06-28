/* $Id$ */

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
 OSAttribute.cpp

 This class represents the object store view on an object's attribute
 *****************************************************************************/

#include "config.h"
#include "OSAttribute.h"

// Constructor for a boolean type attribute
OSAttribute::OSAttribute(const bool value)
{
	boolValue = value;
	attributeType = BOOL;
}

// Constructor for an unsigned long type attribute
OSAttribute::OSAttribute(const unsigned long value)
{
	ulongValue = value;
	attributeType = ULONG;
}

// Constructor for a byte string type attribute
OSAttribute::OSAttribute(const ByteString& value)
{
	byteStrValue = value;
	attributeType = BYTESTR;
}

// Check the attribute type
bool OSAttribute::isBooleanAttribute() const
{
	return (attributeType == BOOL);
}

bool OSAttribute::isUnsignedLongAttribute() const
{
	return (attributeType == ULONG);
}

bool OSAttribute::isByteStringAttribute() const
{
	return (attributeType == BYTESTR);
}

// Retrieve the attribute value
const bool OSAttribute::getBooleanValue() const
{
	return boolValue;
}

const unsigned long OSAttribute::getUnsignedLongValue() const
{
	return ulongValue;
}

const ByteString& OSAttribute::getByteStringValue() const
{
	return byteStrValue;
}

// Set the attribute value
void OSAttribute::setBooleanValue(const bool value)
{
	boolValue = value;
}

void OSAttribute::setUnsignedLongValue(const unsigned long value)
{
	ulongValue = value;
}

void OSAttribute::setByteStringValue(const ByteString& value)
{
	byteStrValue = value;
}

