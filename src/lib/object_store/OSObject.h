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
 OSObject.h

 This file contains the abstract interface for ObjectStore objects. It is
 implemented by persistent objects in the form of the ObjectFile class and
 by session objects in the form of the SessionObject class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSOBJECT_H
#define _SOFTHSM_V2_OSOBJECT_H

#include "config.h"
#include "OSAttribute.h"
#include "cryptoki.h"

class OSObject
{
public:
	// Destructor
	virtual ~OSObject() { }

	// Check if the specified attribute exists
	virtual bool attributeExists(CK_ATTRIBUTE_TYPE type) = 0;

	// Retrieve the specified attribute
	virtual OSAttribute getAttribute(CK_ATTRIBUTE_TYPE type) = 0;
	virtual bool getBooleanValue(CK_ATTRIBUTE_TYPE type, bool val) = 0;
	virtual unsigned long getUnsignedLongValue(CK_ATTRIBUTE_TYPE type, unsigned long val) = 0;
	virtual ByteString getByteStringValue(CK_ATTRIBUTE_TYPE type) = 0;

	// Retrieve the next attribute type
	virtual CK_ATTRIBUTE_TYPE nextAttributeType(CK_ATTRIBUTE_TYPE type) = 0;

	// Set the specified attribute
	virtual bool setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute) = 0;

	// Delete the specified attribute
	virtual bool deleteAttribute(CK_ATTRIBUTE_TYPE type) = 0;

	// The validity state of the object
	virtual bool isValid() = 0;

	// Start an attribute set transaction; this method is used when - for
	// example - a key is generated and all its attributes need to be
	// persisted in one go.
	//
	// N.B.: Starting a transaction locks the object!
	//
	// Function returns false in case a transaction is already in progress
	enum Access {
		ReadOnly,
		ReadWrite
	};
	virtual bool startTransaction(Access access = ReadWrite) = 0;

	// Commit an attribute transaction; returns false if no transaction is in progress
	virtual bool commitTransaction() = 0;

	// Abort an attribute transaction; loads back the previous version of the object from disk;
	// returns false if no transaction was in progress
	virtual bool abortTransaction() = 0;

	// Destroys the object (warning, any pointers to the object are no longer
	// valid after this call because delete is called!)
	virtual bool destroyObject() = 0;
};

#endif // !_SOFTHSM_V2_OSOBJECT_H

