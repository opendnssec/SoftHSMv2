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
 ObjectFile.h

 This class represents object files
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OBJECTFILE_H
#define _SOFTHSM_V2_OBJECTFILE_H

#include "config.h"
#include "File.h"
#include "Generation.h"
#include "ByteString.h"
#include "OSAttribute.h"
#include "MutexFactory.h"
#include <string>
#include <map>
#include <time.h>
#include "cryptoki.h"
#include "OSObject.h"

// OSToken forward declaration
class OSToken;

class ObjectFile : public OSObject
{
public:
	// Constructor
	ObjectFile(OSToken* parent, const std::string inPath, const std::string inLockpath, bool isNew = false);

	// Destructor
	virtual ~ObjectFile();

	// Check if the specified attribute exists
	virtual bool attributeExists(CK_ATTRIBUTE_TYPE type);

	// Retrieve the specified attribute
	virtual OSAttribute getAttribute(CK_ATTRIBUTE_TYPE type);
	virtual bool getBooleanValue(CK_ATTRIBUTE_TYPE type, bool val);
	virtual unsigned long getUnsignedLongValue(CK_ATTRIBUTE_TYPE type, unsigned long val);
	virtual ByteString getByteStringValue(CK_ATTRIBUTE_TYPE type);

	// Retrieve the next attribute type
	virtual CK_ATTRIBUTE_TYPE nextAttributeType(CK_ATTRIBUTE_TYPE type);

	// Set the specified attribute
	virtual bool setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute);

	// Delete the specified attribute
	virtual bool deleteAttribute(CK_ATTRIBUTE_TYPE type);

	// The validity state of the object (refresh from disk as a side effect)
	virtual bool isValid();

	// Invalidate the object file externally; this method is normally
	// only called by the OSToken class in case an object file has
	// been deleted.
	void invalidate();

	// Returns the file name of the object
	std::string getFilename() const;

	// Returns the file name of the lock
	std::string getLockname() const;

	// Start an attribute set transaction; this method is used when - for
	// example - a key is generated and all its attributes need to be
	// persisted in one go.
	//
	// N.B.: Starting a transaction locks the object!
	//
	// Function returns false in case a transaction is already in progress
	virtual bool startTransaction(Access access);

	// Commit an attribute transaction; returns false if no transaction is in progress
	virtual bool commitTransaction();

	// Abort an attribute transaction; loads back the previous version of the object from disk;
	// returns false if no transaction was in progress
	virtual bool abortTransaction();

	// Destroys the object; WARNING: pointers to the object become invalid after this
	// call!
	virtual bool destroyObject();

private:
	// OSToken instances can read valid (vs calling IsValid() from index())
	friend class OSToken;

	// Refresh the object if necessary
	void refresh(bool isFirstTime = false);

	// Write the object to background storage
	void store(bool isCommit = false);

	// Store subroutine
	bool writeAttributes(File &objectFile);

	// Discard the cached attributes
	void discardAttributes();

	// The path to the file
	std::string path;

	// The Generation object that is used to detect changes in the
        // object file from other SoftHSM instances
	Generation* gen;

	// The object's raw attributes
	std::map<CK_ATTRIBUTE_TYPE, OSAttribute*> attributes;

	// The object's validity state
	bool valid;

	// The token this object is associated with
	OSToken* token;

	// Mutex object for thread-safeness
	Mutex* objectMutex;

	// Is the object undergoing an attribute transaction?
	bool inTransaction;
	File* transactionLockFile;
	std::string lockpath;
};

#endif // !_SOFTHSM_V2_OBJECTFILE_H

