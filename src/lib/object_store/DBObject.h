/*
 * Copyright (c) 2013 SURFnet bv
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
 DBObject.h

 This class represents object records in a database
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DBOBJECT_H
#define _SOFTHSM_V2_DBOBJECT_H

#include "config.h"
#include "OSAttribute.h"
#include "cryptoki.h"
#include "OSObject.h"
#include "ObjectStoreToken.h"

#include "MutexFactory.h"
#include <string>

namespace DB { class Connection;  }

class DBObject : public OSObject
{
public:
	// Constructor for creating or accessing an object, don't do anything yet.
	DBObject(DB::Connection *connection, ObjectStoreToken *token = NULL);

	// Constructor for accessing an object with an objectId known to exists
	DBObject(DB::Connection *connection, ObjectStoreToken *token, long long objectId);

	// Destructor
	virtual ~DBObject();

	// Will drop any internal references to the connection
	void dropConnection();

	// create tables to support storage of attributes for the object.
	bool createTables();

	// drop tables that support storage of attributes for the object.
	bool dropTables();

	// Find an existing object.
	bool find(long long objectId);

	// Insert a new object into the database and retrieve the object id associated with it.
	bool insert();

	// Remove an existing object from the database and reset the object id to zero.
	bool remove();

	// Object id associated with this object.
	long long objectId();

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

	// The validity state of the object
	virtual bool isValid();

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

	// Destroys the object (warning, any pointers to the object are no longer
	// valid after this call because delete is called!)
	virtual bool destroyObject();

private:
	// Disable copy constructor and assignment
	DBObject();
	DBObject(const DBObject&);
	DBObject & operator= (const DBObject &);

	// Mutex object for thread-safeness
	Mutex* _mutex;

	DB::Connection *_connection;
	ObjectStoreToken *_token;
	long long _objectId;

	std::map<CK_ATTRIBUTE_TYPE,OSAttribute*> _attributes;
	std::map<CK_ATTRIBUTE_TYPE,OSAttribute*> *_transaction;

	OSAttribute* getAttributeDB(CK_ATTRIBUTE_TYPE type);
	OSAttribute* accessAttribute(CK_ATTRIBUTE_TYPE type);
};

#endif // !_SOFTHSM_V2_DBOBJECT_H

