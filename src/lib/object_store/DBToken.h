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
 DBToken.h

 The token class; a token is stored in a directory containing a single
 database file.
 Each object is stored in multiple tables with every attribute base type
 stored in a different table.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DBTOKEN_H
#define _SOFTHSM_V2_DBTOKEN_H

#include "config.h"
#include "ByteString.h"
#include "MutexFactory.h"
#include "OSAttribute.h"
#include "cryptoki.h"
#include "OSObject.h"
#include "ObjectStoreToken.h"

#include <string>
#include <set>

namespace DB { class Connection; }

class DBToken : public ObjectStoreToken
{
public:
	// Constructor to create a new token
	DBToken(const std::string &baseDir, const std::string &tokenName, const ByteString& label, const ByteString& serial);

	// Constructor to access an existing token
	DBToken(const std::string &baseDir, const std::string &tokenName);

	// Create a new token
	static DBToken* createToken(const std::string basePath, const std::string tokenDir, const ByteString& label, const ByteString& serial);

	// Access an existing token
	static DBToken* accessToken(const std::string &basePath, const std::string &tokenDir);

	// Destructor
	virtual ~DBToken();

	// Set the SO PIN
	virtual bool setSOPIN(const ByteString& soPINBlob);

	// Get the SO PIN
	virtual bool getSOPIN(ByteString& soPINBlob);

	// Set the user PIN
	virtual bool setUserPIN(ByteString userPINBlob);

	// Get the user PIN
	virtual bool getUserPIN(ByteString& userPINBlob);

	// Get the token flags
	virtual bool getTokenFlags(CK_ULONG& flags);

	// Set the token flags
	virtual bool setTokenFlags(const CK_ULONG flags);

	// Retrieve the token label
	virtual bool getTokenLabel(ByteString& label);

	// Retrieve the token serial
	virtual bool getTokenSerial(ByteString& serial);

	// Retrieve objects
	virtual std::set<OSObject*> getObjects();

	// Insert objects into the given set
	virtual void getObjects(std::set<OSObject*> &objects);

	// Create a new object
	virtual OSObject* createObject();

	// Delete an object
	virtual bool deleteObject(OSObject* object);

	// Checks if the token is consistent
	virtual bool isValid();

	// Invalidate the token (for instance if it is deleted)
	virtual void invalidate();

	// Delete the token
	virtual bool clearToken();

	// Reset the token
	virtual bool resetToken(const ByteString& label);

private:
	DB::Connection *_connection;

	// All the objects ever associated with this token
	//
	// This map is kept to be able to clean up when the token
	// instance is discarded; in case the contents of a token
	// change, some objects may disappear but we cannot simply
	// delete them since they may still be referenced from an
	// object outside of this class.
	std::map<long long, OSObject*> _allObjects;

	// For thread safeness
	Mutex* _tokenMutex;
};

#endif // !_SOFTHSM_V2_DBTOKEN_H

