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
 ObjectStoreToken.h

 The object store abstract token base class;
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OBJECTSTORETOKEN_H
#define _SOFTHSM_V2_OBJECTSTORETOKEN_H

#include "config.h"
#include "OSObject.h"
#include <string>
#include <set>

class ObjectStoreToken
{
public:
	// Select the type of backend to use for storing token objects.
	static bool selectBackend(const std::string& backend);

	// Create a new token
	static ObjectStoreToken* createToken(const std::string basePath, const std::string tokenDir, const ByteString& label, const ByteString& serial);

	// Access an existing token
	static ObjectStoreToken* accessToken(const std::string &basePath, const std::string &tokenDir);

	// Set the SO PIN
	virtual bool setSOPIN(const ByteString& soPINBlob) = 0;

	// Get the SO PIN
	virtual bool getSOPIN(ByteString& soPINBlob) = 0;

	// Set the user PIN
	virtual bool setUserPIN(ByteString userPINBlob) = 0;

	// Get the user PIN
	virtual bool getUserPIN(ByteString& userPINBlob) = 0;

	// Get the token flags
	virtual bool getTokenFlags(CK_ULONG& flags) = 0;

	// Set the token flags
	virtual bool setTokenFlags(const CK_ULONG flags) = 0;

	// Retrieve the token label
	virtual bool getTokenLabel(ByteString& label) = 0;

	// Retrieve the token serial
	virtual bool getTokenSerial(ByteString& serial) = 0;

	// Retrieve objects
	virtual std::set<OSObject*> getObjects() = 0;

	// Insert objects into the given set
	virtual void getObjects(std::set<OSObject*> &objects) = 0;

	// Create a new object
	virtual OSObject* createObject() = 0;

	// Delete an object
	virtual bool deleteObject(OSObject* object) = 0;

	// Destructor
	virtual ~ObjectStoreToken() {};

	// Checks if the token is consistent
	virtual bool isValid() = 0;

	// Invalidate the token (for instance if it is deleted)
	virtual void invalidate() = 0;

	// Delete the token
	virtual bool clearToken() = 0;

	// Reset the token
	virtual bool resetToken(const ByteString& label) = 0;
};

#endif // !_SOFTHSM_V2_OBJECTSTORETOKEN_H

