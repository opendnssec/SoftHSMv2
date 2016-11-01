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
 SessionObject.h

 This class implements session objects (i.e. objects that are non-persistent)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SESSIONOBJECT_H
#define _SOFTHSM_V2_SESSIONOBJECT_H

#include "config.h"
#include "ByteString.h"
#include "OSAttribute.h"
#include "MutexFactory.h"
#include <string>
#include <map>
#include "cryptoki.h"
#include "OSObject.h"

// Forward declaration of the session object store
class SessionObjectStore;

class SessionObject : public OSObject
{
public:
	// Constructor
	SessionObject(SessionObjectStore* inParent, CK_SLOT_ID inSlotID, CK_SESSION_HANDLE inHSession, bool inIsPrivate = false);

	// Destructor
	virtual ~SessionObject();

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

	bool hasSlotID(CK_SLOT_ID inSlotID);

	// Called by the session object store when a session is closed. If it's the
	// session this object was associated with, the function returns true and the
	// object is invalidated
	bool removeOnSessionClose(CK_SESSION_HANDLE inHSession);

	// Called by the session object store when all the sessions for a token
	// have been closed.
	bool removeOnAllSessionsClose(CK_SLOT_ID inSlotID);

	// Called by the session object store when a token is logged out.
	// Remove when this session object is a private object for this token.
	bool removeOnTokenLogout(CK_SLOT_ID inSlotID);

	// These functions are just stubs for session objects
	virtual bool startTransaction(Access access);
	virtual bool commitTransaction();
	virtual bool abortTransaction();

	// Destroys the object; WARNING: pointers to the object become invalid after this
	// call!
	virtual bool destroyObject();

	// Invalidate the object
	void invalidate();

private:
	// Discard the object's attributes
	void discardAttributes();

	// The object's raw attributes
	std::map<CK_ATTRIBUTE_TYPE, OSAttribute*> attributes;

	// The object's validity state
	bool valid;

	// Mutex object for thread-safeness
	Mutex* objectMutex;

	// The slotID of the object is associated with.
	CK_SLOT_ID slotID;

	// The session the object is associated with.
	CK_SESSION_HANDLE hSession;

	// Indicates whether this object is private
	bool isPrivate;

	// The parent SessionObjectStore
	SessionObjectStore* parent;
};

#endif // !_SOFTHSM_V2_SESSIONOBJECT_H

