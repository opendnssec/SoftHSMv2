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
 SessionObjectStore.h

 The token class; a token is stored in a directory containing several files.
 Each object is stored in a separate file and a token object is present that
 has the token specific attributes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SESSIONOBJECTSTORE_H
#define _SOFTHSM_V2_SESSIONOBJECTSTORE_H

#include "config.h"
#include "OSAttribute.h"
#include "SessionObject.h"
#include "MutexFactory.h"
#include "cryptoki.h"
#include <string>
#include <set>
#include <map>
#include <list>
#include <memory>

class SessionObjectStore
{
public:
	// Constructor
	SessionObjectStore();

	// Retrieve objects
	std::set<SessionObject*> getObjects();

	// Insert the session objects for the given slotID into the given OSObject set
	void getObjects(CK_SLOT_ID slotID, std::set<OSObject*> &inObjects);

	// Create a new object
	SessionObject* createObject(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession, bool isPrivate = false);

	// Delete an object
	bool deleteObject(SessionObject* object);

	// Indicate that a session has been closed; invalidates all objects
	// associated with this session.
	void sessionClosed(CK_SESSION_HANDLE hSession);

	// Indicate that for a token all sessions have been closed.
	// Invalidates all objects associated with the token.
	void allSessionsClosed(CK_SLOT_ID slotID);

	// Indicate that a token has been logged out; invalidates all private
	// objects associated with this token.
	void tokenLoggedOut(CK_SLOT_ID slotID);

	// Destructor
	virtual ~SessionObjectStore();

	// Clears the store; should be called when all sessions are closed
	void clearStore();

private:
	// The current objects in the store
	std::set<SessionObject*> objects;

	// All the objects ever kept in the store
	std::set<SessionObject*> allObjects;

	// The current list of files
	std::set<std::string> currentFiles;

	// For thread safeness
	Mutex* storeMutex;
};

#endif // !_SOFTHSM_V2_SESSIONOBJECTSTORE_H

