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

class SessionObject : public OSObject
{
public:
	// Constructor
	SessionObject(CK_SESSION_HANDLE hSession);

	// Destructor
	virtual ~SessionObject();

	// Check if the specified attribute exists
	virtual bool attributeExists(CK_ATTRIBUTE_TYPE type);

	// Retrieve the specified attribute
	virtual OSAttribute* getAttribute(CK_ATTRIBUTE_TYPE type);

	// Set the specified attribute
	virtual bool setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute);

	// The validity state of the object
	virtual bool isValid();

	// Called by the session object store when a session is closed. If it's the
	// session this object was associated with, the function returns true and the
	// object is invalidated
	bool closeSession(CK_SESSION_HANDLE hSession);

	// These functions are just stubs for session objects
	virtual bool startTransaction();
	virtual bool commitTransaction();
	virtual bool abortTransaction();

private:
	// Discard the object's attributes
	void discardAttributes();

	// The object's raw attributes
	std::map<CK_ATTRIBUTE_TYPE, OSAttribute*> attributes;

	// The object's validity state
	bool valid;

	// Mutex object for thread-safeness
	Mutex* objectMutex;

	// The session the object is associated with
	CK_SESSION_HANDLE hSession;
};

#endif // !_SOFTHSM_V2_SESSIONOBJECT_H

