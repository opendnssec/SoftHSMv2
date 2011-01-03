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
 SessionObject.cpp

 This class implements session objects (i.e. objects that are non-persistent)
 *****************************************************************************/

#include "config.h"
#include "SessionObject.h"

// Constructor
SessionObject::SessionObject(CK_SESSION_HANDLE hSession)
{
	this->hSession = hSession;
	objectMutex = MutexFactory::i()->getMutex();
	valid = (objectMutex != NULL);
}

// Destructor
SessionObject::~SessionObject()
{
	discardAttributes();

	MutexFactory::i()->recycleMutex(objectMutex);
}

// Check if the specified attribute exists
bool SessionObject::attributeExists(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(objectMutex);

	return valid && (attributes[type] != NULL);
}

// Retrieve the specified attribute
OSAttribute* SessionObject::getAttribute(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(objectMutex);

	return attributes[type];
}

// Set the specified attribute
bool SessionObject::setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute)
{
	MutexLocker lock(objectMutex);

	if (!valid)
	{
		DEBUG_MSG("Cannot update invalid session object 0x%08X", this);

		return false;
	}

	if (attributes[type] != NULL)
	{
		delete attributes[type];

		attributes[type] = NULL;
	}

	attributes[type] = new OSAttribute(attribute);

	return true;
}

// The validity state of the object
bool SessionObject::isValid()
{
	return valid;
}

// Called by the session object store when a session is closed. If it's the
// session this object was associated with, the function returns true and the
// object is invalidated
bool SessionObject::closeSession(CK_SESSION_HANDLE hSession)
{
	if (this->hSession == hSession)
	{
		DEBUG_MSG("Session this object belongs to was closed");

		// Save space
		discardAttributes();

		valid = false;

		return true;
	}

	return false;
}

// Discard the object's attributes
void SessionObject::discardAttributes()
{
	MutexLocker lock(objectMutex);

	std::map<CK_ATTRIBUTE_TYPE, OSAttribute*> cleanUp = attributes;
	attributes.clear();

	for (std::map<CK_ATTRIBUTE_TYPE, OSAttribute*>::iterator i = cleanUp.begin(); i != cleanUp.end(); i++)
	{
		if (i->second == NULL)
		{
			continue;
		}

		delete i->second;
		i->second = NULL;
	}
}

// These functions are just stubs for session objects
bool SessionObject::startTransaction()
{
	return true;
}

bool SessionObject::commitTransaction()
{
	return true;
}

bool SessionObject::abortTransaction()
{
	return true;
}

