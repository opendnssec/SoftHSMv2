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
#include "SessionObjectStore.h"

// Constructor
SessionObject::SessionObject(SessionObjectStore* inParent, CK_SLOT_ID inSlotID, CK_SESSION_HANDLE inHSession, bool inIsPrivate)
{
	hSession = inHSession;
	slotID = inSlotID;
	isPrivate = inIsPrivate;
	objectMutex = MutexFactory::i()->getMutex();
	valid = (objectMutex != NULL);
	parent = inParent;
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
OSAttribute SessionObject::getAttribute(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(objectMutex);

	OSAttribute* attr = attributes[type];
	if (attr == NULL)
	{
		ERROR_MSG("The attribute does not exist: 0x%08X", type);
		return OSAttribute((unsigned long)0);
	}

	return *attr;
}

bool SessionObject::getBooleanValue(CK_ATTRIBUTE_TYPE type, bool val)
{
	MutexLocker lock(objectMutex);

	OSAttribute* attr = attributes[type];
	if (attr == NULL)
	{
		ERROR_MSG("The attribute does not exist: 0x%08X", type);
		return val;
	}

	if (attr->isBooleanAttribute())
	{
		return attr->getBooleanValue();
	}
	else
	{
		ERROR_MSG("The attribute is not a boolean: 0x%08X", type);
		return val;
	}
}

unsigned long SessionObject::getUnsignedLongValue(CK_ATTRIBUTE_TYPE type, unsigned long val)
{
	MutexLocker lock(objectMutex);

	OSAttribute* attr = attributes[type];
	if (attr == NULL)
	{
		ERROR_MSG("The attribute does not exist: 0x%08X", type);
		return val;
	}

	if (attr->isUnsignedLongAttribute())
	{
		return attr->getUnsignedLongValue();
	}
	else
	{
		ERROR_MSG("The attribute is not an unsigned long: 0x%08X", type);
		return val;
	}
}

ByteString SessionObject::getByteStringValue(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(objectMutex);

	ByteString val;

	OSAttribute* attr = attributes[type];
	if (attr == NULL)
	{
		ERROR_MSG("The attribute does not exist: 0x%08X", type);
		return val;
	}

	if (attr->isByteStringAttribute())
	{
		return attr->getByteStringValue();
	}
	else
	{
		ERROR_MSG("The attribute is not a byte string: 0x%08X", type);
		return val;
	}
}

// Retrieve the next attribute type
CK_ATTRIBUTE_TYPE SessionObject::nextAttributeType(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(objectMutex);

	std::map<CK_ATTRIBUTE_TYPE, OSAttribute*>::iterator n = attributes.upper_bound(type);

	// skip null attributes
	while ((n != attributes.end()) && (n->second == NULL))
		++n;


	// return type or CKA_CLASS (= 0)
	if (n == attributes.end())
	{
		return CKA_CLASS;
	}
	else
	{
		return n->first;
	}
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

// Delete the specified attribute
bool SessionObject::deleteAttribute(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(objectMutex);

	if (!valid)
	{
		DEBUG_MSG("Cannot update invalid session object 0x%08X", this);

		return false;
	}

	if (attributes[type] == NULL)
	{
		DEBUG_MSG("Cannot delete attribute that doesn't exist in object 0x%08X", this);

		return false;
	}

	delete attributes[type];
	attributes.erase(type);

	return true;
}

// The validity state of the object
bool SessionObject::isValid()
{
    return valid;
}

bool SessionObject::hasSlotID(CK_SLOT_ID inSlotID)
{
    return slotID == inSlotID;
}

// Called by the session object store when a session is closed. If it's the
// session this object was associated with, the function returns true and the
// object is invalidated
bool SessionObject::removeOnSessionClose(CK_SESSION_HANDLE inHSession)
{
	if (hSession == inHSession)
	{
		// Save space
		discardAttributes();

		valid = false;

		return true;
	}

	return false;
}

// Called by the session object store when a token is logged out.
// Remove when this session object is a private object for this token.
bool SessionObject::removeOnAllSessionsClose(CK_SLOT_ID inSlotID)
{
    if (slotID == inSlotID)
    {
        discardAttributes();

        valid = false;

        return true;
    }

    return false;
}

// Called by the session object store when a token is logged out.
// Remove when this session object is a private object for this token.
bool SessionObject::removeOnTokenLogout(CK_SLOT_ID inSlotID)
{
    if (slotID == inSlotID && isPrivate)
    {
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
bool SessionObject::startTransaction(Access)
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

bool SessionObject::destroyObject()
{
	if (parent == NULL)
	{
		ERROR_MSG("Cannot destroy object that is not associated with a session object store");

		return false;
	}

	return parent->deleteObject(this);
}

// Invalidate the object
void SessionObject::invalidate()
{
	valid = false;
	discardAttributes();
}

