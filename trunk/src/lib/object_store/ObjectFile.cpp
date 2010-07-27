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
 ObjectFile.h

 This class represents object files
 *****************************************************************************/

#include "config.h"
#include "ObjectFile.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

// Attribute types
#define BOOLEAN_ATTR			0x1
#define ULONG_ATTR			0x2
#define BYTESTR_ATTR			0x3

// Constructor
ObjectFile::ObjectFile(std::string path, bool isNew /* = false */)
{
	this->path = path;
	ipcSignal = IPCSignal::create(path);
	valid = (ipcSignal != NULL);

	if (!valid) return;

	if (!isNew)
	{
		refresh(true);
	}
	else
	{
		// Create an empty object file
		store();
	}

}

// Destructor
ObjectFile::~ObjectFile()
{
	discardAttributes();

	if (ipcSignal != NULL)
	{
		delete ipcSignal;
	}
}

// Check if the specified attribute exists
bool ObjectFile::attributeExists(CK_ATTRIBUTE_TYPE type)
{
	refresh();

	return valid && (attributes[type] != NULL);
}

// Retrieve the specified attribute
OSAttribute* ObjectFile::getAttribute(CK_ATTRIBUTE_TYPE type)
{
	refresh();

	return attributes[type];
}

// Set the specified attribute
bool ObjectFile::setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute)
{
	refresh();

	if (!valid)
	{
		DEBUG_MSG("Cannot update invalid object %s", path.c_str());

		return false;
	}

	if (attributes[type] != NULL)
	{
		delete attributes[type];

		attributes[type] = NULL;
	}

	attributes[type] = new OSAttribute(attribute);

	store();

	return isValid();
}

// The validity state of the object
bool ObjectFile::isValid()
{
	return valid;
}

// Refresh the object if necessary
void ObjectFile::refresh(bool isFirstTime /* = false */)
{
	// Check the IPC signal
	if (!isFirstTime && !ipcSignal->wasTriggered())
	{
		return;
	}

	File objectFile(path);

	if (!objectFile.isValid())
	{
		valid = false;

		return;
	}

	// Discard the existing set of attributes
	discardAttributes();

	objectFile.lock();

	// Read back the attributes
	do
	{
		unsigned long p11AttrType;
		unsigned long osAttrType;

		if (!objectFile.readULong(p11AttrType))
		{
			if (objectFile.isEOF())
			{
				break;
			}

			DEBUG_MSG("Corrupt object file %s", path.c_str());

			valid = false;

			return;
		}
			
		if (!objectFile.readULong(osAttrType))
		{
			DEBUG_MSG("Corrupt object file %s", path.c_str());

			valid = false;

			return;
		}

		// Depending on the type, read back the actual value
		if (osAttrType == BOOLEAN_ATTR)
		{
			bool value;

			if (!objectFile.readBool(value))
			{
				DEBUG_MSG("Corrupt object file %s", path.c_str());

				valid = false;

				return;
			}

			if (attributes[p11AttrType] != NULL)
			{
				delete attributes[p11AttrType];
			}

			attributes[p11AttrType] = new OSAttribute(value);
		}
		else if (osAttrType == ULONG_ATTR)
		{
			unsigned long value;

			if (!objectFile.readULong(value))
			{
				DEBUG_MSG("Corrupt object file %s", path.c_str());

				valid = false;

				return;
			}

			if (attributes[p11AttrType] != NULL)
			{
				delete attributes[p11AttrType];
			}
			
			attributes[p11AttrType] = new OSAttribute(value);
		}
		else if (osAttrType == BYTESTR_ATTR)
		{
			ByteString value;

			if (!objectFile.readByteString(value))
			{
				DEBUG_MSG("Corrupt object file %s", path.c_str());

				valid = false;

				return;
			}

			if (attributes[p11AttrType] != NULL)
			{
				delete attributes[p11AttrType];
			}
			
			attributes[p11AttrType] = new OSAttribute(value);
		}
		else
		{
			DEBUG_MSG("Corrupt object file %s with unknown attribute of type %d", path.c_str(), osAttrType);

			valid = false;

			return;
		}
	}
	while (!objectFile.isEOF());

	objectFile.unlock();

	valid = true;
}

// Write the object to background storage
void ObjectFile::store()
{
	if (!valid)
	{
		DEBUG_MSG("Cannot write back an invalid object %s", path.c_str());

		return;
	}

	File objectFile(path, false, true, true);

	if (!objectFile.isValid())
	{
		DEBUG_MSG("Cannot open object %s for writing", path.c_str());

		valid = false;

		return;
	}

	objectFile.lock();

	for (std::map<CK_ATTRIBUTE_TYPE, OSAttribute*>::iterator i = attributes.begin(); i != attributes.end(); i++)
	{
		if (i->second == NULL)
		{
			continue;
		}

		unsigned long p11AttrType = i->first;

		if (!objectFile.writeULong(p11AttrType))
		{
			DEBUG_MSG("Failed to write PKCS #11 attribute type to object %s", path.c_str());

			valid = false;

			return;
		}

		if (i->second->isBooleanAttribute())
		{
			unsigned long osAttrType = BOOLEAN_ATTR;
			bool value = i->second->getBooleanValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeBool(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				valid = false;

				return;
			}
		}
		else if (i->second->isUnsignedLongAttribute())
		{
			unsigned long osAttrType = ULONG_ATTR;
			unsigned long value = i->second->getUnsignedLongValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeULong(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				valid = false;

				return;
			}
		}
		else if (i->second->isByteStringAttribute())
		{
			unsigned long osAttrType = BYTESTR_ATTR;
			const ByteString& value = i->second->getByteStringValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeByteString(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				valid = false;

				return;
			}
		}
		else
		{
			DEBUG_MSG("Unknown attribute type for object %s", path.c_str());

			valid = false;

			return;
		}
	}

	objectFile.unlock();

	// Trigger the IPC signal
	ipcSignal->trigger();

	valid = true;
}

// Discard the cached attributes
void ObjectFile::discardAttributes()
{
	for (std::map<CK_ATTRIBUTE_TYPE, OSAttribute*>::iterator i = attributes.begin(); i != attributes.end(); i++)
	{
		if (i->second == NULL)
		{
			continue;
		}

		delete i->second;
		i->second = NULL;
	}

	attributes.clear();
}

