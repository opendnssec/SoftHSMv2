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
#include "OSToken.h"
#include "OSPathSep.h"
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <set>

// Attribute types
#define BOOLEAN_ATTR			0x1
#define ULONG_ATTR			0x2
#define BYTESTR_ATTR			0x3
#define ATTRMAP_ATTR			0x4
#define MECHSET_ATTR			0x5

// Constructor
ObjectFile::ObjectFile(OSToken* parent, std::string inPath, std::string inLockpath, bool isNew /* = false */)
{
	path = inPath;
	gen = Generation::create(path);
	objectMutex = MutexFactory::i()->getMutex();
	valid = (gen != NULL) && (objectMutex != NULL);
	token = parent;
	inTransaction = false;
	transactionLockFile = NULL;
	lockpath = inLockpath;

	if (!valid) return;

	if (!isNew)
	{
		DEBUG_MSG("Opened existing object %s", path.c_str());

		refresh(true);
	}
	else
	{
		DEBUG_MSG("Created new object %s", path.c_str());

		// Create an empty object file
		store();
	}

}

// Destructor
ObjectFile::~ObjectFile()
{
	discardAttributes();

	if (gen != NULL)
	{
		delete gen;
	}

	MutexFactory::i()->recycleMutex(objectMutex);
}

// Check if the specified attribute exists
bool ObjectFile::attributeExists(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(objectMutex);

	return valid && (attributes[type] != NULL);
}

// Retrieve the specified attribute
OSAttribute ObjectFile::getAttribute(CK_ATTRIBUTE_TYPE type)
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

bool ObjectFile::getBooleanValue(CK_ATTRIBUTE_TYPE type, bool val)
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

unsigned long ObjectFile::getUnsignedLongValue(CK_ATTRIBUTE_TYPE type, unsigned long val)
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

ByteString ObjectFile::getByteStringValue(CK_ATTRIBUTE_TYPE type)
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
CK_ATTRIBUTE_TYPE ObjectFile::nextAttributeType(CK_ATTRIBUTE_TYPE type)
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
bool ObjectFile::setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute)
{
	if (!valid)
	{
		DEBUG_MSG("Cannot update invalid object %s", path.c_str());

		return false;
	}

	{
		MutexLocker lock(objectMutex);

		if (attributes[type] != NULL)
		{
			delete attributes[type];

			attributes[type] = NULL;
		}

		attributes[type] = new OSAttribute(attribute);
	}

	store();

	return valid;
}

// Delete the specified attribute
bool ObjectFile::deleteAttribute(CK_ATTRIBUTE_TYPE type)
{
	if (!valid)
	{
		DEBUG_MSG("Cannot update invalid object %s", path.c_str());

		return false;
	}

	{
		MutexLocker lock(objectMutex);

		if (attributes[type] == NULL)
		{
			DEBUG_MSG("Cannot delete attribute that doesn't exist in object %s", path.c_str());

			return false;
		}

		delete attributes[type];
		attributes.erase(type);
	}

	store();

	return valid;
}

// The validity state of the object (refresh from disk as a side effect)
bool ObjectFile::isValid()
{
	refresh();

	return valid;
}

// Invalidate the object file externally; this method is normally
// only called by the OSToken class in case an object file has
// been deleted.
void ObjectFile::invalidate()
{
	valid = false;

	discardAttributes();
}

// Refresh the object if necessary
void ObjectFile::refresh(bool isFirstTime /* = false */)
{
	// Check if we're in the middle of a transaction
	if (inTransaction)
	{
		DEBUG_MSG("The object is in a transaction");

		return;
	}

	// Refresh the associated token if set
	if (!isFirstTime && (token != NULL))
	{
		// This may cause this instance to become invalid
		token->index();
	}

	// Check the generation
	if (!isFirstTime && (gen == NULL || !gen->wasUpdated()))
	{
		DEBUG_MSG("The object generation has not been updated");

		return;
	}

	File objectFile(path);

	if (!objectFile.isValid())
	{
		DEBUG_MSG("Object %s is invalid", path.c_str());

		valid = false;

		return;
	}

	objectFile.lock();

	if (objectFile.isEmpty())
	{
		DEBUG_MSG("Object %s is empty", path.c_str());

		valid = false;

		return;
	}

	DEBUG_MSG("Object %s has changed", path.c_str());

	// Discard the existing set of attributes
	discardAttributes();

	MutexLocker lock(objectMutex);

	// Read back the generation number
	unsigned long curGen;

	if (!objectFile.readULong(curGen))
	{
		if (!objectFile.isEOF())
		{
			DEBUG_MSG("Corrupt object file %s", path.c_str());

			valid = false;

			objectFile.unlock();

			return;
		}
	}
	else
	{
		gen->set(curGen);
	}

	// Read back the attributes
	while (!objectFile.isEOF())
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

			objectFile.unlock();

			return;
		}

		if (!objectFile.readULong(osAttrType))
		{
			DEBUG_MSG("Corrupt object file %s", path.c_str());

			valid = false;

			objectFile.unlock();

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

				objectFile.unlock();

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

				objectFile.unlock();

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

				objectFile.unlock();

				return;
			}

			if (attributes[p11AttrType] != NULL)
			{
				delete attributes[p11AttrType];
			}

			attributes[p11AttrType] = new OSAttribute(value);
		}
		else if (osAttrType == MECHSET_ATTR)
		{
			std::set<CK_MECHANISM_TYPE> value;

			if (!objectFile.readMechanismTypeSet(value))
			{
				DEBUG_MSG("Corrupt object file %s", path.c_str());

				valid = false;

				objectFile.unlock();

				return;
			}

			if (attributes[p11AttrType] != NULL)
			{
				delete attributes[p11AttrType];
			}

			attributes[p11AttrType] = new OSAttribute(value);
		}
		else if (osAttrType == ATTRMAP_ATTR)
		{
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute> value;

			if (!objectFile.readAttributeMap(value))
			{
				DEBUG_MSG("Corrupt object file %s", path.c_str());

				valid = false;

				objectFile.unlock();

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

			objectFile.unlock();

			return;
		}
	}

	objectFile.unlock();

	valid = true;
}

// Common write part in store()
// called with objectFile locked and returns with objectFile unlocked
bool ObjectFile::writeAttributes(File &objectFile)
{
	if (!gen->sync(objectFile))
	{
		DEBUG_MSG("Failed to synchronize generation number from object %s", path.c_str());

		objectFile.unlock();

		return false;
	}

	if (!objectFile.truncate())
	{
		DEBUG_MSG("Failed to reset object %s", path.c_str());

		objectFile.unlock();

		return false;
	}

	gen->update();

	unsigned long newGen = gen->get();

	if (!objectFile.writeULong(newGen))
	{
		DEBUG_MSG("Failed to write new generation number to object %s", path.c_str());

		gen->rollback();

		objectFile.unlock();

		return false;
	}


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

			objectFile.unlock();

			return false;
		}

		if (i->second->isBooleanAttribute())
		{
			unsigned long osAttrType = BOOLEAN_ATTR;
			bool value = i->second->getBooleanValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeBool(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				objectFile.unlock();

				return false;
			}
		}
		else if (i->second->isUnsignedLongAttribute())
		{
			unsigned long osAttrType = ULONG_ATTR;
			unsigned long value = i->second->getUnsignedLongValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeULong(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				objectFile.unlock();

				return false;
			}
		}
		else if (i->second->isByteStringAttribute())
		{
			unsigned long osAttrType = BYTESTR_ATTR;
			const ByteString& value = i->second->getByteStringValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeByteString(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				objectFile.unlock();

				return false;
			}
		}
		else if (i->second->isMechanismTypeSetAttribute())
		{
			unsigned long osAttrType = MECHSET_ATTR;
			const std::set<CK_MECHANISM_TYPE>& value = i->second->getMechanismTypeSetValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeMechanismTypeSet(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				objectFile.unlock();

				return false;
			}
		}
		else if (i->second->isAttributeMapAttribute())
		{
			unsigned long osAttrType = ATTRMAP_ATTR;
			const std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& value = i->second->getAttributeMapValue();

			if (!objectFile.writeULong(osAttrType) || !objectFile.writeAttributeMap(value))
			{
				DEBUG_MSG("Failed to write attribute to object %s", path.c_str());

				objectFile.unlock();

				return false;
			}
		}
		else
		{
			DEBUG_MSG("Unknown attribute type for object %s", path.c_str());

			objectFile.unlock();

			return false;
		}
	}

	objectFile.unlock();

	return true;
}

// Write the object to background storage
void ObjectFile::store(bool isCommit /* = false */)
{
	// Check if we're in the middle of a transaction
	if (!isCommit && inTransaction)
	{
		return;
	}

	if (!valid)
	{
		DEBUG_MSG("Cannot write back an invalid object %s", path.c_str());

		return;
	}

	File objectFile(path, true, true, true, false);

	if (!objectFile.isValid())
	{
		DEBUG_MSG("Cannot open object %s for writing", path.c_str());

		valid = false;

		return;
	}

	objectFile.lock();

	if (!isCommit) {
		MutexLocker lock(objectMutex);
		File lockFile(lockpath, false, true, true);

		if (!writeAttributes(objectFile))
		{
			valid = false;

			return;
		}
	}
	else
	{
		if (!writeAttributes(objectFile))
		{
			valid = false;

			return;
		}
	}

	valid = true;
}

// Discard the cached attributes
void ObjectFile::discardAttributes()
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


// Returns the file name of the object
std::string ObjectFile::getFilename() const
{
	if ((path.find_last_of(OS_PATHSEP) != std::string::npos) &&
	    (path.find_last_of(OS_PATHSEP) < path.size()))
	{
		return path.substr(path.find_last_of(OS_PATHSEP) + 1);
	}
	else
	{
		return path;
	}
}

// Returns the file name of the lock
std::string ObjectFile::getLockname() const
{
	if ((lockpath.find_last_of(OS_PATHSEP) != std::string::npos) &&
	    (lockpath.find_last_of(OS_PATHSEP) < lockpath.size()))
	{
		return lockpath.substr(lockpath.find_last_of(OS_PATHSEP) + 1);
	}
	else
	{
		return lockpath;
	}
}

// Start an attribute set transaction; this method is used when - for
// example - a key is generated and all its attributes need to be
// persisted in one go.
//
// N.B.: Starting a transaction locks the object!
bool ObjectFile::startTransaction(Access)
{
	MutexLocker lock(objectMutex);

	if (inTransaction)
	{
		return false;
	}

	transactionLockFile = new File(lockpath, false, true, true);

	if (!transactionLockFile->isValid() || !transactionLockFile->lock())
	{
		delete transactionLockFile;
		transactionLockFile = NULL;

		ERROR_MSG("Failed to lock file %s for attribute transaction", lockpath.c_str());

		return false;
	}

	inTransaction = true;

	return true;
}

// Commit an attribute transaction
bool ObjectFile::commitTransaction()
{
	MutexLocker lock(objectMutex);

	if (!inTransaction)
	{
		return false;
	}

	if (transactionLockFile == NULL)
	{
		ERROR_MSG("Transaction lock file instance invalid!");

		return false;
	}

	// Special store case
	store(true);

	if (!valid)
	{
		return false;
	}

	transactionLockFile->unlock();

	delete transactionLockFile;
	transactionLockFile = NULL;
	inTransaction = false;

	return true;
}

// Abort an attribute transaction; loads back the previous version of the object from disk
bool ObjectFile::abortTransaction()
{
	{
		MutexLocker lock(objectMutex);

		if (!inTransaction)
		{
			return false;
		}

		if (transactionLockFile == NULL)
		{
			ERROR_MSG("Transaction lock file instance invalid!");

			return false;
		}

		transactionLockFile->unlock();

		delete transactionLockFile;
		transactionLockFile = NULL;
		inTransaction = false;
	}

	// Force reload from disk
	refresh(true);

	return true;
}

// Destroy the object; WARNING: pointers to the object become invalid after this call
bool ObjectFile::destroyObject()
{
	if (token == NULL)
	{
		ERROR_MSG("Cannot destroy an object that is not associated with a token");

		return false;
	}

	return token->deleteObject(this);
}

