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
 OSToken.cpp

 The token class; a token is stored in a directory containing several files.
 Each object is stored in a separate file and a token object is present that
 has the token specific attributes
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSAttributes.h"
#include "OSAttribute.h"
#include "ObjectFile.h"
#include "Directory.h"
#include "UUID.h"
#include "IPCSignal.h"
#include "cryptoki.h"
#include "OSToken.h"
#include "OSPathSep.h"
#include <vector>
#include <string>
#include <set>
#include <map>
#include <list>
#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <direct.h>
#define rmdir _rmdir
#endif

// Constructor
OSToken::OSToken(const std::string tokenPath)
{
	tokenDir = new Directory(tokenPath);
	tokenObject = new ObjectFile(this, tokenPath + OS_PATHSEP + "token.object", tokenPath + OS_PATHSEP + "token.lock");
	sync = IPCSignal::create(tokenPath);
	tokenMutex = MutexFactory::i()->getMutex();
	this->tokenPath = tokenPath;
	valid = (sync != NULL) && (tokenMutex != NULL) && tokenDir->isValid() && tokenObject->isValid();

	DEBUG_MSG("Opened token %s", tokenPath.c_str());

	index(true);
}

// Create a new token
/*static*/ OSToken* OSToken::createToken(const std::string basePath, const std::string tokenDir, const ByteString& label, const ByteString& serial)
{
	Directory baseDir(basePath);

	if (!baseDir.isValid())
	{
		return NULL;
	}

	// Create the token directory
	if (!baseDir.mkdir(tokenDir))
	{
		return NULL;
	}

	// Create the token object
	ObjectFile tokenObject(NULL, basePath + OS_PATHSEP + tokenDir + OS_PATHSEP + "token.object", basePath + OS_PATHSEP + tokenDir + OS_PATHSEP + "token.lock", true);

	if (!tokenObject.isValid())
	{
		baseDir.remove(tokenDir);

		return NULL;
	}

	// Set the initial attributes
	CK_ULONG flags = 
		CKF_RNG |
		CKF_LOGIN_REQUIRED | // FIXME: check
		CKF_RESTORE_KEY_NOT_NEEDED |
		CKF_TOKEN_INITIALIZED |
		CKF_SO_PIN_LOCKED |
		CKF_SO_PIN_TO_BE_CHANGED;

	OSAttribute tokenLabel(label);
	OSAttribute tokenSerial(serial);
	OSAttribute tokenFlags(flags);

	if (!tokenObject.setAttribute(CKA_OS_TOKENLABEL, tokenLabel) ||
	    !tokenObject.setAttribute(CKA_OS_TOKENSERIAL, tokenSerial) ||
	    !tokenObject.setAttribute(CKA_OS_TOKENFLAGS, tokenFlags))
	{
		baseDir.remove(tokenDir + OS_PATHSEP + "token.object");
		baseDir.remove(tokenDir + OS_PATHSEP + "token.lock");
		baseDir.remove(tokenDir);

		return NULL;
	}

	DEBUG_MSG("Created new token %s", tokenDir.c_str());

	return new OSToken(basePath + OS_PATHSEP + tokenDir);
}

// Destructor
OSToken::~OSToken()
{
	// Clean up
	std::set<ObjectFile*> cleanUp = allObjects;
	allObjects.clear();

	for (std::set<ObjectFile*>::iterator i = cleanUp.begin(); i != cleanUp.end(); i++)
	{
		delete *i;
	}

	delete tokenDir;
	if (sync != NULL) delete sync;
	MutexFactory::i()->recycleMutex(tokenMutex);
	delete tokenObject;
}

// Set the SO PIN
bool OSToken::setSOPIN(const ByteString& soPINBlob)
{
	if (!valid) return false;

	OSAttribute soPIN(soPINBlob);

	CK_ULONG flags;

	if (tokenObject->setAttribute(CKA_OS_SOPIN, soPIN) &&
	    getTokenFlags(flags))
	{
		flags &= ~CKF_SO_PIN_COUNT_LOW;
		flags &= ~CKF_SO_PIN_FINAL_TRY;
		flags &= ~CKF_SO_PIN_LOCKED;
		flags &= ~CKF_SO_PIN_TO_BE_CHANGED;

		return setTokenFlags(flags);
	}

	return false;
}

// Get the SO PIN
bool OSToken::getSOPIN(ByteString& soPINBlob)
{
	if (!valid || !tokenObject->isValid())
	{
		return false;
	}

	OSAttribute* soPIN = tokenObject->getAttribute(CKA_OS_SOPIN);

	if (soPIN != NULL)
	{
		soPINBlob = soPIN->getByteStringValue();

		return true;
	}
	else
	{
		return false;
	}
}

// Set the user PIN
bool OSToken::setUserPIN(ByteString userPINBlob)
{
	if (!valid) return false;

	OSAttribute userPIN(userPINBlob);

	CK_ULONG flags;

	if (tokenObject->setAttribute(CKA_OS_USERPIN, userPIN) &&
	    getTokenFlags(flags))
	{
		flags |= CKF_USER_PIN_INITIALIZED;
		flags &= ~CKF_USER_PIN_COUNT_LOW;
		flags &= ~CKF_USER_PIN_FINAL_TRY;
		flags &= ~CKF_USER_PIN_LOCKED;
		flags &= ~CKF_USER_PIN_TO_BE_CHANGED;

		return setTokenFlags(flags);
	}

	return false;
}

// Get the user PIN
bool OSToken::getUserPIN(ByteString& userPINBlob)
{
	if (!valid || !tokenObject->isValid())
	{
		return false;
	}

	OSAttribute* userPIN = tokenObject->getAttribute(CKA_OS_USERPIN);

	if (userPIN != NULL)
	{
		userPINBlob = userPIN->getByteStringValue();

		return true;
	}
	else
	{
		return false;
	}
}

// Retrieve the token label
bool OSToken::getTokenLabel(ByteString& label)
{
	if (!valid || !tokenObject->isValid())
	{
		return false;
	}

	OSAttribute* tokenLabel = tokenObject->getAttribute(CKA_OS_TOKENLABEL);

	if (tokenLabel != NULL)
	{
		label = tokenLabel->getByteStringValue();

		return true;
	}
	else
	{
		return false;
	}
}

// Retrieve the token serial
bool OSToken::getTokenSerial(ByteString& serial)
{
	if (!valid || !tokenObject->isValid())
	{
		return false;
	}

	OSAttribute* tokenSerial = tokenObject->getAttribute(CKA_OS_TOKENSERIAL);

	if (tokenSerial != NULL)
	{
		serial = tokenSerial->getByteStringValue();

		return true;
	}
	else
	{
		return false;
	}
}

// Get the token flags
bool OSToken::getTokenFlags(CK_ULONG& flags)
{
	if (!valid || !tokenObject->isValid())
	{
		return false;
	}

	OSAttribute* tokenFlags = tokenObject->getAttribute(CKA_OS_TOKENFLAGS);

	if (tokenFlags != NULL)
	{
		flags = tokenFlags->getUnsignedLongValue();

		// Check if the user PIN is initialised
		if (tokenObject->attributeExists(CKA_OS_USERPIN))
		{
			flags |= CKF_USER_PIN_INITIALIZED;
		}

		return true;
	}
	else
	{
		return false;
	}
}

// Set the token flags
bool OSToken::setTokenFlags(const CK_ULONG flags)
{
	if (!valid) return false;

	OSAttribute tokenFlags(flags);

	return tokenObject->setAttribute(CKA_OS_TOKENFLAGS, tokenFlags);
}

// Retrieve objects
std::set<ObjectFile*> OSToken::getObjects()
{
	index();

	// Make sure that no other thread is in the process of changing
	// the object list when we return it
	MutexLocker lock(tokenMutex);

    return objects;
}

void OSToken::getObjects(std::set<OSObject*> &objects)
{
    index();

    // Make sure that no other thread is in the process of changing
    // the object list when we return it
    MutexLocker lock(tokenMutex);

    objects.insert(this->objects.begin(),this->objects.end());
}

// Create a new object
ObjectFile* OSToken::createObject()
{
	if (!valid) return NULL;

	// Generate a name for the object
	std::string objectUUID = UUID::newUUID();
	std::string objectPath = tokenPath + OS_PATHSEP + objectUUID + ".object";
	std::string lockPath = tokenPath + OS_PATHSEP + objectUUID + ".lock";

	// Create the new object file
	ObjectFile* newObject = new ObjectFile(this, objectPath, lockPath, true);

	if (!newObject->isValid())
	{
		ERROR_MSG("Failed to create new object %s", objectPath.c_str());

		delete newObject;

		return NULL;
	}

	// Now add it to the set of objects
	MutexLocker lock(tokenMutex);

	objects.insert(newObject);
	allObjects.insert(newObject);
	currentFiles.insert(newObject->getFilename());

	DEBUG_MSG("(0x%08X) Created new object %s (0x%08X)", this, objectPath.c_str(), newObject);

	sync->trigger();

	return newObject;
}

// Delete an object
bool OSToken::deleteObject(ObjectFile* object)
{
	if (!valid) return false;

	if (objects.find(object) == objects.end())
	{
		ERROR_MSG("Cannot delete non-existent object 0x%08X", object);

		return false;
	}

	MutexLocker lock(tokenMutex);

	// Invalidate the object instance
	object->invalidate();

	// Retrieve the filename of the object
	std::string objectFilename = object->getFilename();

	// Attempt to delete the file
	if (!tokenDir->remove(objectFilename))
	{
		ERROR_MSG("Failed to delete object file %s", objectFilename.c_str());

		return false;
	}

	// Retrieve the filename of the lock
	std::string lockFilename = object->getLockname();

	// Attempt to delete the lock
	if (!tokenDir->remove(lockFilename))
	{
		ERROR_MSG("Failed to delete lock file %s", lockFilename.c_str());

		return false;
	}

	objects.erase(object);

	DEBUG_MSG("Deleted object %s", objectFilename.c_str());

	sync->trigger();

	return true;
}

// Checks if the token is consistent
bool OSToken::isValid()
{
	return valid;
}

// Invalidate the token (for instance if it is deleted)
void OSToken::invalidate()
{
	valid = false;
}

// Delete the token
bool OSToken::clearToken()
{
	MutexLocker lock(tokenMutex);

	// Invalidate the token
	invalidate();

	// First, clear out all objects
	objects.clear();
	
	// Now, delete all files in the token directory
	if (!tokenDir->refresh())
	{
		return false;
	}

	std::vector<std::string> tokenFiles = tokenDir->getFiles();

	for (std::vector<std::string>::iterator i = tokenFiles.begin(); i != tokenFiles.end(); i++)
	{
		if (!tokenDir->remove(*i))
		{
			ERROR_MSG("Failed to remove %s from token directory %s", i->c_str(), tokenPath.c_str());

			return false;
		}
	}

	// Now remove the token directory
	if (rmdir(tokenPath.c_str()))
	{
		ERROR_MSG("Failed to remove the token directory %s", tokenPath.c_str());

		return false;
	}

	DEBUG_MSG("Token instance %s was succesfully cleared", tokenPath.c_str());

	return true;
}

// Index the token
bool OSToken::index(bool isFirstTime /* = false */)
{
	// Check if re-indexing is required
	if (!isFirstTime && (!valid || !sync->wasTriggered()))
	{
		return true;
	}

	// Check the integrity
	if (!tokenDir->refresh() || !tokenObject->isValid())
	{
		valid = false;

		return false;
	}

	DEBUG_MSG("Token %s has changed", tokenPath.c_str());

	// Retrieve the directory listing
	std::vector<std::string> tokenFiles = tokenDir->getFiles();

	// Filter out the objects
	std::set<std::string> newSet;

	for (std::vector<std::string>::iterator i = tokenFiles.begin(); i != tokenFiles.end(); i++)
	{
		if ((i->size() > 7) &&
		    (!(i->substr(i->size() - 7).compare(".object"))) &&
		    (i->compare("token.object")))
		{
			newSet.insert(*i);
		}
		else
		{
			DEBUG_MSG("Ignored file %s", i->c_str());
		}
	}

	// Compute the changes compared to the last list of files
	std::set<std::string> addedFiles;
	std::set<std::string> removedFiles;

	if (!isFirstTime)
	{
		// First compute which files were added
		for (std::set<std::string>::iterator i = newSet.begin(); i != newSet.end(); i++)
		{
			if (currentFiles.find(*i) == currentFiles.end())
			{
				addedFiles.insert(*i);
			}
		}

		// Now compute which files were removed
		for (std::set<std::string>::iterator i = currentFiles.begin(); i != currentFiles.end(); i++)
		{
			if (newSet.find(*i) == newSet.end())
			{
				removedFiles.insert(*i);
			}
		}
	}
	else
	{
		addedFiles = newSet;
	}

	currentFiles = newSet;

	DEBUG_MSG("%d objects were added and %d objects were removed", addedFiles.size(), removedFiles.size());
	DEBUG_MSG("Current directory set contains %d objects", currentFiles.size());

	// Now update the set of objects
	MutexLocker lock(tokenMutex);

	// Add new objects
	for (std::set<std::string>::iterator i = addedFiles.begin(); i != addedFiles.end(); i++)
	{
		if ((i->find_last_of('.') == std::string::npos) ||
		    (i->substr(i->find_last_of('.')) != ".object"))
		{
			continue;
		}

		std::string lockName(*i);
		lockName.replace(lockName.find_last_of('.'), std::string::npos, ".lock");

		// Create a new token object for the added file
		ObjectFile* newObject = new ObjectFile(this, tokenPath + OS_PATHSEP + *i, tokenPath + OS_PATHSEP + lockName);

		DEBUG_MSG("(0x%08X) New object %s (0x%08X) added", this, newObject->getFilename().c_str(), newObject);

		objects.insert(newObject);
		allObjects.insert(newObject);
	}

	// Remove deleted objects
	std::set<ObjectFile*> newObjects;

	for (std::set<ObjectFile*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		DEBUG_MSG("Processing %s (0x%08X)", (*i)->getFilename().c_str(), *i);

		if (removedFiles.find((*i)->getFilename()) == removedFiles.end())
		{
			DEBUG_MSG("Adding object %s", (*i)->getFilename().c_str());
			// This object gets to stay in the set
			newObjects.insert(*i);
		}
		else
		{
			(*i)->invalidate();
		}
	}

	// Set the new objects
	objects = newObjects;

	DEBUG_MSG("The token now contains %d objects", objects.size());

	return true;
}

