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
 ObjectStore.h

 The object store manages the separate tokens that the SoftHSM supports. Each
 token is organised as a directory containing files that are contain the
 token's objects. The object store is initialised with a root directory from
 which it enumerates the tokens.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "ObjectStore.h"
#include "Directory.h"
#include "ObjectStoreToken.h"
#include "OSPathSep.h"
#include "UUID.h"
#include <stdio.h>

// Constructor
ObjectStore::ObjectStore(std::string inStorePath)
{
	storePath = inStorePath;
	valid = false;
	storeMutex = MutexFactory::i()->getMutex();

	MutexLocker lock(storeMutex);

	// Find all tokens in the specified path
	Directory storeDir(storePath);

	if (!storeDir.isValid())
	{
		WARNING_MSG("Failed to enumerate object store in %s", storePath.c_str());

		return;
	}

	// Assume that all subdirectories are tokens
	std::vector<std::string> dirs = storeDir.getSubDirs();

	for (std::vector<std::string>::iterator i = dirs.begin(); i != dirs.end(); i++)
	{
		// Create a token instance
		ObjectStoreToken* token = ObjectStoreToken::accessToken(storePath, *i);

		if (!token->isValid())
		{
			ERROR_MSG("Failed to open token %s", i->c_str());

			delete token;

			// Silently ignore tokens that we do not have access to
			continue;
		}

		tokens.push_back(token);
		allTokens.push_back(token);
	}

	valid = true;
}

// Destructor
ObjectStore::~ObjectStore()
{
	{
		MutexLocker lock(storeMutex);

		// Clean up
		tokens.clear();

		for (std::vector<ObjectStoreToken*>::iterator i = allTokens.begin(); i != allTokens.end(); i++)
		{
			delete *i;
		}
	}

	MutexFactory::i()->recycleMutex(storeMutex);
}

// Check if the object store is valid
bool ObjectStore::isValid()
{
	return valid;
}

// Return the number of tokens that is present
size_t ObjectStore::getTokenCount()
{
	MutexLocker lock(storeMutex);

	return tokens.size();
}

// Return a pointer to the n-th token (counting starts at 0)
ObjectStoreToken* ObjectStore::getToken(size_t whichToken)
{
	MutexLocker lock(storeMutex);

	if (whichToken >= tokens.size())
	{
		return NULL;
	}

	return tokens[whichToken];
}

// Create a new token
ObjectStoreToken* ObjectStore::newToken(const ByteString& label)
{
	MutexLocker lock(storeMutex);

	// Generate a UUID for the token
	std::string tokenUUID = UUID::newUUID();

	// Convert the UUID to a serial number
	std::string serialNumber = tokenUUID.substr(19, 4) + tokenUUID.substr(24);
	ByteString serial((const unsigned char*) serialNumber.c_str(), serialNumber.size());

	// Create the token
	ObjectStoreToken* newToken = ObjectStoreToken::createToken(storePath, tokenUUID, label, serial);

	if (newToken != NULL)
	{
		tokens.push_back(newToken);
		allTokens.push_back(newToken);
	}

	return newToken;
}

// Destroy a token
bool ObjectStore::destroyToken(ObjectStoreToken *token)
{
	MutexLocker lock(storeMutex);

	// Find the token
	for (std::vector<ObjectStoreToken*>::iterator i = tokens.begin(); i != tokens.end(); i++)
	{
		if (*i == token)
		{
			// Found the token, now destroy the token
			if (!token->clearToken())
			{
				ERROR_MSG("Failed to clear token instance");

				return false;
			}

			// And remove it from the vector
			tokens.erase(i);

			return true;
		}
	}

	ERROR_MSG("Could not find the token instance to destroy");

	return false;
}

