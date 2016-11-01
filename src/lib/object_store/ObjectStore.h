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

#ifndef _SOFTHSM_V2_OBJECTSTORE_H
#define _SOFTHSM_V2_OBJECTSTORE_H

#include "config.h"
#include "ByteString.h"
#include "ObjectStoreToken.h"
#include "MutexFactory.h"
#include <string>
#include <vector>

class ObjectStore
{
public:
	// Constructor
	ObjectStore(std::string inStorePath);

	// Destructor
	virtual ~ObjectStore();

	// Return the number of tokens that is present
	size_t getTokenCount();

	// Return a pointer to the n-th token (counting starts at 0)
	ObjectStoreToken* getToken(size_t whichToken);

	// Create a new token
	ObjectStoreToken* newToken(const ByteString& label);

	// Destroy a token
	bool destroyToken(ObjectStoreToken* token);

	// Check if the object store is valid
	bool isValid();

private:
	// The tokens
	std::vector<ObjectStoreToken*> tokens;

	// All tokens
	std::vector<ObjectStoreToken*> allTokens;

	// The object store root directory
	std::string storePath;

	// The status
	bool valid;

	// Object store synchronisation
	Mutex* storeMutex;
};

#endif // !_SOFTHSM_V2_OBJECTSTORE_H

