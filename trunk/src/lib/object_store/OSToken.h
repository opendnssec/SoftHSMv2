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
 OSToken.h

 The token class; a token is stored in a directory containing several files.
 Each object is stored in a separate file and a token object is present that
 has the token specific attributes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSTOKEN_H
#define _SOFTHSM_V2_OSTOKEN_H

#include "config.h"
#include "OSAttribute.h"
#include "ObjectFile.h"
#include "Directory.h"
#include "UUID.h"
#include "IPCSignal.h"
#include "MutexFactory.h"
#include "cryptoki.h"
#include <string>
#include <set>
#include <map>
#include <list>

class OSToken
{
public:
	// Constructor
	OSToken(const std::string tokenPath);

	// Create a new token
	static OSToken* createToken(const std::string basePath, const std::string tokenDir, const ByteString& label, const ByteString& serial);

	// Constructor for new tokens
	OSToken(const std::string tokenPath, const ByteString& label, const ByteString& serialNumber);

	// Set the SO PIN
	bool setSOPIN(const ByteString& soPINBlob);

	// Get the SO PIN
	bool getSOPIN(ByteString& soPINBlob);

	// Set the user PIN
	bool setUserPIN(ByteString userPINBlob);

	// Get the user PIN
	bool getUserPIN(ByteString& userPINBlob);

	// Get the token flags
	bool getTokenFlags(CK_ULONG& flags);

	// Set the token flags
	bool setTokenFlags(const CK_ULONG flags);

	// Retrieve objects
	std::set<ObjectFile*> getObjects();

	// Destructor
	virtual ~OSToken();

	// Checks if the token is consistent
	bool isValid();

private:
	// ObjectFile instances can call the index() function
	friend class ObjectFile;

	// Index the token
	bool index(bool isFirstTime = false);

	// Is the token consistent and valid?
	bool valid;

	// The token path
	std::string tokenPath;

	// The current objects of the token
	std::set<ObjectFile*> objects;

	// All the objects ever associated with this token
	//
	// This set is kept to be able to clean up when the token
	// instance is discarded; in case the contents of a token
	// change, some objects may disappear but we cannot simply
	// delete them since they may still be referenced from an
	// object outside of this class.
	std::set<ObjectFile*> allObjects;

	// The current list of files
	std::set<std::string> currentFiles;

	// The token object
	ObjectFile* tokenObject;

	// Inter-process synchronisation
	IPCSignal* sync;

	// The directory object for this token
	Directory* tokenDir;

	// For thread safeness
	Mutex* tokenMutex;
};

#endif // !_SOFTHSM_V2_OSTOKEN_H

