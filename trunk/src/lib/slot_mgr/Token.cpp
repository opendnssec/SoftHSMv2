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

#include "config.h"
#include "log.h"
#include "ObjectStore.h"
#include "Token.h"
#include "OSAttribute.h"
#include "ByteString.h"
#include "SecureDataManager.h"

// Constructor
Token::Token(OSToken* token)
{
	this->token = token;
	
	ByteString soPINBlob, userPINBlob;

	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);

	sdm = new SecureDataManager(soPINBlob, userPINBlob);
}

// Destructor
Token::~Token()
{
	delete sdm;
}

// Check if the token is still valid
bool Token::isValid()
{
	return (valid && token->isValid());
}

// Create a new token
/*static*/ Token* Token::createToken(ObjectStore* objectStore, CK_UTF8CHAR_PTR soPIN, CK_ULONG pinLen, CK_UTF8CHAR_PTR label)
{
	// Generate the SO PIN blob
	ByteString soPINByteStr((const unsigned char*) soPIN, pinLen);

	SecureDataManager soPINBlobGen;

	if (!soPINBlobGen.setSOPIN(soPINByteStr))
	{
		return NULL;
	}

	// Convert the label
	ByteString labelByteStr((const unsigned char*) label, 32);

	// Create the token
	OSToken* token = objectStore->newToken(labelByteStr);

	if (token == NULL)
	{
		return NULL;
	}

	// Set the SO PIN on the token
	if (!token->setSOPIN(soPINBlobGen.getSOPINBlob()))
	{
		return NULL;
	}

	return new Token(token);
}

