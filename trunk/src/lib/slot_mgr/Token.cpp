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

#include <sys/time.h>

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

// Retrieve token information for the token
CK_RV Token::getTokenInfo(CK_TOKEN_INFO_PTR info)
{
	if (info == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	// Token specific information

	if (!token->getTokenFlags(info->flags))
	{
		DEBUG_MSG("Could not get the token flags");
		return CKR_GENERAL_ERROR;
	}

	ByteString label, serial;

	memset(info->label, ' ', 32);
	memset(info->serialNumber, ' ', 16);

	if (token->getTokenLabel(label))
	{
		strncpy((char*) info->label, (char*) label.byte_str(), label.size());
	}

	if (token->getTokenLabel(serial))
	{
		strncpy((char*) info->serialNumber, (char*) serial.byte_str(), serial.size());
	}

	// Some more text about the token

	char mfgID[33];
	char model[17];

	snprintf(mfgID, 33, "SoftHSM project");
	snprintf(model, 17, "SoftHSM v2");

	memset(info->manufacturerID, ' ', 32);
	memset(info->model, ' ', 16);
	strncpy((char*) info->manufacturerID, mfgID, strlen(mfgID));
	strncpy((char*) info->model, model, strlen(model));

	// Information shared by all tokens

	// TODO: Can we set these?
	info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	info->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;

	info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxPinLen = MAX_PIN_LEN;
	info->ulMinPinLen = MIN_PIN_LEN;
	info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->hardwareVersion.major = VERSION_MAJOR;
	info->hardwareVersion.minor = VERSION_MINOR;
	info->firmwareVersion.major = VERSION_MAJOR;
	info->firmwareVersion.minor = VERSION_MINOR;

	// Current time
	time_t rawtime;
	time(&rawtime);
	char dateTime[17];
	strftime(dateTime, 17, "%Y%m%d%H%M%S00", gmtime(&rawtime));
	memcpy(info->utcTime, dateTime, 16);

        return CKR_OK;
}
