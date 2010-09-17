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
 Slot.h

 This class represents a single PKCS #11 slot
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SessionManager.h"
#include "SlotManager.h"
#include "Token.h"
#include <stdio.h>
#include <string.h>

// Constructor
Slot::Slot(ObjectStore* objectStore, size_t slotID, OSToken* token /* = NULL */)
{
	this->objectStore = objectStore;
	this->slotID = slotID;
	
	if (token != NULL)
	{
		this->token = new Token(token);
	}
	else
	{
		this->token = new Token();
	}
}

// Destructor
Slot::~Slot()
{
	delete token;
}

// Retrieve the token in the slot
Token* Slot::getToken()
{
	return token;
}

// Initialise the token in the slot
CK_RV Slot::initToken(CK_UTF8CHAR_PTR soPIN, CK_ULONG pinLen, CK_UTF8CHAR_PTR label)
{
	return token->createToken(objectStore, soPIN, pinLen, label);
}

// Retrieve slot information for the slot
CK_RV Slot::getSlotInfo(CK_SLOT_INFO_PTR info)
{
	if (info == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	char description[65];
	char mfgID[33];

	snprintf(description, 65, "SoftHSM slot %d", (int) slotID);
	snprintf(mfgID, 33, "SoftHSM project");

	memset(info->slotDescription, ' ', 64);
	memset(info->manufacturerID, ' ', 32);
	strncpy((char*) info->slotDescription, description, strlen(description));
	strncpy((char*) info->manufacturerID, mfgID, strlen(mfgID));

	info->flags = CKF_TOKEN_PRESENT;

	info->hardwareVersion.major = VERSION_MAJOR;
	info->hardwareVersion.minor = VERSION_MINOR;
	info->firmwareVersion.major = VERSION_MAJOR;
	info->firmwareVersion.minor = VERSION_MINOR;

	return CKR_OK;
}

// Get the slot ID
size_t Slot::getSlotID()
{
	return slotID;
}

// Is a token present?
bool Slot::isTokenPresent()
{
	return true;
}
