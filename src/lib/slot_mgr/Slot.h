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

#ifndef _SOFTHSM_V2_SLOT_H
#define _SOFTHSM_V2_SLOT_H

#include "config.h"
#include "ByteString.h"
#include "ObjectStore.h"
#include "ObjectStoreToken.h"
#include "Token.h"
#include "cryptoki.h"
#include <string>
#include <vector>

class Slot
{
public:
	// Constructor
	Slot(ObjectStore* inObjectStore, CK_SLOT_ID inSlotID, ObjectStoreToken *inToken = NULL);

	// Destructor
	virtual ~Slot();

	// Retrieve the token in the slot
	Token* getToken();

	// Initialise the token in the slot
	CK_RV initToken(ByteString& pin, CK_UTF8CHAR_PTR label);

	// Retrieve slot information for the slot
	CK_RV getSlotInfo(CK_SLOT_INFO_PTR info);

	// Get the slot ID
	CK_SLOT_ID getSlotID();

	// Is a token present?
	bool isTokenPresent();

private:
	// A reference to the object store
	ObjectStore* objectStore;

	// The token in the slot
	Token* token;

	// The slot ID
	CK_SLOT_ID slotID;
};

#endif // !_SOFTHSM_V2_SLOT_H

