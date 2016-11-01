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
 SlotManager.h

 The slot manager is a class that forms part of the PKCS #11 core. It manages
 all the slots that SoftHSM is aware of. To make it possible to add new
 tokens, SoftHSM always has one slot available that contains an uninitialised
 token. Users can choose to initialise this token to create a new token.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLOTMANAGER_H
#define _SOFTHSM_V2_SLOTMANAGER_H

#include "config.h"
#include "ByteString.h"
#include "ObjectStore.h"
#include "Slot.h"
#include <string>
#include <map>
typedef std::map<const CK_SLOT_ID, Slot*const> SlotMap;

class SlotManager
{
public:
	// Constructor
	SlotManager(ObjectStore* objectStore);

	// Destructor
	virtual ~SlotManager();

	// Get the slots
	SlotMap getSlots();

	// Get the slot list
	CK_RV getSlotList(ObjectStore* objectStore, CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);

	// Get one slot
	Slot* getSlot(CK_SLOT_ID slotID);
private:
	void insertToken(ObjectStore* objectStore, CK_SLOT_ID slotID, ObjectStoreToken* pToken);
	// The slots
	SlotMap slots;
};

#endif // !_SOFTHSM_V2_SLOTMANAGER_H

