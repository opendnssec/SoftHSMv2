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
 SlotManager.cpp

 The slot manager is a class that forms part of the PKCS #11 core. It manages
 all the slots that SoftHSM is aware of. To make it possible to add new
 tokens, SoftHSM always has one slot available that contains an uninitialised
 token. Users can choose to initialise this token to create a new token.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SlotManager.h"

// Constructor
SlotManager::SlotManager(ObjectStore* objectStore)
{
	// Add a slot for each token that already exists
	for (size_t i = 0; i < objectStore->getTokenCount(); i++)
	{
		Slot* newSlot = new Slot(objectStore, i, objectStore->getToken(i));
		slots.push_back(newSlot);
	}

	// Add an empty slot
	slots.push_back(new Slot(objectStore, objectStore->getTokenCount()));
}

// Destructor
SlotManager::~SlotManager()
{
	std::vector<Slot*> toDelete = slots;
	slots.clear();

	for (std::vector<Slot*>::iterator i = toDelete.begin(); i != toDelete.end(); i++)
	{
		delete *i;
	}
}

// Get the slot list
CK_RV SlotManager::getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_ULONG size = 0;

	if (pulCount == NULL) return CKR_ARGUMENTS_BAD;

	// Calculate the size of the list
	for (std::vector<Slot*>::iterator i = slots.begin(); i != slots.end(); i++)
	{
		if (((tokenPresent == CK_FALSE) && !(*i)->isTokenPresent()) ||
		    ((tokenPresent == CK_TRUE) && (*i)->isTokenPresent()))
		{
			size++;
		}
	}

	// The user wants the size of the list
	if (pSlotList == NULL)
	{
		*pulCount = size;

		return CKR_OK;
	}

	// Is the given buffer too small?
	if (*pulCount < size)
	{
		*pulCount = size;

		return CKR_BUFFER_TOO_SMALL;
	}

	size = 0;

	for (std::vector<Slot*>::iterator i = slots.begin(); i != slots.end(); i++)
	{
		if (((tokenPresent == CK_FALSE) && !(*i)->isTokenPresent()) ||
		    ((tokenPresent == CK_TRUE) && (*i)->isTokenPresent()))
		{
			pSlotList[size++] = (CK_ULONG)(*i)->getSlotID();
		}
	}

	*pulCount = size;

	return CKR_OK;
}

// Get the slots
std::vector<Slot*> SlotManager::getSlots()
{
	return slots;
}

// Get one slot
Slot* SlotManager::getSlot(CK_SLOT_ID slotID)
{
	for (std::vector<Slot*>::iterator i = slots.begin(); i != slots.end(); i++)
	{
		if ((*i)->getSlotID() == slotID)
		{
			return *i;
		}
	}

	return NULL;
}
