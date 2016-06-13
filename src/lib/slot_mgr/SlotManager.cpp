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
#include <cassert>
#include <stdexcept>
typedef std::pair<CK_SLOT_ID, Slot*> SlotMapElement;
typedef std::pair<SlotMap::iterator, bool> InsertResult;

// Constructor
SlotManager::SlotManager(ObjectStore*const objectStore)
{
	// Add a slot for each token that already exists
	for (size_t i = 0; i < objectStore->getTokenCount(); i++)
	{
		ObjectStoreToken*const pToken(objectStore->getToken(i));
		ByteString bs;
		pToken->getTokenSerial(bs);
		const std::string s((const char*)bs.const_byte_str(), bs.size());

		// parse serial string that is expected to have only hex digits.
		CK_SLOT_ID l;
		if (s.size() < 8)
		{
			l = strtoul(s.c_str(), NULL, 16);
		}
		else
		{
			l = strtoul(s.substr(s.size() - 8).c_str(), NULL, 16);
		}

		// mask for 31 bits.
		// this since sunpkcs11 java wrapper is parsing the slot ID to a java int that needs to be positive.
		// java int is 32 bit and the the sign bit is removed.
		const CK_SLOT_ID mask( ((CK_SLOT_ID)1<<31)-1 );
		const CK_SLOT_ID slotID(mask&l);

		insertToken(objectStore, slotID, pToken);
	}

	// Add an empty slot
	insertToken(objectStore, objectStore->getTokenCount(), NULL);
}

void SlotManager::insertToken(ObjectStore*const objectStore, const CK_SLOT_ID slotID, ObjectStoreToken*const pToken) {
	Slot*const newSlot( new Slot(objectStore, slotID, pToken) );
	const InsertResult result( slots.insert(SlotMapElement(slotID, newSlot)) );
	assert(result.second);// fails if there is already a token on this slot
}

// Destructor
SlotManager::~SlotManager()
{
	SlotMap toDelete = slots;
	slots.clear();

	for (SlotMap::iterator i = toDelete.begin(); i != toDelete.end(); i++)
	{
		delete i->second;
	}
}

// Get the slot list
CK_RV SlotManager::getSlotList(ObjectStore* objectStore, CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	size_t size( 0 );

	if (pulCount == NULL) return CKR_ARGUMENTS_BAD;

	// Calculate the size of the list
	bool uninitialized = false;
	for (SlotMap::iterator i = slots.begin(); i != slots.end(); i++)
	{
		if ((tokenPresent == CK_FALSE) || i->second->isTokenPresent())
		{
			size++;
		}

		if (i->second->getToken() != NULL && i->second->getToken()->isInitialized() == false)
		{
			uninitialized = true;
		}
	}

	// The user wants the size of the list
	if (pSlotList == NULL)
	{
		// Always have an uninitialized token
		if (uninitialized == false)
		{
			insertToken(objectStore, objectStore->getTokenCount(), NULL);
			size++;
		}

		*pulCount = size;

		return CKR_OK;
	}

	// Is the given buffer too small?
	if (*pulCount < size)
	{
		*pulCount = size;

		return CKR_BUFFER_TOO_SMALL;
	}

	size_t startIx( 0 );
	size_t endIx( size-1 );

	for (SlotMap::iterator i = slots.begin(); i != slots.end(); i++)
	{
		if ((tokenPresent == CK_TRUE) && !i->second->isTokenPresent())
		{// only show token if present on slot. But this slot has no token so we continue
			continue;
		}
		// put uninitialized last. After all initialized or slots without tokens.
		if ( i->second->isTokenPresent() && !i->second->getToken()->isInitialized() ) {
			pSlotList[endIx--] =  i->second->getSlotID();
		} else {
			pSlotList[startIx++] = i->second->getSlotID();
		}
	}
	assert(startIx==endIx+1);
	*pulCount = size;

	return CKR_OK;
}

// Get the slots
SlotMap SlotManager::getSlots()
{
	return slots;
}

// Get one slot
Slot* SlotManager::getSlot(CK_SLOT_ID slotID)
{
	try {
		return slots.at(slotID);
	} catch( const std::out_of_range &oor) {
		DEBUG_MSG("slotID is out of range: %s", oor.what());
		return NULL_PTR;
	}
}
