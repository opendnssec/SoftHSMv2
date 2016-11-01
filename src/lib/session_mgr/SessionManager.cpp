/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 SessionManager.cpp

 Keeps track of the sessions within SoftHSM. The sessions are stored in a 
 vector. When a session is closed, its spot in the vector will be replaced
 with NULL. Because we want to keep track of the session ID which is 
 equal to its location in the vector. New sessions will first fill up the NULL
 locations and if there is no empty spots, then they are added to the end.
 *****************************************************************************/

#include "SessionManager.h"
#include "log.h"

// Constructor
SessionManager::SessionManager()
{
	sessionsMutex = MutexFactory::i()->getMutex();
}

// Destructor
SessionManager::~SessionManager()
{
	std::vector<Session*> toDelete = sessions;
	sessions.clear();

	for (std::vector<Session*>::iterator i = toDelete.begin(); i != toDelete.end(); i++)
	{
		if (*i != NULL) delete *i;
	}

	MutexFactory::i()->recycleMutex(sessionsMutex);
}

// Open a new session
CK_RV SessionManager::openSession
(
	Slot* slot,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY notify,
	CK_SESSION_HANDLE_PTR phSession
)
{
	if (phSession == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (slot == NULL) return CKR_SLOT_ID_INVALID;
	if ((flags & CKF_SERIAL_SESSION) == 0) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	// Get the token
	Token* token = slot->getToken();
	if (token == NULL) return CKR_TOKEN_NOT_PRESENT;
	if (!token->isInitialized()) return CKR_TOKEN_NOT_RECOGNIZED;

	// Can not open a Read-Only session when in SO mode
	if ((flags & CKF_RW_SESSION) == 0 && token->isSOLoggedIn()) return CKR_SESSION_READ_WRITE_SO_EXISTS;

	// TODO: Do we want to check for maximum number of sessions?
	// return CKR_SESSION_COUNT

	// Create the session
	bool rwSession = ((flags & CKF_RW_SESSION) == CKF_RW_SESSION) ? true : false;
	Session* session = new Session(slot, rwSession, pApplication, notify);

	// First fill any empty spot in the list
	for (size_t i = 0; i < sessions.size(); i++)
	{
		if (sessions[i] != NULL)
		{
			continue;
		}

		sessions[i] = session;
		session->setHandle(i + 1);
		*phSession = session->getHandle();

		return CKR_OK;
	}

	// Or add it to the end
	sessions.push_back(session);
	session->setHandle(sessions.size());
	*phSession = session->getHandle();

	return CKR_OK;
}

// Close a session
CK_RV SessionManager::closeSession(CK_SESSION_HANDLE hSession)
{
	if (hSession == CK_INVALID_HANDLE) return CKR_SESSION_HANDLE_INVALID;

	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	// Check if we are out of range
	if (hSession > sessions.size()) return CKR_SESSION_HANDLE_INVALID;

	// Check if it is a closed session
	unsigned long sessionID = hSession - 1;
	if (sessions[sessionID] == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if this is the last session on the token
	bool lastSession = true;
	const CK_SLOT_ID slotID( sessions[sessionID]->getSlot()->getSlotID() );
	for (size_t i = 0; i < sessions.size(); i++)
	{
		if (sessions[i] == NULL) continue;

		if (sessions[i]->getSlot()->getSlotID() == slotID && i != sessionID)
		{
			lastSession = false;
			break;
		}
	}

	// Logout if this is the last session on the token
	if (lastSession)
	{
		sessions[sessionID]->getSlot()->getToken()->logout();
	}

	// Close the session
	delete sessions[sessionID];
	sessions[sessionID] = NULL;

	return CKR_OK;
}

// Close all sessions
CK_RV SessionManager::closeAllSessions(Slot* slot)
{
	if (slot == NULL) return CKR_SLOT_ID_INVALID;

	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	// Get the token
	Token* token = slot->getToken();
	if (token == NULL) return CKR_TOKEN_NOT_PRESENT;

	// Close all sessions on this slot
	const CK_SLOT_ID slotID( slot->getSlotID() );
	for (std::vector<Session*>::iterator i = sessions.begin(); i != sessions.end(); i++)
	{
		if (*i == NULL) continue;

		if ((*i)->getSlot()->getSlotID() == slotID)
		{
			delete *i;
			*i = NULL;
		}
	}

	// Logout from the token
	token->logout();

	return CKR_OK;
}

// Get session info
CK_RV SessionManager::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	// Get the session
	Session* session = getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return session->getInfo(pInfo);
}

// Get the session
Session* SessionManager::getSession(CK_SESSION_HANDLE hSession)
{
	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	// We do not want to get a negative number below
	if (hSession == CK_INVALID_HANDLE) return NULL;

	// Check if we are out of range
	if (hSession > sessions.size()) return NULL;

	return sessions[hSession - 1];
}

bool SessionManager::haveSession(CK_SLOT_ID slotID)
{
	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	for (std::vector<Session*>::iterator i = sessions.begin(); i != sessions.end(); i++)
	{
		if (*i == NULL) continue;

		if ((*i)->getSlot()->getSlotID() == slotID)
		{
			return true;
		}
	}

	return false;
}

bool SessionManager::haveROSession(CK_SLOT_ID slotID)
{
	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	for (std::vector<Session*>::iterator i = sessions.begin(); i != sessions.end(); i++)
	{
		if (*i == NULL) continue;

		if ((*i)->getSlot()->getSlotID() != slotID) continue;

		if ((*i)->isRW() == false) return true;
	}

	return false;
}
