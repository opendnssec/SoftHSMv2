/* $Id$ */

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

// Initialise the one-and-only instance
std::auto_ptr<SessionManager> SessionManager::instance(NULL);

// Return the one-and-only instance
SessionManager* SessionManager::i()
{
	if (instance.get() == NULL)
	{
		instance = std::auto_ptr<SessionManager>(new SessionManager());
	}

	return instance.get();
}

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
	Slot *slot,
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
	Token *token = slot->getToken();
	if (token == NULL) return CKR_TOKEN_NOT_PRESENT;
	if (!token->isInitialized()) return CKR_TOKEN_NOT_RECOGNIZED;

	// Can not open a Read-Only session when in SO mode
	if ((flags & CKF_RW_SESSION) == 0 && token->isSOLoggedIn()) return CKR_SESSION_READ_WRITE_SO_EXISTS;

	// TODO: Do we want to check for maximum number of sessions?
	// return CKR_SESSION_COUNT

	// Create the session
	bool rwSession = ((flags & CKF_RW_SESSION) == CKF_RW_SESSION) ? true : false;
	Session *session = new Session(slot, rwSession, pApplication, notify);

	// First fill any empty spot in the list
	for (int i = 0; i < sessions.size(); i++)
	{
		if (sessions[i] != NULL)
		{
			continue;
		}

		sessions[i] = session;
		*phSession = i + 1;

		return CKR_OK;
	}

	// Or add it to the end
	sessions.push_back(session);
	*phSession = sessions.size();

	return CKR_OK;
}

// Close a session
CK_RV SessionManager::closeSession(CK_SESSION_HANDLE hSession)
{
	if (hSession == CK_INVALID_HANDLE) return CKR_SESSION_HANDLE_INVALID;

	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	// Check if we are out of range
	if (sessions.size() <= hSession) return CKR_SESSION_HANDLE_INVALID;

	// Check if it is a closed session
	if (sessions[hSession-1] == NULL) return CKR_SESSION_HANDLE_INVALID;

	// TODO: Logout if this is the last session on the token
	// TODO: Remove session objects

	// Close the session
	delete sessions[hSession-1];
	sessions[hSession-1] = NULL;

	return CKR_OK;
}

// Close all sessions
CK_RV SessionManager::closeAllSessions(Slot *slot)
{
	if (slot == NULL) return CKR_SLOT_ID_INVALID;

	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	// TODO: Close all sessions on this slot
	// TODO: Remove session objects
	// TODO: Logout from the token

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Get session info
CK_RV SessionManager::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	// Get the session
	Session *session = getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return session->getSessionInfo(pInfo);
}

// Get the session
Session* SessionManager::getSession(CK_SESSION_HANDLE hSession)
{
	// Lock access to the vector
	MutexLocker lock(sessionsMutex);

	// We do not want to get a negative number below
	if (hSession == CK_INVALID_HANDLE) return NULL;

	// Check if we are out of range
	if (sessions.size() <= hSession) return NULL;

	return sessions[hSession - 1];
}
