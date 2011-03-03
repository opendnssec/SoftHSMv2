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
 Session.h

 This class represents a single session
 *****************************************************************************/

#include "CryptoFactory.h"
#include "Session.h"
#include "SessionObjectStore.h"

// Constructor
Session::Session(Slot *slot, bool isReadWrite, CK_VOID_PTR pApplication, CK_NOTIFY notify)
{
	this->slot = slot;
	this->token = slot->getToken();
	this->isReadWrite = isReadWrite;
	hSession = CK_INVALID_HANDLE;
	this->pApplication = pApplication;
	this->notify = notify;
	operation = SESSION_OP_NONE;
	digestOp = NULL;
}

// Constructor
Session::Session()
{
	slot = NULL;
	token = NULL;
	isReadWrite = false;
	hSession = CK_INVALID_HANDLE;
	pApplication = NULL;
	notify = NULL;
	operation = SESSION_OP_NONE;
	digestOp = NULL;
}

// Destructor
Session::~Session()
{
	resetOp();

	// Remove any session objects
	SessionObjectStore::i()->sessionClosed(hSession);
}

// Get session info
CK_RV Session::getInfo(CK_SESSION_INFO_PTR pInfo)
{
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	pInfo->slotID = slot->getSlotID();

	pInfo->state = getState();
	pInfo->flags = CKF_SERIAL_SESSION;
	if (isRW())
	{
		pInfo->flags |= CKF_RW_SESSION;
	}
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}

// Is a read and write session
bool Session::isRW()
{
	return isReadWrite;
}

// Get session state
CK_STATE Session::getState()
{
	if (token->isSOLoggedIn())
	{
		return CKS_RW_SO_FUNCTIONS;
	}

	if (token->isUserLoggedIn())
	{
		if (isRW())
		{
			return CKS_RW_USER_FUNCTIONS;
		}
		else
		{
			return CKS_RO_USER_FUNCTIONS;
		}
	}

	if (isRW())
	{
		return CKS_RW_PUBLIC_SESSION;
	}
	else
	{
		return CKS_RO_PUBLIC_SESSION;
	}
}

void Session::setHandle(CK_SESSION_HANDLE hSession)
{
	this->hSession = hSession;
}

CK_SESSION_HANDLE Session::getHandle()
{
	return hSession;
}

// Return the slot that the session is connected to
Slot* Session::getSlot()
{
	return slot;
}

// Return the token that the session is connected to
Token* Session::getToken()
{
	return token;
}

// Set the operation type
void Session::setOpType(int operation)
{
	this->operation = operation;
}

// Get the operation type
int Session::getOpType()
{
	return operation;
}

// Reset the operations
void Session::resetOp()
{
	if (digestOp != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(digestOp);
		digestOp = NULL;
	}

	operation = SESSION_OP_NONE;
}

// Set the digesting operator
void Session::setDigestOp(HashAlgorithm *digestOp)
{
	if (this->digestOp != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(this->digestOp);
	}

	this->digestOp = digestOp;
}

// Get the digesting operator
HashAlgorithm* Session::getDigestOp()
{
	return digestOp;
}
