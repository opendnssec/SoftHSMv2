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

// Constructor
Session::Session(Slot* slot, bool isReadWrite, CK_VOID_PTR pApplication, CK_NOTIFY notify)
{
	this->slot = slot;
	this->token = slot->getToken();
	this->isReadWrite = isReadWrite;
	hSession = CK_INVALID_HANDLE;
	this->pApplication = pApplication;
	this->notify = notify;
	operation = SESSION_OP_NONE;
	findOp = NULL;
	digestOp = NULL;
	macOp = NULL;
	asymmetricCryptoOp = NULL;
	publicKey = NULL;
	privateKey = NULL;
	symmetricKey = NULL;
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
	findOp = NULL;
	digestOp = NULL;
	macOp = NULL;
	asymmetricCryptoOp = NULL;
	publicKey = NULL;
	privateKey = NULL;
	symmetricKey = NULL;
}

// Destructor
Session::~Session()
{
	resetOp();
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
	else if (findOp != NULL)
	{
		findOp->recycle();
		findOp = NULL;
	}
	else if (asymmetricCryptoOp != NULL)
	{
		if (publicKey != NULL)
		{
			asymmetricCryptoOp->recyclePublicKey(publicKey);
			publicKey = NULL;
		}
		if (privateKey != NULL)
		{
			asymmetricCryptoOp->recyclePrivateKey(privateKey);
			privateKey = NULL;
		}
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymmetricCryptoOp);
		asymmetricCryptoOp = NULL;
	}
	else if (macOp != NULL)
	{
		if (symmetricKey != NULL)
		{
			macOp->recycleKey(symmetricKey);
			symmetricKey = NULL;
		}
		CryptoFactory::i()->recycleMacAlgorithm(macOp);
		macOp = NULL;
	}

	operation = SESSION_OP_NONE;
}

void Session::setFindOp(FindOperation *findOp)
{
	if (this->findOp != NULL) {
		delete this->findOp;
	}
	this->findOp = findOp;
}

FindOperation *Session::getFindOp()
{
	return findOp;
}

// Set the digesting operator
void Session::setDigestOp(HashAlgorithm* digestOp)
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

// Set the MACing operator
void Session::setMacOp(MacAlgorithm *macOp)
{
	if (this->macOp != NULL)
	{
		setSymmetricKey(NULL);
		CryptoFactory::i()->recycleMacAlgorithm(macOp);
	}

	this->macOp = macOp;
}

// Get the MACing operator
MacAlgorithm *Session::getMacOp()
{
	return macOp;
}

void Session::setAsymmetricCryptoOp(AsymmetricAlgorithm *asymmetricCryptoOp)
{
	if (this->asymmetricCryptoOp != NULL)
	{
		setPublicKey(NULL);
		setPrivateKey(NULL);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymmetricCryptoOp);
	}

	this->asymmetricCryptoOp = asymmetricCryptoOp;
}

AsymmetricAlgorithm *Session::getAsymmetricCryptoOp()
{
	return asymmetricCryptoOp;
}

void Session::setMechanism(const char *mechanism)
{
	this->mechanism = mechanism;
}

const char *Session::getMechanism()
{
	return mechanism;
}

void Session::setAllowMultiPartOp(bool allowMultiPartOp)
{
	this->allowMultiPartOp = allowMultiPartOp;
}

bool Session::getAllowMultiPartOp()
{
	return allowMultiPartOp;
}

void Session::setAllowSinglePartOp(bool allowSinglePartOp)
{
	this->allowSinglePartOp = allowSinglePartOp;
}

bool Session::getAllowSinglePartOp()
{
	return allowSinglePartOp;
}

void Session::setPublicKey(PublicKey* publicKey)
{
	if (asymmetricCryptoOp == NULL)
		return;

	if (this->publicKey != NULL)
	{
		asymmetricCryptoOp->recyclePublicKey(publicKey);
	}

	this->publicKey = publicKey;
}

PublicKey* Session::getPublicKey()
{
	return publicKey;
}

void Session::setPrivateKey(PrivateKey* privateKey)
{
	if (asymmetricCryptoOp == NULL)
		return;

	if (this->privateKey != NULL)
	{
		asymmetricCryptoOp->recyclePrivateKey(privateKey);
	}

	this->privateKey = privateKey;
}

PrivateKey* Session::getPrivateKey()
{
	return privateKey;
}

void Session::setSymmetricKey(SymmetricKey* symmetricKey)
{
	if (macOp == NULL)
		return;

	if (this->symmetricKey != NULL)
	{
		macOp->recycleKey(symmetricKey);
	}

	this->symmetricKey = symmetricKey;
}

SymmetricKey* Session::getSymmetricKey()
{
	return symmetricKey;
}
