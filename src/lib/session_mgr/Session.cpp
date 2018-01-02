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
Session::Session(Slot* inSlot, bool inIsReadWrite, CK_VOID_PTR inPApplication, CK_NOTIFY inNotify)
{
	slot = inSlot;
	token = slot->getToken();
	isReadWrite = inIsReadWrite;
	hSession = CK_INVALID_HANDLE;
	pApplication = inPApplication;
	notify = inNotify;
	operation = SESSION_OP_NONE;
	findOp = NULL;
	digestOp = NULL;
	hashAlgo = HashAlgo::Unknown;
	macOp = NULL;
	asymmetricCryptoOp = NULL;
	symmetricCryptoOp = NULL;
	mechanism = AsymMech::Unknown;
	reAuthentication = false;
	allowSinglePartOp = false;
	allowMultiPartOp = false;
	publicKey = NULL;
	privateKey = NULL;
	symmetricKey = NULL;
	param = NULL;
	paramLen = 0;
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
	hashAlgo = HashAlgo::Unknown;
	macOp = NULL;
	asymmetricCryptoOp = NULL;
	symmetricCryptoOp = NULL;
	mechanism = AsymMech::Unknown;
	reAuthentication = false;
	allowSinglePartOp = false;
	allowMultiPartOp = false;
	publicKey = NULL;
	privateKey = NULL;
	symmetricKey = NULL;
	param = NULL;
	paramLen = 0;
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

void Session::setHandle(CK_SESSION_HANDLE inHSession)
{
	hSession = inHSession;
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
void Session::setOpType(int inOperation)
{
	operation = inOperation;
}

// Get the operation type
int Session::getOpType()
{
	return operation;
}

// Reset the operations
void Session::resetOp()
{
	if (param != NULL)
	{
		free(param);
		param = NULL;
		paramLen = 0;
	}

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
	else if (symmetricCryptoOp != NULL)
	{
		if (symmetricKey != NULL)
		{
			symmetricCryptoOp->recycleKey(symmetricKey);
			symmetricKey = NULL;
		}
		CryptoFactory::i()->recycleSymmetricAlgorithm(symmetricCryptoOp);
		symmetricCryptoOp = NULL;
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
	reAuthentication = false;
}

void Session::setFindOp(FindOperation *inFindOp)
{
	if (findOp != NULL) {
		delete findOp;
	}
	findOp = inFindOp;
}

FindOperation *Session::getFindOp()
{
	return findOp;
}

// Set the digesting operator
void Session::setDigestOp(HashAlgorithm* inDigestOp)
{
	if (digestOp != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(digestOp);
	}

	digestOp = inDigestOp;
}

// Get the digesting operator
HashAlgorithm* Session::getDigestOp()
{
	return digestOp;
}

void Session::setHashAlgo(HashAlgo::Type inHashAlgo)
{
	hashAlgo = inHashAlgo;
}

HashAlgo::Type Session::getHashAlgo()
{
	return hashAlgo;
}

// Set the MACing operator
void Session::setMacOp(MacAlgorithm *inMacOp)
{
	if (macOp != NULL)
	{
		setSymmetricKey(NULL);
		CryptoFactory::i()->recycleMacAlgorithm(macOp);
	}

	macOp = inMacOp;
}

// Get the MACing operator
MacAlgorithm *Session::getMacOp()
{
	return macOp;
}

void Session::setAsymmetricCryptoOp(AsymmetricAlgorithm *inAsymmetricCryptoOp)
{
	if (asymmetricCryptoOp != NULL)
	{
		setPublicKey(NULL);
		setPrivateKey(NULL);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymmetricCryptoOp);
	}

	asymmetricCryptoOp = inAsymmetricCryptoOp;
}

AsymmetricAlgorithm *Session::getAsymmetricCryptoOp()
{
	return asymmetricCryptoOp;
}

void Session::setSymmetricCryptoOp(SymmetricAlgorithm *inSymmetricCryptoOp)
{
	if (symmetricCryptoOp != NULL)
	{
		setSymmetricKey(NULL);
		CryptoFactory::i()->recycleSymmetricAlgorithm(symmetricCryptoOp);
	}

	symmetricCryptoOp = inSymmetricCryptoOp;
}

SymmetricAlgorithm *Session::getSymmetricCryptoOp()
{
	return symmetricCryptoOp;
}

void Session::setMechanism(AsymMech::Type inMechanism)
{
	mechanism = inMechanism;
}

AsymMech::Type Session::getMechanism()
{
	return mechanism;
}

void Session::setParameters(void* inParam, size_t inParamLen)
{
	if (inParam == NULL || inParamLen == 0) return;

	if (param != NULL)
	{
		free(param);
		paramLen = 0;
	}

	param = malloc(inParamLen);
	if (param != NULL)
	{
		memcpy(param, inParam, inParamLen);
		paramLen = inParamLen;
	}
}

void* Session::getParameters(size_t& inParamLen)
{
	inParamLen = paramLen;
	return param;
}

void Session::setReAuthentication(bool inReAuthentication)
{
	reAuthentication = inReAuthentication;
}

bool Session::getReAuthentication()
{
	return reAuthentication;
}

void Session::setAllowMultiPartOp(bool inAllowMultiPartOp)
{
	allowMultiPartOp = inAllowMultiPartOp;
}

bool Session::getAllowMultiPartOp()
{
	return allowMultiPartOp;
}

void Session::setAllowSinglePartOp(bool inAllowSinglePartOp)
{
	allowSinglePartOp = inAllowSinglePartOp;
}

bool Session::getAllowSinglePartOp()
{
	return allowSinglePartOp;
}

void Session::setPublicKey(PublicKey* inPublicKey)
{
	if (asymmetricCryptoOp == NULL)
		return;

	if (publicKey != NULL)
	{
		asymmetricCryptoOp->recyclePublicKey(publicKey);
	}

	publicKey = inPublicKey;
}

PublicKey* Session::getPublicKey()
{
	return publicKey;
}

void Session::setPrivateKey(PrivateKey* inPrivateKey)
{
	if (asymmetricCryptoOp == NULL)
		return;

	if (privateKey != NULL)
	{
		asymmetricCryptoOp->recyclePrivateKey(privateKey);
	}

	privateKey = inPrivateKey;
}

PrivateKey* Session::getPrivateKey()
{
	return privateKey;
}

void Session::setSymmetricKey(SymmetricKey* inSymmetricKey)
{
	if (symmetricKey != NULL)
	{
		if (macOp) {
			macOp->recycleKey(symmetricKey);
		} else if (symmetricCryptoOp) {
			symmetricCryptoOp->recycleKey(symmetricKey);
		} else {
			return;
		}
	}

	symmetricKey = inSymmetricKey;
}

SymmetricKey* Session::getSymmetricKey()
{
	return symmetricKey;
}
