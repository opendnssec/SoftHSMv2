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

#ifndef _SOFTHSM_V2_SESSION_H
#define _SOFTHSM_V2_SESSION_H

#include "Slot.h"
#include "FindOperation.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "SymmetricAlgorithm.h"
#include "Token.h"
#include "cryptoki.h"

#define SESSION_OP_NONE			0x0
#define SESSION_OP_FIND			0x1
#define SESSION_OP_ENCRYPT		0x2
#define SESSION_OP_DECRYPT		0x3
#define SESSION_OP_DIGEST		0x4
#define SESSION_OP_SIGN			0x5
#define SESSION_OP_VERIFY		0x6
#define SESSION_OP_DIGEST_ENCRYPT	0x7
#define SESSION_OP_DECRYPT_DIGEST	0x8
#define SESSION_OP_SIGN_ENCRYPT		0x9
#define SESSION_OP_DECRYPT_VERIFY	0x10

class Session
{
public:
	Session(Slot* inSlot, bool inIsReadWrite, CK_VOID_PTR inPApplication, CK_NOTIFY inNotify);

	// Destructor
	virtual ~Session();

	// Slot and token
	Slot* getSlot();
	Token* getToken();

	// Session properties
	CK_RV getInfo(CK_SESSION_INFO_PTR pInfo);
	bool isRW();
	CK_STATE getState();
	void setHandle(CK_SESSION_HANDLE inHSession);
	CK_SESSION_HANDLE getHandle();

	// Operations
	int getOpType();
	void setOpType(int inOperation);
	void resetOp();

	// Find
	void setFindOp(FindOperation *inFindOp);
	FindOperation *getFindOp();

	// Digest
	void setDigestOp(HashAlgorithm* inDigestOp);
	HashAlgorithm* getDigestOp();
	void setHashAlgo(HashAlgo::Type inHashAlgo);
	HashAlgo::Type getHashAlgo();

	// Mac
	void setMacOp(MacAlgorithm* inMacOp);
	MacAlgorithm* getMacOp();

	// Asymmetric Crypto
	void setAsymmetricCryptoOp(AsymmetricAlgorithm* inAsymmetricCryptoOp);
	AsymmetricAlgorithm* getAsymmetricCryptoOp();

	// Symmetric Crypto
	void setSymmetricCryptoOp(SymmetricAlgorithm* inSymmetricCryptoOp);
	SymmetricAlgorithm* getSymmetricCryptoOp();

	void setMechanism(AsymMech::Type inMechanism);
	AsymMech::Type getMechanism();

	void setParameters(void* inParam, size_t inParamLen);
	void* getParameters(size_t& inParamLen);

	void setReAuthentication(bool inReAuthentication);
	bool getReAuthentication();

	void setAllowMultiPartOp(bool inAllowMultiPartOp);
	bool getAllowMultiPartOp();

	void setAllowSinglePartOp(bool inAllowSinglePartOp);
	bool getAllowSinglePartOp();

	void setPublicKey(PublicKey* inPublicKey);
	PublicKey* getPublicKey();

	void setPrivateKey(PrivateKey* inPrivateKey);
	PrivateKey* getPrivateKey();

	void setSymmetricKey(SymmetricKey* inSymmetricKey);
	SymmetricKey* getSymmetricKey();

private:
	// Constructor
	Session();

	// Slot and token
	Slot* slot;
	Token* token;

	// Application data (not in use)
	CK_VOID_PTR pApplication;
	CK_NOTIFY notify;

	// Session properties
	bool isReadWrite;
	CK_SESSION_HANDLE hSession;

	// Operations
	int operation;

	// Find
	FindOperation *findOp;

	// Digest
	HashAlgorithm* digestOp;
	HashAlgo::Type hashAlgo;

	// Mac
	MacAlgorithm* macOp;

	// Asymmetric Crypto
	AsymmetricAlgorithm* asymmetricCryptoOp;

	// Symmetric Crypto
	SymmetricAlgorithm* symmetricCryptoOp;

	AsymMech::Type mechanism;
	void* param;
	size_t paramLen;
	bool reAuthentication;
	bool allowMultiPartOp;
	bool allowSinglePartOp;
	PublicKey* publicKey;
	PrivateKey* privateKey;

	// Symmetric Crypto
	SymmetricKey* symmetricKey;
};

#endif // !_SOFTHSM_V2_SESSION_H
