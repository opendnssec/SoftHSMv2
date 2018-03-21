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
 SecureDataManager.h

 The secure data manager main class. Every token instance has a secure data
 manager instance member that is used to decrypt and encrypt sensitive object
 attributes such as key material. The secure data manager maintains a key blob
 containing a 256-bit AES key that is used in this decryption and encryption
 process. The key blob itself is encrypted using a PBE derived key that is
 derived from the user PIN and a PBE key that is derived from the SO PIN. It
 is up to the token to enforce access control based on which user is logged
 in; authentication using the SO PIN is required to be able to change the
 user PIN. The master key that is used to decrypt/encrypt sensitive attributes
 is stored in memory under a mask that is changed every time the key is used.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SECUREDATAMANAGER_H
#define _SOFTHSM_V2_SECUREDATAMANAGER_H

#include "config.h"
#include "ByteString.h"
#include "log.h"
#include "AESKey.h"
#include "RNG.h"
#include "SymmetricAlgorithm.h"
#include "MutexFactory.h"

class SecureDataManager
{
public:
	// Constructors

	// Constructs a new SecureDataManager for a blank token; actual
	// initialisation is done by setting the SO PIN
	SecureDataManager();

	// Constructs a SecureDataManager using the specified SO PIN and user PIN
	SecureDataManager(const ByteString& soPINBlob, const ByteString& userPINBlob);

	// Destructor
	virtual ~SecureDataManager();

	// Set the SO PIN (requires either a blank SecureDataManager or the
	// SO to have logged in previously)
	bool setSOPIN(const ByteString& soPIN);

	// Set the user PIN (requires either the SO or the user to have logged
	// in previously)
	bool setUserPIN(const ByteString& userPIN);

	// Log in using the SO PIN
	bool loginSO(const ByteString& soPIN);
	bool isSOLoggedIn();

	// Log in using the user PIN
	bool loginUser(const ByteString& userPIN);
	bool isUserLoggedIn();

	// Re-authentication
	bool reAuthenticateSO(const ByteString& soPIN);
	bool reAuthenticateUser(const ByteString& userPIN);

	// Log out
	void logout();

	// Decrypt the supplied data
	bool decrypt(const ByteString& encrypted, ByteString& plaintext);

	// Encrypt the supplied data
	bool encrypt(const ByteString& plaintext, ByteString& encrypted);

	// Returns the key blob for the SO PIN
	ByteString getSOPINBlob();

	// Returns the key blob for the user PIN
	ByteString getUserPINBlob();

private:
	// Initialise the object
	void initObject();

	// Generic login function
	bool login(const ByteString& passphrase, const ByteString& encryptedKey);

	// Generic re-authentication function
	bool reAuthenticate(const ByteString& passphrase, const ByteString& encryptedKey);

	// Generic function for creating an encrypted version of the key from the specified passphrase
	bool pbeEncryptKey(const ByteString& passphrase, ByteString& encryptedKey);

	// Unmask the key
	void unmask(ByteString& key);

	// Remask the key
	void remask(ByteString& key);

	// The user PIN encrypted key
	ByteString userEncryptedKey;

	// The SO PIN encrypted key
	ByteString soEncryptedKey;

	// Which users are logged in
	bool soLoggedIn;
	bool userLoggedIn;

	// The masked version of the actual key
	ByteString maskedKey;

	// The "magic" data used to detect if a PIN was likely to be correct
	ByteString magic;

	// The mask; this is not a stack member but a heap member. This
	// hopefully ensures that the mask ends up in a memory location
	// that is not logically linked to the masked key
	ByteString* mask;

	// Random number generator instance
	RNG* rng;

	// AES instance
	SymmetricAlgorithm* aes;

	// Mutex
	Mutex* dataMgrMutex;
};

#endif // !_SOFTHSM_V2_SECUREDATAMANAGER_H

