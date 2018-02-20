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
 SecureDataManager.cpp

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

#include "config.h"
#include "SecureDataManager.h"
#include "CryptoFactory.h"
#include "AESKey.h"
#include "SymmetricAlgorithm.h"
#include "RFC4880.h"

// Constructors

// Initialise the object; called by all constructors
void SecureDataManager::initObject()
{
	// Get an RNG instance
	rng = CryptoFactory::i()->getRNG();

	// Get an AES implementation
	aes = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);

	// Initialise masking data
	mask = new ByteString();

	rng->generateRandom(*mask, 32);

	// Set the initial login state
	soLoggedIn = userLoggedIn = false;

	// Set the magic
	magic = ByteString("524A52"); // RJR

	// Get a mutex
	dataMgrMutex = MutexFactory::i()->getMutex();
}

// Constructs a new SecureDataManager for a blank token; actual
// initialisation is done by setting the SO PIN
SecureDataManager::SecureDataManager()
{
	initObject();
}

// Constructs a SecureDataManager using the specified key blob
SecureDataManager::SecureDataManager(const ByteString& soPINBlob, const ByteString& userPINBlob)
{
	initObject();

	// De-serialise the key blob
	soEncryptedKey = soPINBlob;
	userEncryptedKey = userPINBlob;
}

// Destructor
SecureDataManager::~SecureDataManager()
{
	// Recycle the AES instance
	CryptoFactory::i()->recycleSymmetricAlgorithm(aes);

	// Clean up the mask
	delete mask;

	MutexFactory::i()->recycleMutex(dataMgrMutex);
}

// Generic function for creating an encrypted version of the key from the specified passphrase
bool SecureDataManager::pbeEncryptKey(const ByteString& passphrase, ByteString& encryptedKey)
{
	// Generate salt
	ByteString salt;

	if (!rng->generateRandom(salt, 8)) return false;

	// Derive the key using RFC4880 PBE
	AESKey* pbeKey = NULL;

	if (!RFC4880::PBEDeriveKey(passphrase, salt, &pbeKey))
	{
		return false;
	}

	// Add the salt
	encryptedKey.wipe();
	encryptedKey += salt;

	// Generate random IV
	ByteString IV;

	if (!rng->generateRandom(IV, aes->getBlockSize())) return false;

	// Add the IV
	encryptedKey += IV;

	// Encrypt the data
	ByteString block;

	if (!aes->encryptInit(pbeKey, SymMode::CBC, IV))
	{
		delete pbeKey;

		return false;
	}

	// First, add the magic
	if (!aes->encryptUpdate(magic, block))
	{
		delete pbeKey;

		return false;
	}

	encryptedKey += block;

	// Then, add the key itself
	ByteString key;

	{
		MutexLocker lock(dataMgrMutex);

		unmask(key);

		bool rv = aes->encryptUpdate(key, block);

		remask(key);

		if (!rv)
		{
			delete pbeKey;

			return false;
		}
	}

	encryptedKey += block;

	// And finalise encryption
	if (!aes->encryptFinal(block))
	{
		delete pbeKey;

		return false;
	}

	encryptedKey += block;

	delete pbeKey;

	return true;
}

// Set the SO PIN (requires either a blank SecureDataManager or the
// SO to have logged in previously)
bool SecureDataManager::setSOPIN(const ByteString& soPIN)
{
	// Check the new PIN
	if (soPIN.size() == 0)
	{
		DEBUG_MSG("Zero length PIN specified");

		return false;
	}

	// Check if the SO needs to be logged in
	if ((soEncryptedKey.size() > 0) && !soLoggedIn)
	{
		DEBUG_MSG("SO must be logged in to change the SO PIN");

		return false;
	}

	// If no SO PIN was set, then this is a SecureDataManager for a blank token. This
	// means a new key has to be generated
	if (soEncryptedKey.size() == 0)
	{
		ByteString key;

		rng->generateRandom(key, 32);

		remask(key);
	}

	return pbeEncryptKey(soPIN, soEncryptedKey);
}

// Set the user PIN (requires either the SO or the user to have logged
// in previously)
bool SecureDataManager::setUserPIN(const ByteString& userPIN)
{
	// Check if the SO or the user is logged in
	if (!soLoggedIn && !userLoggedIn)
	{
		DEBUG_MSG("Must be logged in to change the user PIN");

		return false;
	}

	// Check the new PIN
	if (userPIN.size() == 0)
	{
		DEBUG_MSG("Zero length PIN specified");

		return false;
	}

	return pbeEncryptKey(userPIN, userEncryptedKey);
}

// Generic login function
bool SecureDataManager::login(const ByteString& passphrase, const ByteString& encryptedKey)
{
	// Log out first
	this->logout();

	// First, take the salt from the encrypted key
	ByteString salt = encryptedKey.substr(0,8);

	// Then, take the IV from the encrypted key
	ByteString IV = encryptedKey.substr(8, aes->getBlockSize());

	// Now, take the encrypted data from the encrypted key
	ByteString encryptedKeyData = encryptedKey.substr(8 + aes->getBlockSize());

	// Derive the PBE key
	AESKey* pbeKey = NULL;

	if (!RFC4880::PBEDeriveKey(passphrase, salt, &pbeKey))
	{
		return false;
	}

	// Decrypt the key data
	ByteString decryptedKeyData;
	ByteString finalBlock;

	// NOTE: The login will fail here if incorrect passphrase is supplied
	if (!aes->decryptInit(pbeKey, SymMode::CBC, IV) ||
	    !aes->decryptUpdate(encryptedKeyData, decryptedKeyData) ||
	    !aes->decryptFinal(finalBlock))
	{
		delete pbeKey;

		return false;
	}

	delete pbeKey;

	decryptedKeyData += finalBlock;

	// Check the magic
	if (decryptedKeyData.substr(0, 3) != magic)
	{
		// The passphrase was incorrect
		DEBUG_MSG("Incorrect passphrase supplied");

		return false;
	}

	// Strip off the magic
	ByteString key = decryptedKeyData.substr(3);

	// And mask the key
	decryptedKeyData.wipe();

	MutexLocker lock(dataMgrMutex);
	remask(key);

	return true;
}

// Log in using the SO PIN
bool SecureDataManager::loginSO(const ByteString& soPIN)
{
	return (soLoggedIn = login(soPIN, soEncryptedKey));
}

// Log in using the user PIN
bool SecureDataManager::loginUser(const ByteString& userPIN)
{
	return (userLoggedIn = login(userPIN, userEncryptedKey));
}

// Generic re-authentication function
bool SecureDataManager::reAuthenticate(const ByteString& passphrase, const ByteString& encryptedKey)
{
	// First, take the salt from the encrypted key
	ByteString salt = encryptedKey.substr(0,8);

	// Then, take the IV from the encrypted key
	ByteString IV = encryptedKey.substr(8, aes->getBlockSize());

	// Now, take the encrypted data from the encrypted key
	ByteString encryptedKeyData = encryptedKey.substr(8 + aes->getBlockSize());

	// Derive the PBE key
	AESKey* pbeKey = NULL;

	if (!RFC4880::PBEDeriveKey(passphrase, salt, &pbeKey))
	{
		return false;
	}

	// Decrypt the key data
	ByteString decryptedKeyData;
	ByteString finalBlock;

	// NOTE: The login will fail here if incorrect passphrase is supplied
	if (!aes->decryptInit(pbeKey, SymMode::CBC, IV) ||
	    !aes->decryptUpdate(encryptedKeyData, decryptedKeyData) ||
	    !aes->decryptFinal(finalBlock))
	{
		delete pbeKey;

		return false;
	}

	delete pbeKey;

	decryptedKeyData += finalBlock;

	// Check the magic
	if (decryptedKeyData.substr(0, 3) != magic)
	{
		// The passphrase was incorrect
		DEBUG_MSG("Incorrect passphrase supplied");

		return false;
	}

	// And mask the key
	decryptedKeyData.wipe();

	return true;
}

// Re-authenticate the SO
bool SecureDataManager::reAuthenticateSO(const ByteString& soPIN)
{
	return reAuthenticate(soPIN, soEncryptedKey);
}

// Re-authenticate the user
bool SecureDataManager::reAuthenticateUser(const ByteString& userPIN)
{
	return reAuthenticate(userPIN, userEncryptedKey);
}

// Log out
void SecureDataManager::logout()
{
	MutexLocker lock(dataMgrMutex);

	// Clear the logged in state
	soLoggedIn = userLoggedIn = false;

	// Clear the masked key
	maskedKey.wipe();
}

// Decrypt the supplied data
bool SecureDataManager::decrypt(const ByteString& encrypted, ByteString& plaintext)
{
	// Check the object logged in state
	if ((!userLoggedIn && !soLoggedIn) || (maskedKey.size() != 32))
	{
		return false;
	}

	// Do not attempt decryption of empty byte strings
	if (encrypted.size() == 0)
	{
		plaintext = ByteString("");
		return true;
	}

	AESKey theKey(256);
	ByteString unmaskedKey;

	{
		MutexLocker lock(dataMgrMutex);

		unmask(unmaskedKey);

		theKey.setKeyBits(unmaskedKey);

		remask(unmaskedKey);
	}

	// Take the IV from the input data
	ByteString IV = encrypted.substr(0, aes->getBlockSize());

	if (IV.size() != aes->getBlockSize())
	{
		ERROR_MSG("Invalid IV in encrypted data");

		return false;
	}

	ByteString finalBlock;

	if (!aes->decryptInit(&theKey, SymMode::CBC, IV) ||
	    !aes->decryptUpdate(encrypted.substr(aes->getBlockSize()), plaintext) ||
	    !aes->decryptFinal(finalBlock))
	{
		return false;
	}

	plaintext += finalBlock;

	return true;
}

// Encrypt the supplied data
bool SecureDataManager::encrypt(const ByteString& plaintext, ByteString& encrypted)
{
	// Check the object logged in state
	if ((!userLoggedIn && !soLoggedIn) || (maskedKey.size() != 32))
	{
		return false;
	}

	AESKey theKey(256);
	ByteString unmaskedKey;

	{
		MutexLocker lock(dataMgrMutex);

		unmask(unmaskedKey);

		theKey.setKeyBits(unmaskedKey);

		remask(unmaskedKey);
	}

	// Wipe encrypted data block
	encrypted.wipe();

	// Generate random IV
	ByteString IV;

	if (!rng->generateRandom(IV, aes->getBlockSize())) return false;

	ByteString finalBlock;

	if (!aes->encryptInit(&theKey, SymMode::CBC, IV) ||
	    !aes->encryptUpdate(plaintext, encrypted) ||
	    !aes->encryptFinal(finalBlock))
	{
		return false;
	}

	encrypted += finalBlock;

	// Add IV to output data
	encrypted = IV + encrypted;

	return true;
}

// Returns the key blob for the SO PIN
ByteString SecureDataManager::getSOPINBlob()
{
	return soEncryptedKey;
}

// Returns the key blob for the user PIN
ByteString SecureDataManager::getUserPINBlob()
{
	return userEncryptedKey;
}

// Unmask the key
void SecureDataManager::unmask(ByteString& key)
{
	key = maskedKey;
	key ^= *mask;
}

// Remask the key
void SecureDataManager::remask(ByteString& key)
{
	// Generate a new mask
	rng->generateRandom(*mask, 32);

	key ^= *mask;
	maskedKey = key;
}

// Check if the SO is logged in
bool SecureDataManager::isSOLoggedIn()
{
	return soLoggedIn;
}

// Check if the user is logged in
bool SecureDataManager::isUserLoggedIn()
{
	return userLoggedIn;
}

