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
 SoftHSM.cpp

 The implementation of the SoftHSM's main class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "Configuration.h"
#include "XMLConfigLoader.h"
#include "MutexFactory.h"
#include "cryptoki.h"
#include "SoftHSM.h"
#include "osmutex.h"

/*****************************************************************************
 Implementation of SoftHSM class specific functions
 *****************************************************************************/

// Initialise the one-and-only instance
std::auto_ptr<SoftHSM> SoftHSM::instance(NULL);

// Return the one-and-only instance
SoftHSM* SoftHSM::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<SoftHSM>(new SoftHSM());
	}

	return instance.get();
}

// Constructor
SoftHSM::SoftHSM()
{
	isInitialised = false;
	objectStore = NULL;
	slotManager = NULL;
}

// Destructor
SoftHSM::~SoftHSM()
{
	if (slotManager != NULL) delete slotManager;
	if (objectStore != NULL) delete objectStore;
}

/*****************************************************************************
 Implementation of PKCS #11 functions
 *****************************************************************************/

// PKCS #11 initialisation function
CK_RV SoftHSM::C_Initialize(CK_VOID_PTR pInitArgs) 
{
	CK_C_INITIALIZE_ARGS_PTR args;

	// Check if PKCS #11 is already initialised
	if (isInitialised)
	{
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	// Do we have any arguments?
	if (pInitArgs != NULL_PTR)
	{
		args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

		// Must be set to NULL_PTR in this version of PKCS#11
		if (args->pReserved != NULL_PTR)
		{
			DEBUG_MSG("pReserved must be set to NULL_PTR");
			return CKR_ARGUMENTS_BAD;
		}

		// Can we spawn our own threads?
		// if (args->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
		// {
		//	DEBUG_MSG("Cannot create threads if CKF_LIBRARY_CANT_CREATE_OS_THREADS is set");
		//	return CKR_NEED_TO_CREATE_THREADS;
		// }

		// Are we not supplied with mutex functions?
		if
		(
			args->CreateMutex == NULL_PTR &&
			args->DestroyMutex == NULL_PTR &&
			args->LockMutex == NULL_PTR &&
			args->UnlockMutex == NULL_PTR
		)
		{
			// Can we use our own mutex functions?
			if (args->flags & CKF_OS_LOCKING_OK)
			{
				// Use our own mutex functions.
				MutexFactory::i()->setCreateMutex(OSCreateMutex);
				MutexFactory::i()->setDestroyMutex(OSDestroyMutex);
				MutexFactory::i()->setLockMutex(OSLockMutex);
				MutexFactory::i()->setUnlockMutex(OSUnlockMutex);
				MutexFactory::i()->enable();
			}
			else
			{
				// The external application is not using threading
				MutexFactory::i()->disable();
			}
		}
		else
		{
			// We must have all mutex functions
			if
			(
				args->CreateMutex == NULL_PTR ||
				args->DestroyMutex == NULL_PTR ||
				args->LockMutex == NULL_PTR ||
				args->UnlockMutex == NULL_PTR
			)
			{
				DEBUG_MSG("Not all mutex functions are supplied");
				return CKR_ARGUMENTS_BAD;
			}

			// We could use our own mutex functions if the flag is set,
			// but we use the external functions in both cases.

			// Load the external mutex functions
			MutexFactory::i()->setCreateMutex(args->CreateMutex);
			MutexFactory::i()->setDestroyMutex(args->DestroyMutex);
			MutexFactory::i()->setLockMutex(args->LockMutex);
			MutexFactory::i()->setUnlockMutex(args->UnlockMutex);
			MutexFactory::i()->enable();
		}
	}
	else
	{
		// No concurrent access by multiple threads
		MutexFactory::i()->disable();
	}

	// (Re)load the configuration
	Configuration::i()->reload(XMLConfigLoader::i());

	// Load the object store
	// TODO: Move the path into the configuration
	objectStore = new ObjectStore("./testdir");
	if (!objectStore->isValid())
	{
		ERROR_MSG("Could not load the object store");
		delete objectStore;
		objectStore = NULL;
		return CKR_GENERAL_ERROR;
	}

	// Load the slot manager
	slotManager = new SlotManager(objectStore);

	// Set the state to initialised
	isInitialised = true;

	return CKR_OK;
}

// PKCS #11 finalisation function
CK_RV SoftHSM::C_Finalize(CK_VOID_PTR pReserved) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Must be set to NULL_PTR in this version of PKCS#11
	if (pReserved != NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (slotManager != NULL) delete slotManager;
	slotManager = NULL;
	if (objectStore != NULL) delete objectStore;
	objectStore = NULL;

	// TODO: What should we finalize?

	return CKR_OK;
}

// Return information about the PKCS #11 module
CK_RV SoftHSM::C_GetInfo(CK_INFO_PTR pInfo) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	memset(pInfo->manufacturerID, ' ', 32);
	memcpy(pInfo->manufacturerID, "SoftHSM", 7);
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', 32);
	memcpy(pInfo->libraryDescription, "Implementation of PKCS11", 24);
	pInfo->libraryVersion.major = VERSION_MAJOR;
	pInfo->libraryVersion.minor = VERSION_MINOR;

	return CKR_OK;
}

// Return a list of available slots
CK_RV SoftHSM::C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return slotManager->getSlotList(tokenPresent, pSlotList, pulCount);
}

// Return information about a slot
CK_RV SoftHSM::C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot *slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	return slot->getSlotInfo(pInfo);
}

// Return information about a token in a slot
CK_RV SoftHSM::C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot *slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	Token *token = slot->getToken();
	if (token == NULL)
	{
		return CKR_TOKEN_NOT_PRESENT;
	}

	return token->getTokenInfo(pInfo);
}

// Return the list of supported mechanisms for a given slot
CK_RV SoftHSM::C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Return more information about a mechanism for a given slot
CK_RV SoftHSM::C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	Slot *slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	switch (type)
	{
		case CKM_MD5:
		case CKM_SHA_1:
		case CKM_SHA256:
		case CKM_SHA512:
			pInfo->flags = CKF_DIGEST;
			break;
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 4096;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_RSA_PKCS:
		case CKM_RSA_X_509:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 4096;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_MD5_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 4096;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_DES_KEY_GEN:
		case CKM_DES2_KEY_GEN:
		case CKM_DES3_KEY_GEN:
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DES_ECB:
		case CKM_DES_CBC:
		case CKM_DES3_ECB:
		case CKM_DES3_CBC:
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_AES_KEY_GEN:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_AES_ECB:
		case CKM_AES_CBC:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_DSA_PARAMETER_GEN:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_DSA_SHA1:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		default:
			DEBUG_MSG("The selected mechanism is not supported");
			return CKR_MECHANISM_INVALID;
			break;
	}

	return CKR_OK;
}

// Initialise the token in the specified slot
CK_RV SoftHSM::C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot *slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	return slot->initToken(pPin, ulPinLen, pLabel);
}

// Initialise the user PIN
CK_RV SoftHSM::C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Change the PIN
CK_RV SoftHSM::C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pOldPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pNewPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulOldLen < MIN_PIN_LEN || ulOldLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;
	if (ulNewLen < MIN_PIN_LEN || ulNewLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Open a new session to the specified slot
CK_RV SoftHSM::C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (phSession == NULL_PTR) return CKR_ARGUMENTS_BAD;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Close the given session
CK_RV SoftHSM::C_CloseSession(CK_SESSION_HANDLE hSession) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Close all open sessions
CK_RV SoftHSM::C_CloseAllSessions(CK_SLOT_ID slotID) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Retrieve information about the specified session
CK_RV SoftHSM::C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Determine the state of a running operation in a session
CK_RV SoftHSM::C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Set the operation sate in a session
CK_RV SoftHSM::C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Login on the token in the specified session
CK_RV SoftHSM::C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Log out of the token in the specified session
CK_RV SoftHSM::C_Logout(CK_SESSION_HANDLE hSession) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Create a new object on the token in the specified session using the given attribute template
CK_RV SoftHSM::C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Create a copy of the object with the specified handle
CK_RV SoftHSM::C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Destroy the specified object
CK_RV SoftHSM::C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Determine the size of the specified object
CK_RV SoftHSM::C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Retrieve the specified attributes for the given object
CK_RV SoftHSM::C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Change or set the value of the specified attributes on the specified object
CK_RV SoftHSM::C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise object search in the specified session using the specified attribute template as search parameters
CK_RV SoftHSM::C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Continue the search for objects in the specified session
CK_RV SoftHSM::C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finish searching for objects
CK_RV SoftHSM::C_FindObjectsFinal(CK_SESSION_HANDLE hSession) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise encryption using the specified object and mechanism
CK_RV SoftHSM::C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single operation encryption operation in the specified session
CK_RV SoftHSM::C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Feed data to the running encryption operation in a session
CK_RV SoftHSM::C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise the encryption operation
CK_RV SoftHSM::C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise decryption using the specified object
CK_RV SoftHSM::C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single operation decryption in the given session
CK_RV SoftHSM::C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Feed data to the running decryption operation in a session
CK_RV SoftHSM::C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise the decryption operation
CK_RV SoftHSM::C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise digesting using the specified mechanism in the specified session
CK_RV SoftHSM::C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Digest the specified data in a one-pass operation and return the resulting digest
CK_RV SoftHSM::C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running digest operation
CK_RV SoftHSM::C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running digest operation by digesting a secret key with the specified handle
CK_RV SoftHSM::C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise the digest operation in the specified session and return the digest
CK_RV SoftHSM::C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise a signing operation using the specified key and mechanism
CK_RV SoftHSM::C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Sign the data in a single pass operation
CK_RV SoftHSM::C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running signing operation with additional data
CK_RV SoftHSM::C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise a running signing operation and return the signature
CK_RV SoftHSM::C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise a signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise a verification operation using the specified key and mechanism
CK_RV SoftHSM::C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single pass verification operation
CK_RV SoftHSM::C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running verification operation with additional data
CK_RV SoftHSM::C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise the verification operation and check the signature
CK_RV SoftHSM::C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise a verification operation the allows recovery of the signed data from the signature
CK_RV SoftHSM::C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part verification operation and recover the signed data
CK_RV SoftHSM::C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part encryption and digesting operation
CK_RV SoftHSM::C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and digesting operation
CK_RV SoftHSM::C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part signing and encryption operation
CK_RV SoftHSM::C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and verification operation
CK_RV SoftHSM::C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generate a secret key using the specified mechanism
CK_RV SoftHSM::C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generate a key-pair using the specified mechanism
CK_RV SoftHSM::C_GenerateKeyPair
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
	CK_ULONG ulPublicKeyAttributeCount, 
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey, 
	CK_OBJECT_HANDLE_PTR phPrivateKey
) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Wrap the specified key using the specified wrapping key and mechanism
CK_RV SoftHSM::C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hWrappingKey, 
	CK_OBJECT_HANDLE hKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG_PTR pulWrappedKeyLen
) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Unwrap the specified key using the specified unwrapping key
CK_RV SoftHSM::C_UnwrapKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hUnwrappingKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR hKey
) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Derive a key from the specified base key
CK_RV SoftHSM::C_DeriveKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hBaseKey, 
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Seed the random number generator with new data
CK_RV SoftHSM::C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generate the specified amount of random data
CK_RV SoftHSM::C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Legacy function
CK_RV SoftHSM::C_GetFunctionStatus(CK_SESSION_HANDLE hSession) 
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

// Legacy function
CK_RV SoftHSM::C_CancelFunction(CK_SESSION_HANDLE hSession) 
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

// Wait or poll for a slot even on the specified slot
CK_RV SoftHSM::C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
