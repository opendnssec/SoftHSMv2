/* $Id$ */

/*
 * Copyright (c) 2010 SURFnet bv
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
 SoftHSM.cpp

 The implementation of the SoftHSM's main class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "Configuration.h"
#include "SimpleConfigLoader.h"
#include "MutexFactory.h"
#include "CryptoFactory.h"
#include "AsymmetricAlgorithm.h"
#include "RNG.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAParameters.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"
#include "cryptoki.h"
#include "SoftHSM.h"
#include "osmutex.h"
#include "SessionManager.h"

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
	sessionManager = NULL;
}

// Destructor
SoftHSM::~SoftHSM()
{
	if (sessionManager != NULL) delete sessionManager;
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
	if (!Configuration::i()->reload(SimpleConfigLoader::i()))
	{
		return CKR_GENERAL_ERROR;
	}

	// Load the object store
	objectStore = new ObjectStore(Configuration::i()->getString("directories.tokendir", DEFAULT_TOKENDIR));
	if (!objectStore->isValid())
	{
		ERROR_MSG("Could not load the object store");
		delete objectStore;
		objectStore = NULL;
		return CKR_GENERAL_ERROR;
	}

	// Load the slot manager
	slotManager = new SlotManager(objectStore);

	// Load the session manager
	sessionManager = new SessionManager();

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

	if (sessionManager != NULL) delete sessionManager;
	sessionManager = NULL;
	if (slotManager != NULL) delete slotManager;
	slotManager = NULL;
	if (objectStore != NULL) delete objectStore;
	objectStore = NULL;

	// TODO: What should we finalize?

	isInitialised = false;

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
	// A list with the supported mechanisms
	CK_ULONG nrSupportedMechanisms = 24;
	CK_MECHANISM_TYPE supportedMechanisms[] =
	{
		CKM_MD5,
		CKM_SHA_1,
		CKM_SHA256,
		CKM_SHA512,
		CKM_RSA_PKCS_KEY_PAIR_GEN,
		CKM_RSA_PKCS,
		CKM_RSA_X_509,
		CKM_MD5_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA512_RSA_PKCS,
		CKM_DES_KEY_GEN,
		CKM_DES2_KEY_GEN,
		CKM_DES3_KEY_GEN,
		CKM_DES_ECB,
		CKM_DES_CBC,
		CKM_DES3_ECB,
		CKM_DES3_CBC,
		CKM_AES_KEY_GEN,
		CKM_AES_ECB,
		CKM_AES_CBC,
		CKM_DSA_PARAMETER_GEN,
		CKM_DSA_KEY_PAIR_GEN,
		CKM_DSA_SHA1
	};

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

	Slot *slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	if (pMechanismList == NULL_PTR)
	{
		*pulCount = nrSupportedMechanisms;

		return CKR_OK;
	}

	if (*pulCount < nrSupportedMechanisms)
	{
		*pulCount = nrSupportedMechanisms;

		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = nrSupportedMechanisms;

	for (int i = 0; i < nrSupportedMechanisms; i ++)
	{
		pMechanismList[i] = supportedMechanisms[i];
	}

	return CKR_OK;
}

// Return more information about a mechanism for a given slot
CK_RV SoftHSM::C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) 
{
	unsigned long rsaMinSize, rsaMaxSize;
	unsigned long dsaMinSize, dsaMaxSize;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	Slot *slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm("RSA");
	if (rsa != NULL)
	{
		rsaMinSize = rsa->getMinKeySize();
		rsaMaxSize = rsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm("DSA");
	if (dsa != NULL)
	{
		dsaMinSize = dsa->getMinKeySize();
		// Limitation in PKCS#11
		if (dsaMinSize < 512)
		{
			dsaMinSize = 512;
		}

		dsaMaxSize = dsa->getMaxKeySize();
		// Limitation in PKCS#11
		if (dsaMaxSize > 1024)
		{
			dsaMaxSize = 1024;
		}
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	switch (type)
	{
		case CKM_MD5:
		case CKM_SHA_1:
		case CKM_SHA256:
		case CKM_SHA512:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_RSA_PKCS:
		case CKM_RSA_X_509:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_MD5_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_DES_KEY_GEN:
		case CKM_DES2_KEY_GEN:
		case CKM_DES3_KEY_GEN:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DES_ECB:
		case CKM_DES_CBC:
		case CKM_DES3_ECB:
		case CKM_DES3_CBC:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_AES_KEY_GEN:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_AES_ECB:
		case CKM_AES_CBC:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_DSA_PARAMETER_GEN:
			pInfo->ulMinKeySize = dsaMinSize;
			pInfo->ulMaxKeySize = dsaMaxSize;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = dsaMinSize;
			pInfo->ulMaxKeySize = dsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_DSA_SHA1:
			pInfo->ulMinKeySize = dsaMinSize;
			pInfo->ulMaxKeySize = dsaMaxSize;
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

	// Check if any session is open with this token.
	if (sessionManager->haveSession(slotID))
	{
		return CKR_SESSION_EXISTS;
	}

	// Check the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_INCORRECT;

	ByteString soPIN(pPin, ulPinLen);

	return slot->initToken(soPIN, pLabel);
}

// Initialise the user PIN
CK_RV SoftHSM::C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// The SO must be logged in
	if (session->getState() != CKS_RW_SO_FUNCTIONS) return CKR_USER_NOT_LOGGED_IN;

	// Get the token
	Token *token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	ByteString userPIN(pPin, ulPinLen);

	return token->initUserPIN(userPIN);
}

// Change the PIN
CK_RV SoftHSM::C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) 
{
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the new PINs
	if (pOldPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pNewPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulNewLen < MIN_PIN_LEN || ulNewLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	ByteString oldPIN(pOldPin, ulOldLen);
	ByteString newPIN(pNewPin, ulNewLen);

	// Get the token
	Token *token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	switch (session->getState())
	{
		case CKS_RW_PUBLIC_SESSION:
		case CKS_RW_USER_FUNCTIONS:
			rv = token->setUserPIN(oldPIN, newPIN);
			break;
		case CKS_RW_SO_FUNCTIONS:
			rv = token->setSOPIN(oldPIN, newPIN);
			break;
		default:
			return CKR_SESSION_READ_ONLY;
	}

	// TODO: Should we keep track of unsuccessful login attempts?

	return rv;
}

// Open a new session to the specified slot
CK_RV SoftHSM::C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot *slot = slotManager->getSlot(slotID);

	return sessionManager->openSession(slot, flags, pApplication, notify, phSession);
}

// Close the given session
CK_RV SoftHSM::C_CloseSession(CK_SESSION_HANDLE hSession) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return sessionManager->closeSession(hSession);
}

// Close all open sessions
CK_RV SoftHSM::C_CloseAllSessions(CK_SLOT_ID slotID) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot *slot = slotManager->getSlot(slotID);

	return sessionManager->closeAllSessions(slot);
}

// Retrieve information about the specified session
CK_RV SoftHSM::C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return sessionManager->getSessionInfo(hSession, pInfo);
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
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	ByteString pin(pPin, ulPinLen);

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token *token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	switch (userType)
	{
		case CKU_SO:
			// There cannot exist a R/O session on this slot
			if (sessionManager->haveROSession(session->getSlot()->getSlotID())) return CKR_SESSION_READ_ONLY_EXISTS;

			// Login
			rv = token->loginSO(pin);
			break;
		case CKU_USER:
			// Login
			rv = token->loginUser(pin);
			break;
		case CKU_CONTEXT_SPECIFIC:
			// TODO: When do we want to use this user type?
			return CKR_OPERATION_NOT_INITIALIZED;
			break;
		default:
			return CKR_USER_TYPE_INVALID;
	}

	// TODO: Should we keep track of unsuccessful login attempts?

	return rv;
}

// Log out of the token in the specified session
CK_RV SoftHSM::C_Logout(CK_SESSION_HANDLE hSession) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token *token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Logout
	token->logout();

	// TODO: Remove private session objects

	// TODO: From PKCS#11: any of the application’s handles to private objects become invalid
	//	 (even if a user is later logged back into the token, those handles remain invalid)

	return CKR_OK;
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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// TODO: Should we lock the session?

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the mechanism
	HashAlgorithm *hash = NULL;
	switch(pMechanism->mechanism) {
		case CKM_MD5:
			hash = CryptoFactory::i()->getHashAlgorithm("md5");
			break;
		case CKM_SHA_1:
			hash = CryptoFactory::i()->getHashAlgorithm("sha1");
			break;
		case CKM_SHA256:
			hash = CryptoFactory::i()->getHashAlgorithm("sha256");
			break;
		case CKM_SHA512:
			hash = CryptoFactory::i()->getHashAlgorithm("sha512");
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	if (hash == NULL) return CKR_MECHANISM_INVALID;

	// Initialize hashing
	if (hash->hashInit() == false)
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return CKR_GENERAL_ERROR;
	}

	session->setOpType(SESSION_OP_DIGEST);
	session->setDigestOp(hash);

	return CKR_OK;
}

// Digest the specified data in a one-pass operation and return the resulting digest
CK_RV SoftHSM::C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// TODO: Should we lock the session?

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Return size
	CK_ULONG size = session->getDigestOp()->getHashSize();
	if (pDigest == NULL_PTR)
	{
		*pulDigestLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDigestLen < size)
	{
		*pulDigestLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Digest the data
	if (session->getDigestOp()->hashUpdate(data) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the digest
	ByteString digest;
	if (session->getDigestOp()->hashFinal(digest) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (digest.size() != size)
	{
		ERROR_MSG("The size of the digest differ from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pDigest, digest.byte_str(), size);
	*pulDigestLen = size;

	session->resetOp();

	return CKR_OK;
}

// Update a running digest operation
CK_RV SoftHSM::C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// TODO: Should we lock the session?

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Get the data
	ByteString data(pPart, ulPartLen);

	// Digest the data
	if (session->getDigestOp()->hashUpdate(data) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

// Update a running digest operation by digesting a secret key with the specified handle
CK_RV SoftHSM::C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) 
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise the digest operation in the specified session and return the digest
CK_RV SoftHSM::C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// TODO: Should we lock the session?

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Return size
	CK_ULONG size = session->getDigestOp()->getHashSize();
	if (pDigest == NULL_PTR)
	{
		*pulDigestLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDigestLen < size)
	{
		*pulDigestLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the digest
	ByteString digest;
	if (session->getDigestOp()->hashFinal(digest) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (digest.size() != size)
	{
		ERROR_MSG("The size of the digest differ from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pDigest, digest.byte_str(), size);
	*pulDigestLen = size;

	session->resetOp();

	return CKR_OK;
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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pPublicKeyTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pPrivateKeyTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phPublicKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phPrivateKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	CK_BBOOL isToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;

	// Extract object information
	for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++)
	{
		switch (pPrivateKeyTemplate[i].type)
		{
			case CKA_TOKEN:
				if (pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isToken = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
				}
				break;
			case CKA_PRIVATE:
				if (pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isPrivate = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
				}
				break;
			default:
				break;
		}
	}

	// Check user credentials
	if (!haveRW(session->getState(), isToken, isPrivate))
	{
		INFO_MSG("User is not authorized");
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Generate keys
	CK_RV rv = CKR_MECHANISM_INVALID;
	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			rv = this->generateRSA(session, pPublicKeyTemplate, ulPublicKeyAttributeCount,
						pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
						phPublicKey, phPrivateKey);
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			rv = this->generateDSA(session, pPublicKeyTemplate, ulPublicKeyAttributeCount,
						pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
						phPublicKey, phPrivateKey);
			break;
		default:
			break;
	}

	return rv;
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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pSeed == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG *rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;

	// Seed the RNG
	ByteString seed(pSeed, ulSeedLen);
	rng->seed(seed);

	return CKR_OK;
}

// Generate the specified amount of random data
CK_RV SoftHSM::C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) 
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pRandomData == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session *session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG *rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;

	// Generate random data
	ByteString randomData;
	if (!rng->generateRandom(randomData, ulRandomLen)) return CKR_GENERAL_ERROR;

	// Return random data
	memcpy(pRandomData, randomData.byte_str(), ulRandomLen);

	return CKR_OK;
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

// Generate an RSA key pair
CK_RV SoftHSM::generateRSA
(
	Session *session,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	AsymmetricKeyPair *kp = NULL;
	RSAParameters p;
	size_t bitLen = 0;
	ByteString exponent("010001");

	// Extract desired key information
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_MODULUS_BITS:
				if (pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_MODULUS_BITS does not have the size of CK_ULONG");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				bitLen = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
				break;
			case CKA_PUBLIC_EXPONENT:
				exponent = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// CKA_MODULUS_BITS must be specified to be able to generate a key pair.
	if (bitLen == 0) {
		INFO_MSG("Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	p.setE(exponent);
	p.setBitLength(bitLen);

	// Generate key pair
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm("RSA");
	if (rsa == NULL) return CKR_GENERAL_ERROR;
	if (!rsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return CKR_GENERAL_ERROR;
	}

	RSAPublicKey *pub = (RSAPublicKey*) kp->getPublicKey();
	RSAPrivateKey *priv = (RSAPrivateKey*) kp->getPrivateKey();

	// TODO: Save keys 

	// Clean up
	rsa->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	return CKR_MECHANISM_INVALID;
}

// Generate an DSA key pair
CK_RV SoftHSM::generateDSA
(
	Session *session,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	AsymmetricKeyPair *kp = NULL;
	DSAParameters p;
	ByteString prime;
	ByteString subprime;
	ByteString generator;

	// Extract desired key information
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_PRIME:
				prime = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_SUBPRIME:
				subprime = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_BASE:
				generator = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (prime.size() == 0 || subprime.size() == 0 || generator.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	p.setP(prime);
	p.setQ(subprime);
	p.setG(generator);

	// Generate key pair
	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm("DSA");
	if (dsa == NULL) return CKR_GENERAL_ERROR;
	if (!dsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return CKR_GENERAL_ERROR;
	}

	DSAPublicKey *pub = (DSAPublicKey*) kp->getPublicKey();
	DSAPrivateKey *priv = (DSAPrivateKey*) kp->getPrivateKey();

	// TODO: Save keys 

	// Clean up
	dsa->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	return CKR_MECHANISM_INVALID;
}
