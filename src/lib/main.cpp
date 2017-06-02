/*
 * Copyright (c)2010 SURFnet bv
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
 * INTERRUPTION)HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE)ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 main.cpp

 This file contains the main entry point to the PKCS #11 library. All it does
 is dispatch calls to the actual implementation and check for fatal exceptions
 on the boundary of the library.
 *****************************************************************************/

// The functions are exported library/DLL entry points
#define CRYPTOKI_EXPORTS

#include "config.h"
#include "log.h"
#include "fatal.h"
#include "cryptoki.h"
#include "SoftHSM.h"

#if defined(__GNUC__) && \
	(__GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3)) || \
	defined(__SUNPRO_C) && __SUNPRO_C >= 0x590
#define PKCS_API __attribute__ ((visibility("default")))
#else
#define PKCS_API
#endif

// PKCS #11 function list
static CK_FUNCTION_LIST functionList =
{
	// Version information
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	// Function pointers
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

// PKCS #11 initialisation function
PKCS_API CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	try
	{
		return SoftHSM::i()->C_Initialize(pInitArgs);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// PKCS #11 finalisation function
PKCS_API CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	try
	{
		return SoftHSM::i()->C_Finalize(pReserved);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about the PKCS #11 module
PKCS_API CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	try
	{
		return SoftHSM::i()->C_GetInfo(pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return the list of PKCS #11 functions
PKCS_API CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	try
	{
		if (ppFunctionList == NULL_PTR) return CKR_ARGUMENTS_BAD;

		*ppFunctionList = &functionList;

		return CKR_OK;
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return a list of available slots
PKCS_API CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	try
	{
		return SoftHSM::i()->C_GetSlotList(tokenPresent, pSlotList, pulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about a slot
PKCS_API CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	try
	{
		return SoftHSM::i()->C_GetSlotInfo(slotID, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about a token in a slot
PKCS_API CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	try
	{
		return SoftHSM::i()->C_GetTokenInfo(slotID, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return the list of supported mechanisms for a given slot
PKCS_API CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	try
	{
		return SoftHSM::i()->C_GetMechanismList(slotID, pMechanismList, pulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Return more information about a mechanism for a given slot
PKCS_API CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	try
	{
		return SoftHSM::i()->C_GetMechanismInfo(slotID, type, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise the token in the specified slot
PKCS_API CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	try
	{
		return SoftHSM::i()->C_InitToken(slotID, pPin, ulPinLen, pLabel);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise the user PIN
PKCS_API CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	try
	{
		return SoftHSM::i()->C_InitPIN(hSession, pPin, ulPinLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Change the PIN
PKCS_API CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	try
	{
		return SoftHSM::i()->C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Open a new session to the specified slot
PKCS_API CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	try
	{
		return SoftHSM::i()->C_OpenSession(slotID, flags, pApplication, notify, phSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Close the given session
PKCS_API CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	try
	{
		return SoftHSM::i()->C_CloseSession(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Close all open sessions
PKCS_API CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	try
	{
		return SoftHSM::i()->C_CloseAllSessions(slotID);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Retrieve information about the specified session
PKCS_API CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	try
	{
		return SoftHSM::i()->C_GetSessionInfo(hSession, pInfo);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Determine the state of a running operation in a session
PKCS_API CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	try
	{
		return SoftHSM::i()->C_GetOperationState(hSession, pOperationState, pulOperationStateLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Set the operation sate in a session
PKCS_API CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	try
	{
		return SoftHSM::i()->C_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Login on the token in the specified session
PKCS_API CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	try
	{
		return SoftHSM::i()->C_Login(hSession, userType, pPin, ulPinLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Log out of the token in the specified session
PKCS_API CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	try
	{
		return SoftHSM::i()->C_Logout(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Create a new object on the token in the specified session using the given attribute template
PKCS_API CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	try
	{
		return SoftHSM::i()->C_CreateObject(hSession, pTemplate, ulCount, phObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Create a copy of the object with the specified handle
PKCS_API CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	try
	{
		return SoftHSM::i()->C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Destroy the specified object
PKCS_API CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return SoftHSM::i()->C_DestroyObject(hSession, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Determine the size of the specified object
PKCS_API CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	try
	{
		return SoftHSM::i()->C_GetObjectSize(hSession, hObject, pulSize);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Retrieve the specified attributes for the given object
PKCS_API CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
		return SoftHSM::i()->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Change or set the value of the specified attributes on the specified object
PKCS_API CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
		return SoftHSM::i()->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise object search in the specified session using the specified attribute template as search parameters
PKCS_API CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
		return SoftHSM::i()->C_FindObjectsInit(hSession, pTemplate, ulCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Continue the search for objects in the specified session
PKCS_API CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	try
	{
		return SoftHSM::i()->C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finish searching for objects
PKCS_API CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	try
	{
		return SoftHSM::i()->C_FindObjectsFinal(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise encryption using the specified object and mechanism
PKCS_API CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return SoftHSM::i()->C_EncryptInit(hSession, pMechanism, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single operation encryption operation in the specified session
PKCS_API CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
		return SoftHSM::i()->C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Feed data to the running encryption operation in a session
PKCS_API CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
		return SoftHSM::i()->C_EncryptUpdate(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the encryption operation
PKCS_API CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
		return SoftHSM::i()->C_EncryptFinal(hSession, pEncryptedData, pulEncryptedDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise decryption using the specified object
PKCS_API CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return SoftHSM::i()->C_DecryptInit(hSession, pMechanism, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single operation decryption in the given session
PKCS_API CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	try
	{
		return SoftHSM::i()->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Feed data to the running decryption operation in a session
PKCS_API CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	try
	{
		return SoftHSM::i()->C_DecryptUpdate(hSession, pEncryptedData, ulEncryptedDataLen, pData, pDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the decryption operation
PKCS_API CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	try
	{
		return SoftHSM::i()->C_DecryptFinal(hSession, pData, pDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise digesting using the specified mechanism in the specified session
PKCS_API CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	try
	{
		return SoftHSM::i()->C_DigestInit(hSession, pMechanism);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Digest the specified data in a one-pass operation and return the resulting digest
PKCS_API CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	try
	{
		return SoftHSM::i()->C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running digest operation
PKCS_API CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
		return SoftHSM::i()->C_DigestUpdate(hSession, pPart, ulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running digest operation by digesting a secret key with the specified handle
PKCS_API CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	try
	{
		return SoftHSM::i()->C_DigestKey(hSession, hObject);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the digest operation in the specified session and return the digest
PKCS_API CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	try
	{
		return SoftHSM::i()->C_DigestFinal(hSession, pDigest, pulDigestLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a signing operation using the specified key and mechanism
PKCS_API CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return SoftHSM::i()->C_SignInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Sign the data in a single pass operation
PKCS_API CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
		return SoftHSM::i()->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running signing operation with additional data
PKCS_API CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
		return SoftHSM::i()->C_SignUpdate(hSession, pPart, ulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise a running signing operation and return the signature
PKCS_API CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
		return SoftHSM::i()->C_SignFinal(hSession, pSignature, pulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a signing operation that allows recovery of the signed data
PKCS_API CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return SoftHSM::i()->C_SignRecoverInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single part signing operation that allows recovery of the signed data
PKCS_API CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
		return SoftHSM::i()->C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a verification operation using the specified key and mechanism
PKCS_API CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return SoftHSM::i()->C_VerifyInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single pass verification operation
PKCS_API CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	try
	{
		return SoftHSM::i()->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running verification operation with additional data
PKCS_API CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
		return SoftHSM::i()->C_VerifyUpdate(hSession, pPart, ulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the verification operation and check the signature
PKCS_API CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	try
	{
		return SoftHSM::i()->C_VerifyFinal(hSession, pSignature, ulSignatureLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a verification operation the allows recovery of the signed data from the signature
PKCS_API CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
		return SoftHSM::i()->C_VerifyRecoverInit(hSession, pMechanism, hKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single part verification operation and recover the signed data
PKCS_API CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	try
	{
		return SoftHSM::i()->C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part encryption and digesting operation
PKCS_API CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	try
	{
		return SoftHSM::i()->C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part decryption and digesting operation
PKCS_API CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
{
	try
	{
		return SoftHSM::i()->C_DecryptDigestUpdate(hSession, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part signing and encryption operation
PKCS_API CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	try
	{
		return SoftHSM::i()->C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part decryption and verification operation
PKCS_API CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	try
	{
		return SoftHSM::i()->C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Generate a secret key using the specified mechanism
PKCS_API CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	try
	{
		return SoftHSM::i()->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Generate a key-pair using the specified mechanism
PKCS_API CK_RV C_GenerateKeyPair
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
	try
	{
		return SoftHSM::i()->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Wrap the specified key using the specified wrapping key and mechanism
PKCS_API CK_RV C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hWrappingKey, 
	CK_OBJECT_HANDLE hKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	try
	{
		return SoftHSM::i()->C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Unwrap the specified key using the specified unwrapping key
PKCS_API CK_RV C_UnwrapKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hUnwrappingKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
)
{
	try
	{
		return SoftHSM::i()->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulCount, phKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Derive a key from the specified base key
PKCS_API CK_RV C_DeriveKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hBaseKey, 
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
)
{
	try
	{
		return SoftHSM::i()->C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Seed the random number generator with new data
PKCS_API CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	try
	{
		return SoftHSM::i()->C_SeedRandom(hSession, pSeed, ulSeedLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Generate the specified amount of random data
PKCS_API CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
	try
	{
		return SoftHSM::i()->C_GenerateRandom(hSession, pRandomData, ulRandomLen);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Legacy function
PKCS_API CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	try
	{
		return SoftHSM::i()->C_GetFunctionStatus(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Legacy function
PKCS_API CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	try
	{
		return SoftHSM::i()->C_CancelFunction(hSession);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

// Wait or poll for a slot even on the specified slot
PKCS_API CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	try
	{
		return SoftHSM::i()->C_WaitForSlotEvent(flags, pSlot, pReserved);
	}
	catch (...)
	{
		FatalException();
	}

	return CKR_FUNCTION_FAILED;
}

