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
 main.cpp

 This file contains the main entry point to the PKCS #11 library. All it does
 is dispatch calls to the actual implementation and check for fatal exceptions
 on the boundary of the library.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "fatal.h"
#include "cryptoki.h"
#include "SoftHSM.h"

// PKCS #11 function list
//
// TODO: contrary to the SoftHSM v2 requirements, PKCS #11 v2.20 is still
//       implemented in stead of PKCS #11 v2.30 because the header files
//       for PKCS #11 v2.30 are not yet available
const CK_FUNCTION_LIST functionList = 
{
	// Version information
	{ 2, 20 },
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
CK_RV C_Initialize(CK_VOID_PTR pInitArgs) 
{
}

// PKCS #11 finalisation function
CK_RV C_Finalize(CK_VOID_PTR pReserved) 
{
}

// Return information about the PKCS #11 module
CK_RV C_GetInfo(CK_INFO_PTR pInfo) 
{
}

// Return the list of PKCS #11 functions
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) 
{
	try
	{
		*ppFunctionList = &functionList;
	}
	catch (...)
	{
		FatalException();
	}
}

// Return a list of available slots
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) 
{
}

// Return information about a slot
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) 
{
}

// Return information about a token in a slot
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) 
{
}

// Return the list of supported mechanisms for a given slot
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) 
{
}

// Return more information about a mechanism for a given slot
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) 
{
}

// Initialise the token in the specified slot
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) 
{
}

// Initialise the user PIN
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) 
{
}

// Change the PIN
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) 
{
}

// Open a new session to the specified slot
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) 
{
}

// Close the given session
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) 
{
}

// Close all open sessions
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) 
{
}

// Retrieve information about the specified session
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) 
{
}

// Determine the state of a running operation in a session
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) 
{
}

// Set the operation sate in a session
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) 
{
}

// Login on the token in the specified session
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) 
{
}

// Log out of the token in the specified session
CK_RV C_Logout(CK_SESSION_HANDLE hSession) 
{
}

// Create a new object on the token in the specified session using the given attribute template
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) 
{
}

// Create a copy of the object with the specified handle
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) 
{
}

// Destroy the specified object
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) 
{
}

// Determine the size of the specified object
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) 
{
}

// Retrieve the specified attributes for the given object
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
}

// Change or set the value of the specified attributes on the specified object
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
}

// Initialise object search in the specified session using the specified attribute template as search parameters
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
}

// Continue the search for objects in the specified session
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) 
{
}

// Finish searching for objects
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) 
{
}

// Initialise encryption using the specified object and mechanism
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject) 
{
}

// Perform a single operation encryption operation in the specified session
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) 
{
}

// Feed data to the running encryption operation in a session
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) 
{
}

// Finalise the encryption operation
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) 
{
}

// Initialise decryption using the specified object
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject) 
{
}

// Perform a single operation decryption in the given session
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) 
{
}

// Feed data to the running decryption operation in a session
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) 
{
}

// Finalise the decryption operation
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) 
{
}

// Initialise digesting using the specified mechanism in the specified session
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) 
{
}

// Digest the specified data in a one-pass operation and return the resulting digest
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) 
{
}

// Update a running digest operation
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) 
{
}

// Update a running digest operation by digesting a secret key with the specified handle
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) 
{
}

// Finalise the digest operation in the specified session and return the digest
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) 
{
}

// Initialise a signing operation using the specified key and mechanism
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
}

// Sign the data in a single pass operation
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) 
{
}

// Update a running signing operation with additional data
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) 
{
}

// Finalise a running signing operation and return the signature
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) 
{
}

// Initialise a signing operation that allows recovery of the signed data
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
}

// Perform a single part signing operation that allows recovery of the signed data
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) 
{
}

// Initialise a verification operation using the specified key and mechanism
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
}

// Perform a single pass verification operation
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) 
{
}

// Update a running verification operation with additional data
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) 
{
}

// Finalise the verification operation and check the signature
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) 
{
}

// Initialise a verification operation the allows recovery of the signed data from the signature
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) 
{
}

// Perform a single part verification operation and recover the signed data
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
}

// Update a running multi-part encryption and digesting operation
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) 
{
}

// Update a running multi-part decryption and digesting operation
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
{
}

// Update a running multi-part signing and encryption operation
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) 
{
}

// Update a running multi-part decryption and verification operation
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
}

// Generate a secret key using the specified mechanism
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) 
{
}

// Generate a key-pair using the specified mechanism
CK_RV C_GenerateKeyPair
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
}

// Wrap the specified key using the specified wrapping key and mechanism
CK_RV C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hWrappingKey, 
	CK_OBJECT_HANDLE hKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG_PTR pulWrappedKeyLen
) 
{
}

// Unwrap the specified key using the specified unwrapping key
CK_RV C_UnwrapKey
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
}

// Derive a key from the specified base key
CK_RV C_DeriveKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hBaseKey, 
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
) 
{
}

// Seed the random number generator with new data
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) 
{
}

// Generate the specified amount of random data
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) 
{
}

// Legacy function
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) 
{
}

// Legacy function
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) 
{
}

// Wait or poll for a slot even on the specified slot
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
}

