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
#include "SymmetricAlgorithm.h"
#include "AESKey.h"
#include "DESKey.h"
#include "RNG.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAParameters.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "ECParameters.h"
#include "DHParameters.h"
#include "DHPublicKey.h"
#include "DHPrivateKey.h"
#include "GOSTPublicKey.h"
#include "GOSTPrivateKey.h"
#include "cryptoki.h"
#include "SoftHSM.h"
#include "osmutex.h"
#include "SessionManager.h"
#include "SessionObjectStore.h"
#include "HandleManager.h"
#include "P11Objects.h"

#include <stdlib.h>

static CK_RV newP11Object(CK_OBJECT_CLASS objClass, CK_KEY_TYPE keyType, CK_CERTIFICATE_TYPE certType, std::auto_ptr< P11Object > &p11object)
{
	switch(objClass) {
		case CKO_DATA:
			p11object.reset( new P11DataObj);
			break;
		case CKO_CERTIFICATE:
			if (certType == CKC_X_509)
				p11object.reset( new P11X509CertificateObj );
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_PUBLIC_KEY:
			if (keyType == CKK_RSA)
				p11object.reset( new P11RSAPublicKeyObj );
			else if (keyType == CKK_DSA)
				p11object.reset( new P11DSAPublicKeyObj );
			else if (keyType == CKK_EC)
				p11object.reset( new P11ECPublicKeyObj );
			else if (keyType == CKK_DH)
				p11object.reset( new P11DHPublicKeyObj );
			else if (keyType == CKK_GOSTR3410)
				p11object.reset( new P11GOSTPublicKeyObj );
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_PRIVATE_KEY:
			// we need to know the type too
			if (keyType == CKK_RSA)
				p11object.reset( new P11RSAPrivateKeyObj );
			else if (keyType == CKK_DSA)
				p11object.reset( new P11DSAPrivateKeyObj );
			else if (keyType == CKK_EC)
				p11object.reset( new P11ECPrivateKeyObj );
			else if (keyType == CKK_DH)
				p11object.reset( new P11DHPrivateKeyObj );
			else if (keyType == CKK_GOSTR3410)
				p11object.reset( new P11GOSTPrivateKeyObj );
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_SECRET_KEY:
			if ((keyType == CKK_GENERIC_SECRET) ||
			    (keyType == CKK_MD5_HMAC) ||
			    (keyType == CKK_SHA_1_HMAC) ||
			    (keyType == CKK_SHA224_HMAC) ||
			    (keyType == CKK_SHA256_HMAC) ||
			    (keyType == CKK_SHA384_HMAC) ||
			    (keyType == CKK_SHA512_HMAC))
			{
				P11GenericSecretKeyObj* key = new P11GenericSecretKeyObj;
				p11object.reset(key);
				key->setKeyType(keyType);
			}
			else if (keyType == CKK_AES)
			{
				p11object.reset( new P11AESSecretKeyObj );
			}
			else if ((keyType == CKK_DES) ||
				 (keyType == CKK_DES2) ||
				 (keyType == CKK_DES3))
			{
				P11DESSecretKeyObj* key = new P11DESSecretKeyObj;
				p11object.reset(key);
				key->setKeyType(keyType);
			}
			else if (keyType == CKK_GOST28147)
			{
				p11object.reset( new P11GOSTSecretKeyObj );
			}
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_DOMAIN_PARAMETERS:
			if (keyType == CKK_DSA)
				p11object.reset( new P11DSADomainObj );
			else if (keyType == CKK_DH)
				p11object.reset( new P11DHDomainObj );
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID; // invalid value for a valid argument
	}
	return CKR_OK;
}

static CK_RV extractObjectInformation(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
									   CK_OBJECT_CLASS &objClass,
									   CK_KEY_TYPE &keyType,
									   CK_CERTIFICATE_TYPE &certType,
									   CK_BBOOL &isToken,
									   CK_BBOOL &isPrivate)
{
	bool bHasClass = false;
	bool bHasKeyType = false;
	bool bHasCertType = false;

	// Extract object information
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
				if (pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS))
				{
					objClass = *(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue;
					bHasClass = true;
				}
				break;
			case CKA_KEY_TYPE:
				if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE))
				{
					keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
					bHasKeyType = true;
				}
				break;
			case CKA_CERTIFICATE_TYPE:
				if (pTemplate[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE))
				{
					certType = *(CK_CERTIFICATE_TYPE*)pTemplate[i].pValue;
					bHasCertType = true;
				}
				break;
			case CKA_TOKEN:
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isToken = *(CK_BBOOL*)pTemplate[i].pValue;
				}
				break;
			case CKA_PRIVATE:
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
				}
				break;
			default:
				break;
		}
	}

	if (!bHasClass)
	{
		return CKR_TEMPLATE_INCOMPLETE;
	}

	bool bKeyTypeRequired = (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY);
	if (bKeyTypeRequired && !bHasKeyType)
	{
		 return CKR_TEMPLATE_INCOMPLETE;
	}

	bool bCertTypeRequired = (objClass == CKO_CERTIFICATE);
	if (bCertTypeRequired && !bHasCertType)
	{
		return CKR_TEMPLATE_INCOMPLETE;
	}

	return CKR_OK;
}

static CK_RV newP11Object(OSObject *object, std::auto_ptr< P11Object > &p11object)
{
	CK_OBJECT_CLASS objClass = object->getAttribute(CKA_CLASS)->getUnsignedLongValue();
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	if (object->attributeExists(CKA_KEY_TYPE))
		keyType = object->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue();
	if (object->attributeExists(CKA_CERTIFICATE_TYPE))
		certType = object->getAttribute(CKA_CERTIFICATE_TYPE)->getUnsignedLongValue();
	CK_RV rv = newP11Object(objClass,keyType,certType,p11object);
	if (rv != CKR_OK)
		return rv;
	if (!p11object->init(object))
		return CKR_GENERAL_ERROR; // something went wrong that shouldn't have.
	return CKR_OK;
}

#ifdef notyet
static CK_ATTRIBUTE bsAttribute(CK_ATTRIBUTE_TYPE type, const ByteString &value)
{
	CK_ATTRIBUTE attr = {type, (CK_VOID_PTR)value.const_byte_str(), value.size() };
	return attr;
}
#endif

static void libcleanup()
{
	SoftHSM::i()->C_Finalize(NULL);
}

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

void SoftHSM::reset()
{
	if (instance.get())
		instance.reset();
}

// Constructor
SoftHSM::SoftHSM()
{
	isInitialised = false;
	sessionObjectStore = NULL;
	objectStore = NULL;
	slotManager = NULL;
	sessionManager = NULL;
	handleManager = NULL;
}

// Destructor
SoftHSM::~SoftHSM()
{
	if (handleManager != NULL) delete handleManager;
	if (sessionManager != NULL) delete sessionManager;
	if (slotManager != NULL) delete slotManager;
	if (objectStore != NULL) delete objectStore;
	if (sessionObjectStore != NULL) delete sessionObjectStore;
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

	sessionObjectStore = new SessionObjectStore();

	// Configure object store storage backend used by all tokens.
	ObjectStoreToken::selectBackend(Configuration::i()->getString("objectstore.backend", DEFAULT_OBJECTSTORE_BACKEND));
	
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

	// Load the handle manager
	handleManager = new HandleManager();

	// Set the state to initialised
	isInitialised = true;

	// Hook cleanup on dlclose() or exit()
	atexit(libcleanup);

	return CKR_OK;
}

// PKCS #11 finalisation function
CK_RV SoftHSM::C_Finalize(CK_VOID_PTR pReserved)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Must be set to NULL_PTR in this version of PKCS#11
	if (pReserved != NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (handleManager != NULL) delete handleManager;
	handleManager = NULL;
	if (sessionManager != NULL) delete sessionManager;
	sessionManager = NULL;
	if (slotManager != NULL) delete slotManager;
	slotManager = NULL;
	if (objectStore != NULL) delete objectStore;
	objectStore = NULL;

	// TODO: What should we finalize?

	isInitialised = false;

	SoftHSM::reset();
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

	Slot* slot = slotManager->getSlot(slotID);
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

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	Token* token = slot->getToken();
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
	CK_ULONG nrSupportedMechanisms = 44;
#ifdef WITH_ECC
	nrSupportedMechanisms += 3;
#endif
#ifdef WITH_GOST
	nrSupportedMechanisms += 5;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
	nrSupportedMechanisms += 1;
#endif
	CK_MECHANISM_TYPE supportedMechanisms[] =
	{
		CKM_MD5,
		CKM_SHA_1,
		CKM_SHA224,
		CKM_SHA256,
		CKM_SHA384,
		CKM_SHA512,
		CKM_MD5_HMAC,
		CKM_SHA_1_HMAC,
		CKM_SHA224_HMAC,
		CKM_SHA256_HMAC,
		CKM_SHA384_HMAC,
		CKM_SHA512_HMAC,
		CKM_RSA_PKCS_KEY_PAIR_GEN,
		CKM_RSA_PKCS,
		CKM_RSA_X_509,
		CKM_MD5_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_RSA_PKCS_OAEP,
		CKM_SHA224_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS,
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
		CKM_AES_KEY_WRAP,
#ifdef HAVE_AES_KEY_WRAP_PAD
		CKM_AES_KEY_WRAP_PAD,
#endif
		CKM_DSA_PARAMETER_GEN,
		CKM_DSA_KEY_PAIR_GEN,
		CKM_DSA,
		CKM_DSA_SHA1,
		CKM_DSA_SHA224,
		CKM_DSA_SHA256,
		CKM_DSA_SHA384,
		CKM_DSA_SHA512,
		CKM_DH_PKCS_KEY_PAIR_GEN,
		CKM_DH_PKCS_PARAMETER_GEN,
		CKM_DH_PKCS_DERIVE,
#ifdef WITH_ECC
		CKM_EC_KEY_PAIR_GEN,
		CKM_ECDSA,
		CKM_ECDH1_DERIVE,
#endif
#ifdef WITH_GOST
		CKM_GOSTR3411,
		CKM_GOSTR3411_HMAC,
		CKM_GOSTR3410_KEY_PAIR_GEN,
		CKM_GOSTR3410,
		CKM_GOSTR3410_WITH_GOSTR3411
#endif
	};

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

	Slot* slot = slotManager->getSlot(slotID);
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

	for (CK_ULONG i = 0; i < nrSupportedMechanisms; i ++)
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
	unsigned long dhMinSize, dhMaxSize;
#ifdef WITH_ECC
	unsigned long ecdsaMinSize, ecdsaMaxSize;
	unsigned long ecdhMinSize, ecdhMaxSize;
#endif

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	Slot* slot = slotManager->getSlot(slotID);
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

	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm("DH");
	if (dh != NULL)
	{
		dhMinSize = dh->getMinKeySize();
		dhMaxSize = dh->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

#ifdef WITH_ECC
	AsymmetricAlgorithm* ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm("ECDSA");
	if (ecdsa != NULL)
	{
		ecdsaMinSize = ecdsa->getMinKeySize();
		ecdsaMaxSize = ecdsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);

	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm("ECDH");
	if (ecdh != NULL)
	{
		ecdhMinSize = ecdh->getMinKeySize();
		ecdhMaxSize = ecdh->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
#endif

	switch (type)
	{
		case CKM_MD5:
		case CKM_SHA_1:
		case CKM_SHA224:
		case CKM_SHA256:
		case CKM_SHA384:
		case CKM_SHA512:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;
		case CKM_MD5_HMAC:
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
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
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
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
		case CKM_AES_KEY_WRAP:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 0x80000000;
			pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			pInfo->ulMinKeySize = 1;
			pInfo->ulMaxKeySize = 0x80000000;
			pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#endif
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
		case CKM_DSA:
		case CKM_DSA_SHA1:
		case CKM_DSA_SHA224:
		case CKM_DSA_SHA256:
		case CKM_DSA_SHA384:
		case CKM_DSA_SHA512:
			pInfo->ulMinKeySize = dsaMinSize;
			pInfo->ulMaxKeySize = dsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = dhMinSize;
			pInfo->ulMaxKeySize = dhMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_DH_PKCS_PARAMETER_GEN:
			pInfo->ulMinKeySize = dhMinSize;
			pInfo->ulMaxKeySize = dhMaxSize;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DH_PKCS_DERIVE:
			pInfo->ulMinKeySize = dhMinSize;
			pInfo->ulMaxKeySize = dhMaxSize;
			pInfo->flags = CKF_DERIVE;
			break;
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = ecdsaMinSize;
			pInfo->ulMaxKeySize = ecdsaMaxSize;
#define CKF_EC_COMMOM	(CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)
			pInfo->flags = CKF_GENERATE_KEY_PAIR | CKF_EC_COMMOM;
			break;
		case CKM_ECDSA:
			pInfo->ulMinKeySize = ecdsaMinSize;
			pInfo->ulMaxKeySize = ecdsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_EC_COMMOM;
			break;
		case CKM_ECDH1_DERIVE:
			pInfo->ulMinKeySize = ecdhMinSize;
			pInfo->ulMaxKeySize = ecdhMaxSize;
			pInfo->flags = CKF_DERIVE;
			break;
#endif
#ifdef WITH_GOST
		case CKM_GOSTR3411:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;
		case CKM_GOSTR3411_HMAC:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_GOSTR3410_KEY_PAIR_GEN:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_GOSTR3410:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_GOSTR3410_WITH_GOSTR3411:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
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

	Slot* slot = slotManager->getSlot(slotID);
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
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// The SO must be logged in
	if (session->getState() != CKS_RW_SO_FUNCTIONS) return CKR_USER_NOT_LOGGED_IN;

	// Get the token
	Token* token = session->getToken();
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
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the new PINs
	if (pOldPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pNewPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulNewLen < MIN_PIN_LEN || ulNewLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	ByteString oldPIN(pOldPin, ulOldLen);
	ByteString newPIN(pNewPin, ulNewLen);

	// Get the token
	Token* token = session->getToken();
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

	return rv;
}

// Open a new session to the specified slot
CK_RV SoftHSM::C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot* slot = slotManager->getSlot(slotID);

	CK_RV rv = sessionManager->openSession(slot, flags, pApplication, notify, phSession);
	if (rv != CKR_OK)
		return rv;

	// Get a pointer to the session object and store it in the handle manager.
	Session* session = sessionManager->getSession(*phSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	*phSession = handleManager->addSession(slotID,session);

	return CKR_OK;
}

// Close the given session
CK_RV SoftHSM::C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Tell the handle manager the session has been closed.
	handleManager->sessionClosed(hSession);


	// Tell the session object store that the session has closed.
	sessionObjectStore->sessionClosed(hSession);

	// Tell the session manager the session has been closed.
	return sessionManager->closeSession(session->getHandle());
}

// Close all open sessions
CK_RV SoftHSM::C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the slot
	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL) return CKR_SLOT_ID_INVALID;

	// Get the token
	Token* token = slot->getToken();
	if (token == NULL) return CKR_TOKEN_NOT_PRESENT;

	// Tell the handle manager all sessions were closed for the given slotID.
	// The handle manager should then remove all session and object handles for this slot.
	handleManager->allSessionsClosed(slotID);

	// Tell the session object store that all sessions were closed for the given slotID.
	// The session object store should then remove all session objects for this slot.
	sessionObjectStore->allSessionsClosed(slotID);

	// Finally tell the session manager tho close all sessions for the given slot.
	// This will also trigger a logout on the associated token to occur.
	return sessionManager->closeAllSessions(slot);
}

// Retrieve information about the specified session
CK_RV SoftHSM::C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return session->getInfo(pInfo);
}

// Determine the state of a running operation in a session
CK_RV SoftHSM::C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pOperationState*/, CK_ULONG_PTR /*pulOperationStateLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Set the operation sate in a session
CK_RV SoftHSM::C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pOperationState*/, CK_ULONG /*ulOperationStateLen*/, CK_OBJECT_HANDLE /*hEncryptionKey*/, CK_OBJECT_HANDLE /*hAuthenticationKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Login on the token in the specified session
CK_RV SoftHSM::C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	ByteString pin(pPin, ulPinLen);

	// Get the token
	Token* token = session->getToken();
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

	return rv;
}

// Log out of the token in the specified session
CK_RV SoftHSM::C_Logout(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Logout
	token->logout();

	// [PKCS#11 v2.3 p124] When logout is successful...
	// a. Any of the application's handles to private objects become invalid.
	// b. Even if a user is later logged back into the token those handles remain invalid.
	// c. All private session objects from sessions belonging to the application area destroyed.

	// Have the handle manager remove all handles pointing to private objects for this slot.
	CK_SLOT_ID slotID = session->getSlot()->getSlotID();
	handleManager->tokenLoggedOut(slotID);
	sessionObjectStore->tokenLoggedOut(slotID);

	return CKR_OK;
}

// Create a new object on the token in the specified session using the given attribute template
CK_RV SoftHSM::C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	return this->CreateObject(hSession,pTemplate,ulCount,phObject,OBJECT_OP_CREATE);
}

// Create a copy of the object with the specified handle
CK_RV SoftHSM::C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phNewObject == NULL_PTR) return CKR_ARGUMENTS_BAD;
	*phNewObject = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL wasToken = object->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL wasPrivate = object->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), wasToken, wasPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check if the object is copyable
	CK_BBOOL isCopyable = true;
	if (object->attributeExists(CKA_COPYABLE))
		isCopyable = object->getAttribute(CKA_COPYABLE)->getBooleanValue();
	if (!isCopyable) return CKR_COPY_PROHIBITED;

	// Extract critical information from the template
	CK_BBOOL isToken = wasToken;
	CK_BBOOL isPrivate = wasPrivate;
	
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		if ((pTemplate[i].type == CKA_TOKEN) && (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)))
		{
			isToken = *(CK_BBOOL*)pTemplate[i].pValue;
			continue;
		}
		if ((pTemplate[i].type == CKA_PRIVATE) && (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)))
		{
			isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
			continue;
		}
	}

	// Check privacy does not downgrade
	if (wasPrivate && !isPrivate) return CKR_TEMPLATE_INCONSISTENT;

	// Check write user credentials
	rv = haveWrite(session->getState(), isToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Create the object in session or on the token
	OSObject *newobject = NULL_PTR;
	if (isToken)
	{
		newobject = (OSObject*) token->createObject();
	}
	else
	{
		newobject = sessionObjectStore->createObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE);
	}
	if (newobject == NULL) return CKR_GENERAL_ERROR;

	// Copy attributes from object class (CKA_CLASS=0 so the first)
	if (!newobject->startTransaction())
	{
		newobject->destroyObject();
		return CKR_FUNCTION_FAILED;
	}

	CK_ATTRIBUTE_TYPE attrType = CKA_CLASS;
	do
	{
		OSAttribute* attr = object->getAttribute(attrType);
		// Upgrade privacy has to encrypt byte strings
		if (!wasPrivate && isPrivate &&
		    attr->isByteStringAttribute() &&
		    attr->getByteStringValue().size() != 0)
		{
			ByteString value;
			if (!token->encrypt(attr->getByteStringValue(), value) ||
			    !newobject->setAttribute(attrType, value))
			{
				rv = CKR_FUNCTION_FAILED;
				break;
			}
				
		}
		else
		{
			if (!newobject->setAttribute(attrType, *attr))
			{
				rv = CKR_FUNCTION_FAILED;
				break;
			}
		}
		attrType = object->nextAttributeType(attrType);
	}
	while (attrType != CKA_CLASS);

	if (rv != CKR_OK)
	{
		newobject->abortTransaction();
	}
	else if (!newobject->commitTransaction())
	{
		rv = CKR_FUNCTION_FAILED;
	}

	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Get the new P11 object
	std::auto_ptr< P11Object > newp11object;
	rv = newP11Object(newobject,newp11object);
	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Apply the template
	rv = newp11object->saveTemplate(token, isPrivate != CK_FALSE, pTemplate, ulCount, OBJECT_OP_COPY);

	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Set handle
	if (isToken)
	{
		*phNewObject = handleManager->addTokenObject(slot->getSlotID(), isPrivate != CK_FALSE, newobject);
	}
	else
	{
		*phNewObject = handleManager->addSessionObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE, newobject);
	}

	return CKR_OK;
}

// Destroy the specified object
CK_RV SoftHSM::C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isToken = object->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL isPrivate = object->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Tell the handleManager to forget about the object.
	handleManager->destroyObject(hObject);

	// Destroy the object
	if (!object->destroyObject())
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

// Determine the size of the specified object
CK_RV SoftHSM::C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulSize == NULL) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	*pulSize = CK_UNAVAILABLE_INFORMATION;

	return CKR_OK;
}

// Retrieve the specified attributes for the given object
CK_RV SoftHSM::C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Wrap a P11Object around the OSObject so we can access the attributes in the
	// context of the object in which it is defined.
	std::auto_ptr< P11Object > p11object;
	CK_RV rv = newP11Object(object,p11object);
	if (rv != CKR_OK)
		return rv;

	// Ask the P11Object to fill the template with attribute values.
	return p11object->loadTemplate(token, pTemplate,ulCount);
}

// Change or set the value of the specified attributes on the specified object
CK_RV SoftHSM::C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isToken = object->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL isPrivate = object->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Wrap a P11Object around the OSObject so we can access the attributes in the
	// context of the object in which it is defined.
	std::auto_ptr< P11Object > p11object;
	rv = newP11Object(object,p11object);
	if (rv != CKR_OK)
		return rv;

	// Ask the P11Object to save the template with attribute values.
	return p11object->saveTemplate(token, isPrivate != CK_FALSE, pTemplate,ulCount,OBJECT_OP_SET);
}

// Initialise object search in the specified session using the specified attribute template as search parameters
CK_RV SoftHSM::C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Determine whether we have a public session or not.
	bool isPublicSession;
	switch (session->getState()) {
		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:
		case CKS_RW_SO_FUNCTIONS:
			isPublicSession = false;
			break;
		default:
			isPublicSession = true;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	session->setOpType(SESSION_OP_FIND);
	FindOperation *findOp = FindOperation::create();

	// Check if we are out of memory
	if (findOp == NULL_PTR) return CKR_HOST_MEMORY;

	std::set<OSObject*> allObjects;
	token->getObjects(allObjects);
	sessionObjectStore->getObjects(slot->getSlotID(),allObjects);

	std::set<CK_OBJECT_HANDLE> handles;
	std::set<OSObject*>::iterator it;
	for (it=allObjects.begin(); it != allObjects.end(); ++it)
	{

		// Determine if the object has CKA_PRIVATE set to CK_TRUE
		bool isPrivateObject;
		OSAttribute *attr = (*it)->getAttribute(CKA_PRIVATE);
		if (attr == NULL_PTR || !attr->isBooleanAttribute())
		{
			// This attribute does not exist or is of an incompatible type
			return CKR_GENERAL_ERROR;
		}
		isPrivateObject = attr->getBooleanValue();

		// If the object is private, and we are in a public session then skip it !
		if (isPublicSession && isPrivateObject)
			continue; // skip object

		// Perform the actual attribute matching.
		bool bAttrMatch = true; // We let an empty template match everything.
		for (CK_ULONG i=0; i<ulCount; ++i)
		{
			bAttrMatch = false;

			OSAttribute *attr = (*it)->getAttribute(pTemplate[i].type);
			if (attr == NULL_PTR)
				break;

			if (attr->isBooleanAttribute())
			{
				if (sizeof(CK_BBOOL) != pTemplate[i].ulValueLen)
					break;
				bool bTemplateValue = (*(CK_BBOOL*)pTemplate[i].pValue == CK_TRUE);
				if (attr->getBooleanValue() != bTemplateValue)
					break;
			}
			else
			{
				if (attr->isUnsignedLongAttribute())
				{
					if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
						break;
					CK_ULONG ulTemplateValue = *(CK_ULONG_PTR)pTemplate[i].pValue;
					if (attr->getUnsignedLongValue() != ulTemplateValue)
						break;
				}
				else
				{
					if (attr->isByteStringAttribute())
					{
						ByteString bsAttrValue;
						if (isPrivateObject && attr->getByteStringValue().size() != 0)
						{
							if (!token->decrypt(attr->getByteStringValue(), bsAttrValue))
								return CKR_GENERAL_ERROR;
						}
						else
							bsAttrValue = attr->getByteStringValue();

						if (bsAttrValue.size() != pTemplate[i].ulValueLen)
							break;
						if (pTemplate[i].ulValueLen != 0)
						{
							ByteString bsTemplateValue((const unsigned char*)pTemplate[i].pValue, pTemplate[i].ulValueLen);
							if (bsAttrValue != bsTemplateValue)
								break;
						}
					}
					else
						break;
				}
			}
			// The attribute matched !
			bAttrMatch = true;
		}

		if (bAttrMatch)
		{
			CK_SLOT_ID slotID = slot->getSlotID();
			bool isToken = (*it)->getAttribute(CKA_TOKEN)->getBooleanValue();
			bool isPrivate = (*it)->getAttribute(CKA_PRIVATE)->getBooleanValue();
			// Create an object handle for every returned object.
			CK_OBJECT_HANDLE hObject;
			if (isToken)
				hObject = handleManager->addTokenObject(slotID,isPrivate,*it);
			else
				hObject = handleManager->addSessionObject(slotID,hSession,isPrivate,*it);
			if (hObject == CK_INVALID_HANDLE)
				return CKR_GENERAL_ERROR;
			handles.insert(hObject);
		}
	}

	// Storing the object handles for the find will protect the library
	// whenever a stale object handle is used to access the library.
	findOp->setHandles(handles);

	session->setFindOp(findOp);

	return CKR_OK;
}

// Continue the search for objects in the specified session
CK_RV SoftHSM::C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (phObject == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulObjectCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_FIND) return CKR_OPERATION_NOT_INITIALIZED;

	// return the object handles that have been added to the find operation.
	FindOperation *findOp = session->getFindOp();
	if (findOp == NULL) return CKR_GENERAL_ERROR;

	// Ask the find operation to retrieve the object handles
	*pulObjectCount = findOp->retrieveHandles(phObject,ulMaxObjectCount);

	// Erase the object handles from the find operation.
	findOp->eraseHandles(0,*pulObjectCount);

	return CKR_OK;
}

// Finish searching for objects
CK_RV SoftHSM::C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_FIND) return CKR_OPERATION_NOT_INITIALIZED;

	session->resetOp();
	return CKR_OK;
}

// Encrypt*/Decrypt*() is for Symmetrical ciphers too
static bool isSymMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
		case CKM_DES_ECB:
		case CKM_DES_CBC:
		case CKM_DES3_ECB:
		case CKM_DES3_CBC:
		case CKM_AES_ECB:
		case CKM_AES_CBC:
			return true;
		default:
			return false;
	}
}

// SymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::SymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for encryption
        if (!key->attributeExists(CKA_ENCRYPT) || key->getAttribute(CKA_ENCRYPT)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the symmetric algorithm matching the mechanism
	SymmetricAlgorithm* cipher = NULL;
	std::string mode;
	ByteString iv;
	size_t bb = 8;
	switch(pMechanism->mechanism) {
		case CKM_DES_ECB:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("des");
			mode = "ecb";
			bb = 7;
			break;
		case CKM_DES_CBC:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("des");
			mode = "cbc";
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_DES3_ECB:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("3des");
			mode = "ecb";
			bb = 7;
			break;
		case CKM_DES3_CBC:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("3des");
			mode = "cbc";
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_AES_ECB:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "ecb";
			break;
		case CKM_AES_CBC:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "cbc";
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();
	if (secretkey == NULL)
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize encryption
	if (!cipher->encryptInit(secretkey, mode, iv, false))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::AsymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for encryption
        if (!key->attributeExists(CKA_ENCRYPT) || key->getAttribute(CKA_ENCRYPT)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the asymmetric algorithm matching the mechanism
	const char *mechanism;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = "rsa-pkcs";
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = "rsa-raw";
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
			{
				DEBUG_MSG("pParameter must be of type CK_RSA_PKCS_OAEP_PARAMS");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_RSA_PKCS_OAEP_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1)
			{
				DEBUG_MSG("hashAlg must be CKM_SHA_1");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_RSA_PKCS_OAEP_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				DEBUG_MSG("mgf must be CKG_MGF1_SHA1");
				return CKR_ARGUMENTS_BAD;
			}

			mechanism = "rsa-pkcs-oaep";
			isRSA = true;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PublicKey* publicKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("rsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Initialise encryption using the specified object and mechanism
CK_RV SoftHSM::C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isSymMechanism(pMechanism))
		return SymEncryptInit(hSession, pMechanism, hKey);
	else
		return AsymEncryptInit(hSession, pMechanism, hKey);
}

// SymAlgorithm version of C_Encrypt
static CK_RV SymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	if (ulDataLen % cipher->getBlockSize() != 0)
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = ulDataLen;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < ulDataLen)
	{
		*pulEncryptedDataLen = ulDataLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);
	ByteString encryptedData;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, encryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	encryptedData += encryptedFinal;
	encryptedData.resize(ulDataLen);

	memcpy(pEncryptedData, encryptedData.byte_str(), encryptedData.size());
	*pulEncryptedDataLen = encryptedData.size();

	session->resetOp();
	return CKR_OK;
}

// AsymAlgorithm version of C_Encrypt
static CK_RV AsymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	const char *mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || mechanism == NULL || !session->getAllowSinglePartOp() || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the encrypted data
	CK_ULONG size = publicKey->getOutputLength();

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < size)
	{
		*pulEncryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;
	ByteString encryptedData;

	// PKCS #11 Mechanisms v2.30: Cryptoki Draft 7 page 32
	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (strcmp(mechanism,"rsa-raw") == 0) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);

	// Encrypt the data
	if (!asymCrypto->encrypt(publicKey,data,encryptedData,mechanism))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (encryptedData.size() != size)
	{
		ERROR_MSG("The size of the encrypted data differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pEncryptedData, encryptedData.byte_str(), size);
	*pulEncryptedDataLen = size;

	session->resetOp();
	return CKR_OK;
}

// Perform a single operation encryption operation in the specified session
CK_RV SoftHSM::C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulEncryptedDataLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymEncrypt(session, pData, ulDataLen,
				  pEncryptedData, pulEncryptedDataLen);
	else
		return AsymEncrypt(session, pData, ulDataLen,
				   pEncryptedData, pulEncryptedDataLen);
}

// Feed data to the running encryption operation in a session
CK_RV SoftHSM::C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pData*/, CK_ULONG /*ulDataLen*/, CK_BYTE_PTR /*pEncryptedData*/, CK_ULONG_PTR /*pulEncryptedDataLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise the encryption operation
CK_RV SoftHSM::C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pEncryptedData*/, CK_ULONG_PTR /*pulEncryptedDataLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT) return CKR_OPERATION_NOT_INITIALIZED;

	session->resetOp();
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// SymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::SymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for decryption
        if (!key->attributeExists(CKA_DECRYPT) || key->getAttribute(CKA_DECRYPT)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the symmetric algorithm matching the mechanism
	SymmetricAlgorithm* cipher = NULL;
	std::string mode;
	ByteString iv;
	size_t bb = 8;
	switch(pMechanism->mechanism) {
		case CKM_DES_ECB:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("des");
			mode = "ecb";
			bb = 7;
			break;
		case CKM_DES_CBC:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("des");
			mode = "cbc";
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_DES3_ECB:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("3des");
			mode = "ecb";
			bb = 7;
			break;
		case CKM_DES3_CBC:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("3des");
			mode = "cbc";
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_AES_ECB:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "ecb";
			break;
		case CKM_AES_CBC:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "cbc";
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();
	if (secretkey == NULL)
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize decryption
	if (!cipher->decryptInit(secretkey, mode, iv, false))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_DECRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::AsymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for decryption
        if (!key->attributeExists(CKA_DECRYPT) || key->getAttribute(CKA_DECRYPT)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the asymmetric algorithm matching the mechanism
	const char *mechanism;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = "rsa-pkcs";
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = "rsa-raw";
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
			{
				DEBUG_MSG("pParameter must be of type CK_RSA_PKCS_OAEP_PARAMS");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_RSA_PKCS_OAEP_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1)
			{
				DEBUG_MSG("hashAlg must be CKM_SHA_1");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_RSA_PKCS_OAEP_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				DEBUG_MSG("mgf must be CKG_MGF1_SHA1");
				return CKR_ARGUMENTS_BAD;
			}

			mechanism = "rsa-pkcs-oaep";
			isRSA = true;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PrivateKey* privateKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("rsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	session->setOpType(SESSION_OP_DECRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Initialise decryption using the specified object
CK_RV SoftHSM::C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isSymMechanism(pMechanism))
		return SymDecryptInit(hSession, pMechanism, hKey);
	else
		return AsymDecryptInit(hSession, pMechanism, hKey);
}

// SymAlgorithm version of C_Decrypt
static CK_RV SymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted size
	if (ulEncryptedDataLen % cipher->getBlockSize() != 0)
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (pData == NULL_PTR)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < ulEncryptedDataLen)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!cipher->decryptUpdate(encryptedData,data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Finalize decryption
	ByteString dataFinal;
	if (!cipher->decryptFinal(dataFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	data += dataFinal;
	data.resize(ulEncryptedDataLen);

	memcpy(pData, data.byte_str(), data.size());
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// AsymAlgorithm version of C_Decrypt
static CK_RV AsymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	const char *mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || mechanism == NULL || !session->getAllowSinglePartOp() || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the data
	CK_ULONG size = privateKey->getOutputLength();
	if (pData == NULL_PTR)
	{
		*pulDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < size)
	{
		*pulDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!asymCrypto->decrypt(privateKey,encryptedData,data,mechanism))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (data.size() > size)
	{
		ERROR_MSG("The size of the decrypted data exceeds the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pData, data.byte_str(), data.size());
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// Perform a single operation decryption in the given session
CK_RV SoftHSM::C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pEncryptedData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulDataLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				  pData, pulDataLen);
	else
		return AsymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				   pData, pulDataLen);
}

// Feed data to the running decryption operation in a session
CK_RV SoftHSM::C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pEncryptedData*/, CK_ULONG /*ulEncryptedDataLen*/, CK_BYTE_PTR /*pData*/, CK_ULONG_PTR /*pDataLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Finalise the decryption operation
CK_RV SoftHSM::C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pData*/, CK_ULONG_PTR /*pDataLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT) return CKR_OPERATION_NOT_INITIALIZED;

	session->resetOp();
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialise digesting using the specified mechanism in the specified session
CK_RV SoftHSM::C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the mechanism
	HashAlgorithm* hash = NULL;
	switch(pMechanism->mechanism) {
		case CKM_MD5:
			hash = CryptoFactory::i()->getHashAlgorithm("md5");
			break;
		case CKM_SHA_1:
			hash = CryptoFactory::i()->getHashAlgorithm("sha1");
			break;
		case CKM_SHA224:
			hash = CryptoFactory::i()->getHashAlgorithm("sha224");
			break;
		case CKM_SHA256:
			hash = CryptoFactory::i()->getHashAlgorithm("sha256");
			break;
		case CKM_SHA384:
			hash = CryptoFactory::i()->getHashAlgorithm("sha384");
			break;
		case CKM_SHA512:
			hash = CryptoFactory::i()->getHashAlgorithm("sha512");
			break;
#ifdef WITH_GOST
		case CKM_GOSTR3411:
			hash = CryptoFactory::i()->getHashAlgorithm("gost");
			break;
#endif
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
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

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
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hObject);
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL isPrivate = key->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Parano...
	if (!key->attributeExists(CKA_EXTRACTABLE) || key->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false)
		return CKR_KEY_INDIGESTIBLE;
	if (key->attributeExists(CKA_SENSITIVE) && key->getAttribute(CKA_SENSITIVE)->getBooleanValue())
		return CKR_KEY_INDIGESTIBLE;

	// Get value
	if (!key->attributeExists(CKA_VALUE))
		return CKR_KEY_INDIGESTIBLE;
	ByteString keybits;
	if (isPrivate)
	{
		if (!token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key->getAttribute(CKA_VALUE)->getByteStringValue();
	}

	// Digest the value
	if (session->getDigestOp()->hashUpdate(keybits) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

// Finalise the digest operation in the specified session and return the digest
CK_RV SoftHSM::C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

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

// Sign*/Verify*() is for MACs too
static bool isMacMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
		case CKM_MD5_HMAC:
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
#ifdef WITH_GOST
		case CKM_GOSTR3411_HMAC:
#endif
			return true;
		default:
			return false;
	}
}

// MacAlgorithm version of C_SignInit
CK_RV SoftHSM::MacSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for signing
        if (!key->attributeExists(CKA_SIGN) || key->getAttribute(CKA_SIGN)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the MAC algorithm matching the mechanism
	MacAlgorithm* mac = NULL;
	switch(pMechanism->mechanism) {
		case CKM_MD5_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-md5");
			break;
		case CKM_SHA_1_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha1");
			break;
		case CKM_SHA224_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha224");
			break;
		case CKM_SHA256_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha256");
			break;
		case CKM_SHA384_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha384");
			break;
		case CKM_SHA512_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha512");
			break;
#ifdef WITH_GOST
		case CKM_GOSTR3411_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-gost");
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* privkey = new SymmetricKey();
	if (privkey == NULL)
	{
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_HOST_MEMORY;
	}

	if (getSymmetricKey(privkey, token, key) != CKR_OK)
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Initialize signing
	if (!mac->signInit(privkey))
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(privkey);

	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignInit
CK_RV SoftHSM::AsymSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for signing
        if (!key->attributeExists(CKA_SIGN) || key->getAttribute(CKA_SIGN)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the asymmetric algorithm matching the mechanism
	const char *mechanism;
	bool bAllowMultiPartOp;
	bool isRSA = false;
	bool isDSA = false;
	bool isECDSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = "rsa-pkcs";
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = "rsa-raw";
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_MD5_RSA_PKCS:
			mechanism = "rsa-md5-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA1_RSA_PKCS:
			mechanism = "rsa-sha1-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = "rsa-sha224-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = "rsa-sha256-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = "rsa-sha384-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = "rsa-sha512-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_DSA:
			mechanism = "dsa";
			bAllowMultiPartOp = false;
			isDSA = true;
			break;
		case CKM_DSA_SHA1:
			mechanism = "dsa-sha1";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA224:
			mechanism = "dsa-sha224";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA256:
			mechanism = "dsa-sha256";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA384:
			mechanism = "dsa-sha384";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA512:
			mechanism = "dsa-sha512";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = "ecdsa";
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
#endif
#ifdef WITH_GOST
		case CKM_GOSTR3410:
			mechanism = "gost";
			bAllowMultiPartOp = false;
			break;
		case CKM_GOSTR3410_WITH_GOSTR3411:
			mechanism = "gost-gost";
			bAllowMultiPartOp = true;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PrivateKey* privateKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("rsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else if (isDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("dsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getDSAPrivateKey((DSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
        }
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("ecdsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPrivateKey((ECPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else
	{
#ifdef WITH_GOST
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("gost");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getGOSTPrivateKey((GOSTPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
#else
		return CKR_MECHANISM_INVALID;
#endif
        }

	// Initialize signing
	if (bAllowMultiPartOp && !asymCrypto->signInit(privateKey,mechanism))
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Initialise a signing operation using the specified key and mechanism
CK_RV SoftHSM::C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isMacMechanism(pMechanism))
		return MacSignInit(hSession, pMechanism, hKey);
	else
		return AsymSignInit(hSession, pMechanism, hKey);
}

// MacAlgorithm version of C_Sign
static CK_RV MacSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Sign the data
	if (!mac->signUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Sign
static CK_RV AsymSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	const char *mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || mechanism == NULL || !session->getAllowSinglePartOp() || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;

	// PKCS #11 Mechanisms v2.30: Cryptoki Draft 7 page 32
	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (strcmp(mechanism,"rsa-raw") == 0) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);
	ByteString signature;

	// Sign the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->signUpdate(data) ||
		    !asymCrypto->signFinal(signature))
		{
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}
	}
	else if (!asymCrypto->sign(privateKey,data,signature,mechanism))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// Sign the data in a single pass operation
CK_RV SoftHSM::C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSign(session, pData, ulDataLen,
			       pSignature, pulSignatureLen);
	else
		return AsymSign(session, pData, ulDataLen,
				pSignature, pulSignatureLen);
}

// MacAlgorithm version of C_SignUpdate
static CK_RV MacSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!mac->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignUpdate
static CK_RV AsymSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!asymCrypto->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running signing operation with additional data
CK_RV SoftHSM::C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSignUpdate(session, pPart, ulPartLen);
	else
		return AsymSignUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignFinal
static CK_RV AsymSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!asymCrypto->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// Finalise a running signing operation and return the signature
CK_RV SoftHSM::C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSignFinal(session, pSignature, pulSignatureLen);
	else
		return AsymSignFinal(session, pSignature, pulSignatureLen);
}

// Initialise a signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pData*/, CK_ULONG /*ulDataLen*/, CK_BYTE_PTR /*pSignature*/, CK_ULONG_PTR /*pulSignatureLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// MacAlgorithm version of C_VerifyInit
CK_RV SoftHSM::MacVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for verifying
        if (!key->attributeExists(CKA_VERIFY) || key->getAttribute(CKA_VERIFY)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the MAC algorithm matching the mechanism
	MacAlgorithm* mac = NULL;
	switch(pMechanism->mechanism) {
		case CKM_MD5_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-md5");
			break;
		case CKM_SHA_1_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha1");
			break;
		case CKM_SHA224_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha224");
			break;
		case CKM_SHA256_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha256");
			break;
		case CKM_SHA384_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha384");
			break;
		case CKM_SHA512_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-sha512");
			break;
#ifdef WITH_GOST
		case CKM_GOSTR3411_HMAC:
			mac = CryptoFactory::i()->getMacAlgorithm("hmac-gost");
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* pubkey = new SymmetricKey();
	if (pubkey == NULL)
	{
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_HOST_MEMORY;
	}

	if (getSymmetricKey(pubkey, token, key) != CKR_OK)
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Initialize verifying
	if (!mac->verifyInit(pubkey))
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(pubkey);

	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyInit
CK_RV SoftHSM::AsymVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	// Check if key can be used for verifying
        if (!key->attributeExists(CKA_VERIFY) || key->getAttribute(CKA_VERIFY)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Get the asymmetric algorithm matching the mechanism
	const char *mechanism;
	bool bAllowMultiPartOp;
	bool isRSA = false;
	bool isDSA = false;
	bool isECDSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = "rsa-pkcs";
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = "rsa-raw";
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_MD5_RSA_PKCS:
			mechanism = "rsa-md5-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA1_RSA_PKCS:
			mechanism = "rsa-sha1-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = "rsa-sha224-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = "rsa-sha256-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = "rsa-sha384-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = "rsa-sha512-pkcs";
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_DSA:
			mechanism = "dsa";
			bAllowMultiPartOp = false;
			isDSA = true;
			break;
		case CKM_DSA_SHA1:
			mechanism = "dsa-sha1";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA224:
			mechanism = "dsa-sha224";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA256:
			mechanism = "dsa-sha256";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA384:
			mechanism = "dsa-sha384";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA512:
			mechanism = "dsa-sha512";
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = "ecdsa";
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
#endif
#ifdef WITH_GOST
		case CKM_GOSTR3410:
			mechanism = "gost";
			bAllowMultiPartOp = false;
			break;
		case CKM_GOSTR3410_WITH_GOSTR3411:
			mechanism = "gost-gost";
			bAllowMultiPartOp = true;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PublicKey* publicKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("rsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else if (isDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("dsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getDSAPublicKey((DSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
        }
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("ecdsa");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPublicKey((ECPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else
	{
#ifdef WITH_GOST
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm("gost");
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getGOSTPublicKey((GOSTPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
#else
		return CKR_MECHANISM_INVALID;
#endif
        }

	// Initialize verifying
	if (bAllowMultiPartOp && !asymCrypto->verifyInit(publicKey,mechanism))
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Initialise a verification operation using the specified key and mechanism
CK_RV SoftHSM::C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isMacMechanism(pMechanism))
		return MacVerifyInit(hSession, pMechanism, hKey);
	else
		return AsymVerifyInit(hSession, pMechanism, hKey);
}

// MacAlgorithm version of C_Verify
static CK_RV MacVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Verify the data
	if (!mac->verifyUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the signature
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Verify
static CK_RV AsymVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	const char *mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || mechanism == NULL || !session->getAllowSinglePartOp() || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString data;

	// PKCS #11 Mechanisms v2.30: Cryptoki Draft 7 page 32
	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (strcmp(mechanism,"rsa-raw") == 0) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->verifyUpdate(data) ||
		    !asymCrypto->verifyFinal(signature))
		{
			session->resetOp();
			return CKR_SIGNATURE_INVALID;
		}
	}
	else if (!asymCrypto->verify(publicKey,data,signature,mechanism))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// Perform a single pass verification operation
CK_RV SoftHSM::C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerify(session, pData, ulDataLen,
				 pSignature, ulSignatureLen);
	else
		return AsymVerify(session, pData, ulDataLen,
				  pSignature, ulSignatureLen);
}

// MacAlgorithm version of C_VerifyUpdate
static CK_RV MacVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!mac->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyUpdate
static CK_RV AsymVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!asymCrypto->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running verification operation with additional data
CK_RV SoftHSM::C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyUpdate(session, pPart, ulPartLen);
	else
		return AsymVerifyUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyFinal
static CK_RV AsymVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!asymCrypto->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// Finalise the verification operation and check the signature
CK_RV SoftHSM::C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyFinal(session, pSignature, ulSignatureLen);
	else
		return AsymVerifyFinal(session, pSignature, ulSignatureLen);
}

// Initialise a verification operation the allows recovery of the signed data from the signature
CK_RV SoftHSM::C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part verification operation and recover the signed data
CK_RV SoftHSM::C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pSignature*/, CK_ULONG /*ulSignatureLen*/, CK_BYTE_PTR /*pData*/, CK_ULONG_PTR /*pulDataLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part encryption and digesting operation
CK_RV SoftHSM::C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG_PTR /*pulEncryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and digesting operation
CK_RV SoftHSM::C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pDecryptedPart*/, CK_ULONG_PTR /*pulDecryptedPartLen*/)
{	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part signing and encryption operation
CK_RV SoftHSM::C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG_PTR /*pulEncryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and verification operation
CK_RV SoftHSM::C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG /*ulEncryptedPartLen*/, CK_BYTE_PTR /*pPart*/, CK_ULONG_PTR /*pulPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generate a secret key or a domain parameter set using the specified mechanism
CK_RV SoftHSM::C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DSA and DH parameters
	// and symmetric ciphers
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	switch (pMechanism->mechanism)
	{
		case CKM_DSA_PARAMETER_GEN:
			objClass = CKO_DOMAIN_PARAMETERS;
			keyType = CKK_DSA;
			break;
		case CKM_DH_PKCS_PARAMETER_GEN:
			objClass = CKO_DOMAIN_PARAMETERS;
			keyType = CKK_DH;
			break;
		case CKM_DES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES;
			break;
		case CKM_DES2_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES2;
			break;
		case CKM_DES3_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES3;
			break;
		case CKM_AES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_AES;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Extract information from the template that is needed to create the object.
	CK_BBOOL isToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isToken, isPrivate);

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_DOMAIN_PARAMETERS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DSA_PARAMETER_GEN &&
	    (objClass != CKO_DOMAIN_PARAMETERS || keyType != CKK_DSA))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DH_PKCS_PARAMETER_GEN &&
	    (objClass != CKO_DOMAIN_PARAMETERS || keyType != CKK_DH))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DES2_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES2))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DES3_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES3))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_AES))
		return CKR_TEMPLATE_INCONSISTENT;

	// Check authorization
	CK_RV rv = haveWrite(session->getState(), isToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Generate DSA domain parameters
	if (pMechanism->mechanism == CKM_DSA_PARAMETER_GEN)
	{
		return this->generateDSAParameters(hSession, pTemplate, ulCount, phKey, isToken, isPrivate);
	}

	// Generate DH domain parameters
	if (pMechanism->mechanism == CKM_DH_PKCS_PARAMETER_GEN)
	{
		return this->generateDHParameters(hSession, pTemplate, ulCount, phKey, isToken, isPrivate);
	}

	// Generate DES secret key
	if (pMechanism->mechanism == CKM_DES_KEY_GEN)
	{
		return this->generateDES(hSession, pTemplate, ulCount, phKey, isToken, isPrivate);
	}

	// Generate DES2 secret key
	if (pMechanism->mechanism == CKM_DES2_KEY_GEN)
	{
		return this->generateDES2(hSession, pTemplate, ulCount, phKey, isToken, isPrivate);
	}

	// Generate DES3 secret key
	if (pMechanism->mechanism == CKM_DES3_KEY_GEN)
	{
		return this->generateDES3(hSession, pTemplate, ulCount, phKey, isToken, isPrivate);
	}

	// Generate AES secret key
	if (pMechanism->mechanism == CKM_AES_KEY_GEN)
	{
		return this->generateAES(hSession, pTemplate, ulCount, phKey, isToken, isPrivate);
	}

	return CKR_GENERAL_ERROR;
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
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept RSA, DSA, EC and DH key pair generation.
	CK_KEY_TYPE keyType;
	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			keyType = CKK_RSA;
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			keyType = CKK_DSA;
			break;
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			keyType = CKK_DH;
			break;
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			keyType = CKK_EC;
			break;
#endif
#ifdef WITH_GOST
		case CKM_GOSTR3410_KEY_PAIR_GEN:
			keyType = CKK_GOSTR3410;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	CK_CERTIFICATE_TYPE dummy;

	// Extract information from the public key template that is needed to create the object.
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL ispublicKeyToken = CK_FALSE;
	CK_BBOOL ispublicKeyPrivate = CK_TRUE;
	extractObjectInformation(pPublicKeyTemplate, ulPublicKeyAttributeCount, publicKeyClass, keyType, dummy, ispublicKeyToken, ispublicKeyPrivate);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (publicKeyClass != CKO_PUBLIC_KEY)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DSA_KEY_PAIR_GEN && keyType != CKK_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN && keyType != CKK_DH)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN && keyType != CKK_GOSTR3410)
		return CKR_TEMPLATE_INCONSISTENT;

	// Extract information from the private key template that is needed to create the object.
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isprivateKeyToken = CK_FALSE;
	CK_BBOOL isprivateKeyPrivate = CK_TRUE;
	extractObjectInformation(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, privateKeyClass, keyType, dummy, isprivateKeyToken, isprivateKeyPrivate);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (privateKeyClass != CKO_PRIVATE_KEY)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DSA_KEY_PAIR_GEN && keyType != CKK_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN && keyType != CKK_DH)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN && keyType != CKK_GOSTR3410)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), ispublicKeyToken || isprivateKeyToken, ispublicKeyPrivate || isprivateKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Generate RSA keys
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
	{
			return this->generateRSA(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate DSA keys
	if (pMechanism->mechanism == CKM_DSA_KEY_PAIR_GEN)
	{
			return this->generateDSA(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate EC keys
	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN)
	{
			return this->generateEC(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate DH keys
	if (pMechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN)
	{
			return this->generateDH(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate GOST keys
	if (pMechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN)
	{
			return this->generateGOST(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	return CKR_GENERAL_ERROR;
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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulWrappedKeyLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept advanced AES key wrapping
	switch(pMechanism->mechanism)
	{
		case CKM_AES_KEY_WRAP:
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
#endif
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the wrapping key handle.
	OSObject *wrapKey = (OSObject *)handleManager->getObject(hWrappingKey);
	if (wrapKey == NULL_PTR || !wrapKey->isValid()) return CKR_WRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isWrapKeyOnToken = wrapKey->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL isWrapKeyPrivate = wrapKey->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check user credentials for the wrapping key
	CK_RV rv = haveWrite(session->getState(), isWrapKeyOnToken, isWrapKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Check wrapping key class and type
	if (wrapKey->getAttribute(CKA_CLASS)->getUnsignedLongValue() != CKO_SECRET_KEY)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP && wrapKey->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue() != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && wrapKey->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue() != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

	// Check if the wrapping key can be used for wrapping
	if (!wrapKey->attributeExists(CKA_WRAP) || wrapKey->getAttribute(CKA_WRAP)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check the to be wrapped key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = key->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL isKeyPrivate = key->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check user credentials for the to be wrapped key
	rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check if the to be wrapped key can be wrapped
	if (!key->attributeExists(CKA_EXTRACTABLE) || key->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false)
		return CKR_KEY_UNEXTRACTABLE;
	if ((key->attributeExists(CKA_WRAP_WITH_TRUSTED) && key->getAttribute(CKA_WRAP_WITH_TRUSTED)->getBooleanValue()) && (!wrapKey->attributeExists(CKA_TRUSTED) || wrapKey->getAttribute(CKA_TRUSTED)->getBooleanValue() == false))
		return CKR_KEY_NOT_WRAPPABLE;
	// If a sensible key may be wrapped, it may be unwrapped as not sensible
	if (key->attributeExists(CKA_SENSITIVE) && key->getAttribute(CKA_SENSITIVE)->getBooleanValue())
		return CKR_KEY_NOT_WRAPPABLE;

	// Check the class
	CK_OBJECT_CLASS keyClass = key->getAttribute(CKA_CLASS)->getUnsignedLongValue();
	if (keyClass != CKO_SECRET_KEY && keyClass != CKO_PRIVATE_KEY)
		return CKR_KEY_NOT_WRAPPABLE;

	// Verify the wrap template attribute
	if (wrapKey->attributeExists(CKA_WRAP_TEMPLATE) && wrapKey->getAttribute(CKA_WRAP_TEMPLATE)->isArrayAttribute())
	{
		typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> array_type;

		const array_type& array = wrapKey->getAttribute(CKA_WRAP_TEMPLATE)->getArrayValue();

		for (array_type::const_iterator it = array.begin(); it != array.end(); ++it)
		{
			if (!key->attributeExists(it->first))
				return CKR_KEY_NOT_WRAPPABLE;
			ByteString v1, v2;
			if (!key->getAttribute(it->first)->peekValue(v1) || !it->second.peekValue(v2) || (v1 != v2))
				return CKR_KEY_NOT_WRAPPABLE;
		}
	}

	// Get the key data to encrypt
	ByteString keydata;
	if (keyClass == CKO_SECRET_KEY)
	{
		if (isKeyPrivate)
		{
			token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), keydata);
		}
		else
		{
			keydata = key->getAttribute(CKA_VALUE)->getByteStringValue();
		}
	}
	else
	{
		CK_KEY_TYPE keyType = key->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue();
		std::string alg = "";
		switch (keyType) {
			case CKK_RSA:
				alg = "rsa";
				break;
			case CKK_DSA:
				alg = "dsa";
				break;
			case CKK_DH:
				alg = "dh";
				break;
#ifdef WITH_ECC
			case CKK_EC:
				// can be ecdh too but it doesn't matter
				alg = "ecdsa";
				break;
#endif
			default:
				return CKR_KEY_NOT_WRAPPABLE;
		}
		AsymmetricAlgorithm* asymCrypto = NULL;
		PrivateKey* privateKey = NULL;
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(alg.c_str());
		if (asymCrypto == NULL)
			return CKR_GENERAL_ERROR;
		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}
		switch (keyType) {
			case CKK_RSA:
				rv = getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key);
				break;
			case CKK_DSA:
				rv = getDSAPrivateKey((DSAPrivateKey*)privateKey, token, key);
				break;
			case CKK_DH:
				rv = getDHPrivateKey((DHPrivateKey*)privateKey, token, key);
				break;
#ifdef WITH_ECC
			case CKK_EC:
				rv = getECPrivateKey((ECPrivateKey*)privateKey, token, key);
				break;
#endif
		}
		if (rv != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
		keydata = privateKey->PKCS8Encode();
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
	}
	if (keydata.size() == 0)
		return CKR_KEY_NOT_WRAPPABLE;

	// Get the symmetric algorithm matching the mechanism
	SymmetricAlgorithm* cipher = NULL;
	std::string mode;
	size_t bb = 8;
	CK_ULONG wrappedlen = keydata.size();
	switch(pMechanism->mechanism) {
		case CKM_AES_KEY_WRAP:
			if ((wrappedlen < 16) || ((wrappedlen % 8) != 0))
				return CKR_KEY_SIZE_RANGE;
			wrappedlen += 8;
			if (pWrappedKey == NULL_PTR)
			{
				*pulWrappedKeyLen = wrappedlen;
				return CKR_OK;
			}
			if (*pulWrappedKeyLen < wrappedlen)
			{
				*pulWrappedKeyLen = wrappedlen;
				return CKR_BUFFER_TOO_SMALL;
			}
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "aes-keywrap";
			break;
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			wrappedlen = ((wrappedlen + 7) / 8 + 1) * 8;
			if (pWrappedKey == NULL_PTR)
			{
				*pulWrappedKeyLen = wrappedlen;
				return CKR_OK;
			}
			if (*pulWrappedKeyLen < wrappedlen)
			{
				*pulWrappedKeyLen = wrappedlen;
				return CKR_BUFFER_TOO_SMALL;
			}
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "aes-keywrap-pad";
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* wrappingkey = new SymmetricKey();
	if (wrappingkey == NULL)
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	if (getSymmetricKey(wrappingkey, token, wrapKey) != CKR_OK)
	{
		cipher->recycleKey(wrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	wrappingkey->setBitLen(wrappingkey->getKeyBits().size() * bb);

	// Wrap the key
	ByteString wrapped;
	if (!cipher->wrapKey(wrappingkey, mode, keydata, wrapped))
	{
		cipher->recycleKey(wrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	cipher->recycleKey(wrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);

	memcpy(pWrappedKey, wrapped.byte_str(), wrapped.size());
	*pulWrappedKeyLen = wrapped.size();

	return CKR_OK;
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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pWrappedKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (hKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept advanced AES key unwrapping
	switch(pMechanism->mechanism)
	{
		case CKM_AES_KEY_WRAP:
			if ((ulWrappedKeyLen < 24) || ((ulWrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			if ((ulWrappedKeyLen < 16) || ((ulWrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the unwrapping key handle.
	OSObject *unwrapKey = (OSObject *)handleManager->getObject(hUnwrappingKey);
	if (unwrapKey == NULL_PTR || !unwrapKey->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isUnwrapKeyOnToken = unwrapKey->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL isUnwrapKeyPrivate = unwrapKey->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isUnwrapKeyOnToken, isUnwrapKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Check unwrapping key class and type
	if (unwrapKey->getAttribute(CKA_CLASS)->getUnsignedLongValue() != CKO_SECRET_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP && unwrapKey->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue() != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && unwrapKey->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue() != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

	// Check if the unwrapping key can be used for unwrapping
	if (!unwrapKey->attributeExists(CKA_UNWRAP) || unwrapKey->getAttribute(CKA_UNWRAP)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Extract information from the template that is needed to create the object.

	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate);

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_PRIVATE_KEY)
		return CKR_TEMPLATE_INCONSISTENT;
	// Key type will be handled at object creation

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Build unwrapped key template
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	// Apply the unwrap template
	if (unwrapKey->attributeExists(CKA_UNWRAP_TEMPLATE) && unwrapKey->getAttribute(CKA_UNWRAP_TEMPLATE)->isArrayAttribute())
	{
		typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> array_type;

		const array_type& array = unwrapKey->getAttribute(CKA_UNWRAP_TEMPLATE)->getArrayValue();

		for (array_type::const_iterator it = array.begin(); it != array.end(); ++it)
		{
			CK_ATTRIBUTE* attr = NULL;
			for (CK_ULONG i = 0; i < secretAttribsCount; ++i)
			{
				if (it->first == secretAttribs[i].type)
				{
					if (attr != NULL)
						return CKR_TEMPLATE_INCONSISTENT;
					attr = &secretAttribs[i];
					ByteString value;
					it->second.peekValue(value);
					if (attr->ulValueLen != value.size())
						return CKR_TEMPLATE_INCONSISTENT;
					if (memcmp(attr->pValue, value.const_byte_str(), value.size()) != 0)
						return CKR_TEMPLATE_INCONSISTENT;
				}
			}
			if (attr == NULL)
				return CKR_TEMPLATE_INCONSISTENT;
		}
	}

	*hKey = CK_INVALID_HANDLE;

	// Get the symmetric algorithm matching the mechanism
	SymmetricAlgorithm* cipher = NULL;
	std::string mode;
	size_t bb = 8;
	switch(pMechanism->mechanism) {
		case CKM_AES_KEY_WRAP:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "aes-keywrap";
			break;
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			cipher = CryptoFactory::i()->getSymmetricAlgorithm("aes");
			mode = "aes-keywrap-pad";
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* unwrappingkey = new SymmetricKey();
	if (unwrappingkey == NULL)
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	if (getSymmetricKey(unwrappingkey, token, unwrapKey) != CKR_OK)
	{
		cipher->recycleKey(unwrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	unwrappingkey->setBitLen(unwrappingkey->getKeyBits().size() * bb);

	// Unwrap the key
	ByteString wrapped(pWrappedKey, ulWrappedKeyLen);
	ByteString keydata;
	rv = CKR_OK;
	if (!cipher->unwrapKey(unwrappingkey, mode, wrapped, keydata))
		rv = CKR_GENERAL_ERROR;
	cipher->recycleKey(unwrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	if (rv != CKR_OK)
		return rv;

	// Create the secret object using C_CreateObject
	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, hKey, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*hKey);
		if (osobject == NULL_PTR || !osobject->isValid())
			rv = CKR_FUNCTION_FAILED;
		if (osobject->startTransaction())
		{
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);

			// Common Secret Key Attributes
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

			// Secret Attributes
			if (objClass == CKO_SECRET_KEY)
			{
				ByteString value;
				if (isPrivate)
					token->encrypt(keydata, value);
				else
					value = keydata;
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			}
			else if (keyType == CKK_RSA)
			{
				bOK = bOK && setRSAPrivateKey(osobject, keydata, token, isPrivate);
			}
			else if (keyType == CKK_DSA)
			{
				bOK = bOK && setDSAPrivateKey(osobject, keydata, token, isPrivate);
			}
			else if (keyType == CKK_DH)
			{
				bOK = bOK && setDHPrivateKey(osobject, keydata, token, isPrivate);
			}
			else if (keyType == CKK_EC)
			{
				bOK = bOK && setECPrivateKey(osobject, keydata, token, isPrivate);
			}
			else
				bOK = false;
				

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		}
		else
			rv = CKR_FUNCTION_FAILED;
	}

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*hKey != CK_INVALID_HANDLE)
		{
			OSObject* obj = (OSObject*)handleManager->getObject(*hKey);
			handleManager->destroyObject(*hKey);
			if (obj) obj->destroyObject();
			*hKey = CK_INVALID_HANDLE;
		}

	}

	return rv;
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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DH and ECDH derive
	switch (pMechanism->mechanism)
	{
		case CKM_DH_PKCS_DERIVE:
			break;
#ifdef WITH_ECC
		case CKM_ECDH1_DERIVE:
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hBaseKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = key->getAttribute(CKA_TOKEN)->getBooleanValue();
	CK_BBOOL isKeyPrivate = key->getAttribute(CKA_PRIVATE)->getBooleanValue();

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Check key class and type
	if (key->getAttribute(CKA_CLASS)->getUnsignedLongValue() != CKO_PRIVATE_KEY)
		return CKR_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_DH_PKCS_DERIVE && key->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue() != CKK_DH)
		return CKR_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_ECDH1_DERIVE && key->getAttribute(CKA_KEY_TYPE)->getUnsignedLongValue() != CKK_EC)
		return CKR_KEY_TYPE_INCONSISTENT;

	// Check if key can be used for derive
        if (!key->attributeExists(CKA_DERIVE) || key->getAttribute(CKA_DERIVE)->getBooleanValue() == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Extract information from the template that is needed to create the object.

	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate);

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && keyType != CKK_GENERIC_SECRET)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Derive DH secret
	if (pMechanism->mechanism == CKM_DH_PKCS_DERIVE)
	{
		return this->deriveDH(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, isOnToken, isPrivate);
	}

#ifdef WITH_ECC
	// Derive ECDH secret
	if (pMechanism->mechanism == CKM_ECDH1_DERIVE)
	{
		return this->deriveECDH(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, isOnToken, isPrivate);
	}
#endif

	return CKR_GENERAL_ERROR;
}

// Seed the random number generator with new data
CK_RV SoftHSM::C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSeed == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG* rng = CryptoFactory::i()->getRNG();
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
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG* rng = CryptoFactory::i()->getRNG();
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
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_PARALLEL;
}

// Legacy function
CK_RV SoftHSM::C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_PARALLEL;
}

// Wait or poll for a slot event on the specified slot
CK_RV SoftHSM::C_WaitForSlotEvent(CK_FLAGS /*flags*/, CK_SLOT_ID_PTR /*pSlot*/, CK_VOID_PTR /*pReserved*/)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generate an AES secret key
CK_RV SoftHSM::generateAES
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t keyLen = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				keyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// keyLen must be 16, 24 or 32
	if ((keyLen != 16) && (keyLen != 24) && (keyLen != 32))
	{
		INFO_MSG("bad AES key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Generate the secret key
	AESKey* key = new AESKey(keyLen * 8);
	SymmetricAlgorithm* aes = CryptoFactory::i()->getSymmetricAlgorithm("AES");
	if (aes == NULL) return CKR_GENERAL_ERROR;
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;
	if (!aes->generateKey(*key, rng))
	{
		ERROR_MSG("Could not generate AES secret key");
		aes->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isToken, sizeof(isToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_AES_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// AES Secret Key Attributes
			ByteString value;
			if (isPrivate)
				token->encrypt(key->getKeyBits(), value);
			else
				value = key->getKeyBits();
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	aes->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(aes);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* key = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (key) key->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DES secret key
CK_RV SoftHSM::generateDES
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Generate the secret key
	DESKey* key = new DESKey(56);
	SymmetricAlgorithm* des = CryptoFactory::i()->getSymmetricAlgorithm("DES");
	if (des == NULL) return CKR_GENERAL_ERROR;
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;
	if (!des->generateKey(*key, rng))
	{
		ERROR_MSG("Could not generate DES secret key");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isToken, sizeof(isToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// DES Secret Key Attributes
			ByteString value;
			if (isPrivate)
				token->encrypt(key->getKeyBits(), value);
			else
				value = key->getKeyBits();
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	des->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(des);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* key = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (key) key->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DES2 secret key
CK_RV SoftHSM::generateDES2
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Generate the secret key
	DESKey* key = new DESKey(112);
	SymmetricAlgorithm* des = CryptoFactory::i()->getSymmetricAlgorithm("DES");
	if (des == NULL) return CKR_GENERAL_ERROR;
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;
	if (!des->generateKey(*key, rng))
	{
		ERROR_MSG("Could not generate DES secret key");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES2;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isToken, sizeof(isToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES2_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// DES Secret Key Attributes
			ByteString value;
			if (isPrivate)
				token->encrypt(key->getKeyBits(), value);
			else
				value = key->getKeyBits();
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	des->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(des);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* key = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (key) key->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DES3 secret key
CK_RV SoftHSM::generateDES3
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Generate the secret key
	DESKey* key = new DESKey(168);
	SymmetricAlgorithm* des = CryptoFactory::i()->getSymmetricAlgorithm("DES");
	if (des == NULL) return CKR_GENERAL_ERROR;
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;
	if (!des->generateKey(*key, rng))
	{
		ERROR_MSG("Could not generate DES secret key");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES3;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isToken, sizeof(isToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES3_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// DES Secret Key Attributes
			ByteString value;
			if (isPrivate)
				token->encrypt(key->getKeyBits(), value);
			else
				value = key->getKeyBits();
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	des->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(des);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* key = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (key) key->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate an RSA key pair
CK_RV SoftHSM::generateRSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate
)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: bitlen and public exponent
	size_t bitLen = 0;
	ByteString exponent("010001");
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
	RSAParameters p;
	p.setE(exponent);
	p.setBitLength(bitLen);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm("RSA");
	if (rsa == NULL)
		return CKR_GENERAL_ERROR;
	if (!rsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return CKR_GENERAL_ERROR;
	}

	RSAPublicKey* pub = (RSAPublicKey*) kp->getPublicKey();
	RSAPrivateKey* priv = (RSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_RSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PUBLIC_EXPONENT:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// RSA Public Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getN(), modulus);
					token->encrypt(pub->getE(), publicExponent);
				}
				else
				{
					modulus = pub->getN();
					publicExponent = pub->getE();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_RSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// RSA Private Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				ByteString privateExponent;
				ByteString prime1;
				ByteString prime2;
				ByteString exponent1;
				ByteString exponent2;
				ByteString coefficient;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getN(), modulus);
					token->encrypt(priv->getE(), publicExponent);
					token->encrypt(priv->getD(), privateExponent);
					token->encrypt(priv->getP(), prime1);
					token->encrypt(priv->getQ(), prime2);
					token->encrypt(priv->getDP1(), exponent1);
					token->encrypt(priv->getDQ1(), exponent2);
					token->encrypt(priv->getPQ(), coefficient);
				}
				else
				{
					modulus = priv->getN();
					publicExponent = priv->getE();
					privateExponent = priv->getD();
					prime1 = priv->getP();
					prime2 = priv->getQ();
					exponent1 =  priv->getDP1();
					exponent2 = priv->getDQ1();
					coefficient = priv->getPQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_1, prime1);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_2, prime2);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_1,exponent1);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_2, exponent2);
				bOK = bOK && osobject->setAttribute(CKA_COEFFICIENT, coefficient);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	rsa->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* priv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (priv) priv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* pub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (pub) pub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DSA key pair
CK_RV SoftHSM::generateDSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString prime;
	ByteString subprime;
	ByteString generator;
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
	DSAParameters p;
	p.setP(prime);
	p.setQ(subprime);
	p.setG(generator);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm("DSA");
	if (dsa == NULL) return CKR_GENERAL_ERROR;
	if (!dsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return CKR_GENERAL_ERROR;
	}

	DSAPublicKey* pub = (DSAPublicKey*) kp->getPublicKey();
	DSAPrivateKey* priv = (DSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_DSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PRIME:
				case CKA_SUBPRIME:
				case CKA_BASE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// DSA Public Key Attributes
				ByteString prime;
				ByteString subprime;
				ByteString generator;
				ByteString value;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getP(), prime);
					token->encrypt(pub->getQ(), subprime);
					token->encrypt(pub->getG(), generator);
					token->encrypt(pub->getY(), value);
				}
				else
				{
					prime = pub->getP();
					subprime = pub->getQ();
					generator = pub->getG();
					value = pub->getY();
				}
				bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
				bOK = bOK && osobject->setAttribute(CKA_SUBPRIME, subprime);
				bOK = bOK && osobject->setAttribute(CKA_BASE, generator);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_DSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// DSA Private Key Attributes
				ByteString prime;
				ByteString subprime;
				ByteString generator;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getP(), prime);
					token->encrypt(priv->getQ(), subprime);
					token->encrypt(priv->getG(), generator);
					token->encrypt(priv->getX(), value);
				}
				else
				{
					prime = priv->getP();
					subprime = priv->getQ();
					generator = priv->getG();
					value = priv->getX();
				}
				bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
				bOK = bOK && osobject->setAttribute(CKA_SUBPRIME, subprime);
				bOK = bOK && osobject->setAttribute(CKA_BASE, generator);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	dsa->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* priv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (priv) priv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* pub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (pub) pub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DSA domain parameter set
CK_RV SoftHSM::generateDSAParameters
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t bitLen = 0;
	size_t qLen = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_PRIME_BITS:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				bitLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_SUBPRIME_BITS:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_SUBPRIME_BITS does not have the size of CK_ULONG");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				qLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// CKA_PRIME_BITS must be specified
	if (bitLen == 0)
	{
		INFO_MSG("Missing CKA_PRIME_BITS in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// No real choice for CKA_SUBPRIME_BITS
	if ((qLen != 0) &&
	    (((bitLen >= 2048) && (qLen != 256)) ||
	     ((bitLen < 2048) && (qLen != 160))))
		INFO_MSG("CKA_SUBPRIME_BITS is ignored");


	// Generate domain parameters
	AsymmetricParameters* p = NULL;
	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm("DSA");
	if (dsa == NULL) return CKR_GENERAL_ERROR;
	if (!dsa->generateParameters(&p, (void *)bitLen))
	{
		ERROR_MSG("Could not generate parameters");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return CKR_GENERAL_ERROR;
	}

	DSAParameters* params = (DSAParameters*) p;

	CK_RV rv = CKR_OK;

	// Create the domain parameter object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_DOMAIN_PARAMETERS;
	CK_KEY_TYPE keyType = CKK_DSA;
	CK_ATTRIBUTE paramsAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isToken, sizeof(isToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG paramsAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - paramsAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			paramsAttribs[paramsAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, paramsAttribs, paramsAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_PARAMETER_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// DSA Domain Parameters Attributes
			ByteString prime;
			ByteString subprime;
			ByteString generator;
			if (isPrivate)
			{
				token->encrypt(params->getP(), prime);
				token->encrypt(params->getQ(), subprime);
				token->encrypt(params->getG(), generator);
			}
			else
			{
				prime = params->getP();
				subprime = params->getQ();
				generator = params->getG();
			}
			bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
			bOK = bOK && osobject->setAttribute(CKA_SUBPRIME, subprime);
			bOK = bOK && osobject->setAttribute(CKA_BASE, generator);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	dsa->recycleParameters(p);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	// Remove parameters that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* params = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (params) params->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate an EC key pair
CK_RV SoftHSM::generateEC
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	ECParameters p;
	p.setEC(params);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* ec = CryptoFactory::i()->getAsymmetricAlgorithm("ECDSA");
	if (ec == NULL) return CKR_GENERAL_ERROR;
	if (!ec->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);
		return CKR_GENERAL_ERROR;
	}

	ECPublicKey* pub = (ECPublicKey*) kp->getPublicKey();
	ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_EC;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_EC_PARAMS:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// EC Public Key Attributes
				ByteString group;
				ByteString point;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getEC(), group);
					token->encrypt(pub->getQ(), point);
				}
				else
				{
					group = pub->getEC();
					point = pub->getQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_EC_POINT, point);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_EC;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// EC Private Key Attributes
				ByteString group;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getEC(), group);
					token->encrypt(priv->getD(), value);
				}
				else
				{
					group = priv->getEC();
					value = priv->getD();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	ec->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* priv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (priv) priv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* pub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (pub) pub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DH key pair
CK_RV SoftHSM::generateDH
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString prime;
	ByteString generator;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_PRIME:
				prime = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_BASE:
				generator = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (prime.size() == 0 || generator.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	DHParameters p;
	p.setP(prime);
	p.setG(generator);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm("DH");
	if (dh == NULL) return CKR_GENERAL_ERROR;
	if (!dh->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	DHPublicKey* pub = (DHPublicKey*) kp->getPublicKey();
	DHPrivateKey* priv = (DHPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_DH;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PRIME:
				case CKA_BASE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// DH Public Key Attributes
				ByteString prime;
				ByteString generator;
				ByteString value;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getP(), prime);
					token->encrypt(pub->getG(), generator);
					token->encrypt(pub->getY(), value);
				}
				else
				{
					prime = pub->getP();
					generator = pub->getG();
					value = pub->getY();
				}
				bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
				bOK = bOK && osobject->setAttribute(CKA_BASE, generator);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_DH;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// DH Private Key Attributes
				ByteString prime;
				ByteString generator;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getP(), prime);
					token->encrypt(priv->getG(), generator);
					token->encrypt(priv->getX(), value);
				}
				else
				{
					prime = priv->getP();
					generator = priv->getG();
					value = priv->getX();
				}
				bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
				bOK = bOK && osobject->setAttribute(CKA_BASE, generator);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	dh->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* priv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (priv) priv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* pub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (pub) pub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DH domain parameter set
CK_RV SoftHSM::generateDHParameters
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t bitLen = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_PRIME_BITS:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				bitLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// CKA_PRIME_BITS must be specified
	if (bitLen == 0)
	{
		INFO_MSG("Missing CKA_PRIME_BITS in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Generate domain parameters
	AsymmetricParameters* p = NULL;
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm("DH");
	if (dh == NULL) return CKR_GENERAL_ERROR;
	if (!dh->generateParameters(&p, (void *)bitLen))
	{
		ERROR_MSG("Could not generate parameters");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	DHParameters* params = (DHParameters*) p;

	CK_RV rv = CKR_OK;

	// Create the domain parameter object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_DOMAIN_PARAMETERS;
	CK_KEY_TYPE keyType = CKK_DH;
	CK_ATTRIBUTE paramsAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isToken, sizeof(isToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG paramsAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - paramsAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			paramsAttribs[paramsAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, paramsAttribs, paramsAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_PARAMETER_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// DH Domain Parameters Attributes
			ByteString prime;
			ByteString generator;
			if (isPrivate)
			{
				token->encrypt(params->getP(), prime);
				token->encrypt(params->getG(), generator);
			}
			else
			{
				prime = params->getP();
				generator = params->getG();
			}
			bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
			bOK = bOK && osobject->setAttribute(CKA_BASE, generator);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	dh->recycleParameters(p);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	// Remove parameters that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* params = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (params) params->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a GOST key pair
CK_RV SoftHSM::generateGOST
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString param_3410;
	ByteString param_3411;
	ByteString param_28147;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_GOSTR3410_PARAMS:
				param_3410 = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_GOSTR3411_PARAMS:
				param_3411 = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_GOST28147_PARAMS:
				param_28147 = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (param_3410.size() == 0 || param_3411.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	ECParameters p;
	p.setEC(param_3410);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* gost = CryptoFactory::i()->getAsymmetricAlgorithm("GOST");
	if (gost == NULL) return CKR_GENERAL_ERROR;
	if (!gost->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
		return CKR_GENERAL_ERROR;
	}

	GOSTPublicKey* pub = (GOSTPublicKey*) kp->getPublicKey();
	GOSTPrivateKey* priv = (GOSTPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_GOSTR3410;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// EC Public Key Attributes
				ByteString point;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getQ(), point);
				}
				else
				{
					point = pub->getQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_VALUE, point);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_GOSTR3410;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable =  osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// GOST Private Key Attributes
				ByteString value;
				ByteString param_a;
				ByteString param_b;
				ByteString param_c;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getD(), value);
					token->encrypt(priv->getEC(), param_a);
					token->encrypt(param_3411, param_b);
					token->encrypt(param_28147, param_c);
				}
				else
				{
					value = priv->getD();
					param_a = priv->getEC();
					param_b = param_3411;
					param_c = param_28147;
				}
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
				bOK = bOK && osobject->setAttribute(CKA_GOSTR3410_PARAMS, param_a);
				bOK = bOK && osobject->setAttribute(CKA_GOSTR3411_PARAMS, param_b);
				bOK = bOK && osobject->setAttribute(CKA_GOST28147_PARAMS, param_c);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				  rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	gost->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* priv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (priv) priv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* pub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (pub) pub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Derive a DH secret
CK_RV SoftHSM::deriveDH
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if (pMechanism->pParameter == NULL_PTR) return CKR_MECHANISM_PARAM_INVALID;
	if (pMechanism->ulParameterLen == 0) return CKR_MECHANISM_PARAM_INVALID;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_TEMPLATE_INCONSISTENT;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// Get the base key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL && !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the DH algorithm handler
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm("DH");
	if (dh == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = dh->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_HOST_MEMORY;
	}
	if (getDHPrivateKey((DHPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		dh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	ByteString mechParameters;
	mechParameters.resize(pMechanism->ulParameterLen);
	memcpy(&mechParameters[0], pMechanism->pParameter, pMechanism->ulParameterLen);
	PublicKey* publicKey = dh->newPublicKey();
	if (publicKey == NULL)
	{
		dh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_HOST_MEMORY;
	}
	if (getDHPublicKey((DHPublicKey*)publicKey, (DHPrivateKey*)privateKey, mechParameters) != CKR_OK)
	{
		dh->recyclePrivateKey(privateKey);
		dh->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!dh->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	dh->recyclePrivateKey(privateKey);
	dh->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_VALUE_LEN:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->attributeExists(CKA_ALWAYS_SENSITIVE) && baseKey->getAttribute(CKA_ALWAYS_SENSITIVE)->getBooleanValue())
			{
				bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (!baseKey->attributeExists(CKA_NEVER_EXTRACTABLE) || baseKey->getAttribute(CKA_NEVER_EXTRACTABLE)->getBooleanValue())
			{
				bool bNeverExtractable = osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString value;
			if (isPrivate)
			{
				token->encrypt(secret->getKeyBits(), value);
			}
			else
			{
				value = secret->getKeyBits();
			}
			// Truncate value when requested
			if (byteLen != 0 && byteLen < value.size())
				value.resize(byteLen);
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	dh->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* secret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (secret) secret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Derive an ECDH secret
CK_RV SoftHSM::deriveECDH
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
#ifdef WITH_ECC
	*phKey = CK_INVALID_HANDLE;

	if ((pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
	{
		DEBUG_MSG("pParameter must be of type CK_ECDH1_DERIVE_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf != CKD_NULL)
	{
		DEBUG_MSG("kdf must be CKD_NULL");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen != 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData != NULL_PTR))
	{
		DEBUG_MSG("there must be no shared data");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen == 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData == NULL_PTR))
	{
		DEBUG_MSG("there must be a public data");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_TEMPLATE_INCONSISTENT;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// Get the base key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the ECDH algorithm handler
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm("ECDH");
	if (ecdh == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = ecdh->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECPrivateKey((ECPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	ByteString publicData;
	publicData.resize(CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	memcpy(&publicData[0],
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData,
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	PublicKey* publicKey = ecdh->newPublicKey();
	if (publicKey == NULL)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECDHPublicKey((ECPublicKey*)publicKey, (ECPrivateKey*)privateKey, publicData) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		ecdh->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!ecdh->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	ecdh->recyclePrivateKey(privateKey);
	ecdh->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_VALUE_LEN:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->attributeExists(CKA_ALWAYS_SENSITIVE) && baseKey->getAttribute(CKA_ALWAYS_SENSITIVE)->getBooleanValue())
			{
				bool bAlwaysSensitive = osobject->getAttribute(CKA_SENSITIVE)->getBooleanValue();
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (!baseKey->attributeExists(CKA_NEVER_EXTRACTABLE) || baseKey->getAttribute(CKA_NEVER_EXTRACTABLE)->getBooleanValue())
			{
				bool bNeverExtractable = osobject->getAttribute(CKA_EXTRACTABLE)->getBooleanValue() == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString value;
			if (isPrivate)
			{
				token->encrypt(secret->getKeyBits(), value);
			}
			else
			{
				value = secret->getKeyBits();
			}
			// Truncate value when requested
			if (byteLen != 0 && byteLen < value.size())
				value.resize(byteLen);
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	ecdh->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* secret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (secret) secret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
#else
	return CKR_MECHANISM_INVALID;
#endif
}

CK_RV SoftHSM::CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject, int op)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phObject == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL isToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_RV rv = extractObjectInformation(pTemplate,ulCount,objClass,keyType,certType, isToken, isPrivate);
	if (rv != CKR_OK)
	{
		ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Check user credentials
	rv = haveWrite(session->getState(), isToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	std::auto_ptr< P11Object > p11object;
	rv = newP11Object(objClass,keyType,certType,p11object);
	if (rv != CKR_OK)
		return rv;

	// Create the object in session or on the token
	OSObject *object = NULL_PTR;
	if (isToken)
	{
		object = (OSObject*) token->createObject();
	}
	else
	{
		object = sessionObjectStore->createObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE);
	}
	if (object == NULL) return CKR_GENERAL_ERROR;

	p11object->init(object);

	rv = p11object->saveTemplate(token, isPrivate != CK_FALSE, pTemplate,ulCount,op);
	if (rv != CKR_OK)
		return rv;

	if (isToken) {
		*phObject = handleManager->addTokenObject(slot->getSlotID(), isPrivate != CK_FALSE, object);
	} else {
		*phObject = handleManager->addSessionObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE, object);
	}

	return CKR_OK;
}

CK_RV SoftHSM::getRSAPrivateKey(RSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_MODULUS)->getByteStringValue(), modulus);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PUBLIC_EXPONENT)->getByteStringValue(), publicExponent);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PRIVATE_EXPONENT)->getByteStringValue(), privateExponent);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PRIME_1)->getByteStringValue(), prime1);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PRIME_2)->getByteStringValue(), prime2);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_EXPONENT_1)->getByteStringValue(), exponent1);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_EXPONENT_2)->getByteStringValue(), exponent2);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_COEFFICIENT)->getByteStringValue(), coefficient);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getAttribute(CKA_MODULUS)->getByteStringValue();
		publicExponent = key->getAttribute(CKA_PUBLIC_EXPONENT)->getByteStringValue();
		privateExponent = key->getAttribute(CKA_PRIVATE_EXPONENT)->getByteStringValue();
		prime1 = key->getAttribute(CKA_PRIME_1)->getByteStringValue();
		prime2 = key->getAttribute(CKA_PRIME_2)->getByteStringValue();
		exponent1 =  key->getAttribute(CKA_EXPONENT_1)->getByteStringValue();
		exponent2 = key->getAttribute(CKA_EXPONENT_2)->getByteStringValue();
		coefficient = key->getAttribute(CKA_COEFFICIENT)->getByteStringValue();
	}

	privateKey->setN(modulus);
	privateKey->setE(publicExponent);
	privateKey->setD(privateExponent);
	privateKey->setP(prime1);
	privateKey->setQ(prime2);
	privateKey->setDP1(exponent1);
	privateKey->setDQ1(exponent2);
	privateKey->setPQ(coefficient);

	return CKR_OK;
}

CK_RV SoftHSM::getRSAPublicKey(RSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// RSA Public Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_MODULUS)->getByteStringValue(), modulus);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PUBLIC_EXPONENT)->getByteStringValue(), publicExponent);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getAttribute(CKA_MODULUS)->getByteStringValue();
		publicExponent = key->getAttribute(CKA_PUBLIC_EXPONENT)->getByteStringValue();
	}

	publicKey->setN(modulus);
	publicKey->setE(publicExponent);

	return CKR_OK;
}

CK_RV SoftHSM::getDSAPrivateKey(DSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// DSA Private Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PRIME)->getByteStringValue(), prime);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_SUBPRIME)->getByteStringValue(), subprime);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_BASE)->getByteStringValue(), generator);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key->getAttribute(CKA_PRIME)->getByteStringValue();
		subprime = key->getAttribute(CKA_SUBPRIME)->getByteStringValue();
		generator = key->getAttribute(CKA_BASE)->getByteStringValue();
		value = key->getAttribute(CKA_VALUE)->getByteStringValue();
	}

	privateKey->setP(prime);
	privateKey->setQ(subprime);
	privateKey->setG(generator);
	privateKey->setX(value);

	return CKR_OK;
}

CK_RV SoftHSM::getDSAPublicKey(DSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// DSA Public Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PRIME)->getByteStringValue(), prime);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_SUBPRIME)->getByteStringValue(), subprime);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_BASE)->getByteStringValue(), generator);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key->getAttribute(CKA_PRIME)->getByteStringValue();
		subprime = key->getAttribute(CKA_SUBPRIME)->getByteStringValue();
		generator = key->getAttribute(CKA_BASE)->getByteStringValue();
		value = key->getAttribute(CKA_VALUE)->getByteStringValue();
	}

	publicKey->setP(prime);
	publicKey->setQ(subprime);
	publicKey->setG(generator);
	publicKey->setY(value);

	return CKR_OK;
}

CK_RV SoftHSM::getECPrivateKey(ECPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_EC_PARAMS)->getByteStringValue(), group);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getAttribute(CKA_EC_PARAMS)->getByteStringValue();
		value = key->getAttribute(CKA_VALUE)->getByteStringValue();
	}

	privateKey->setEC(group);
	privateKey->setD(value);

	return CKR_OK;
}

CK_RV SoftHSM::getECPublicKey(ECPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// EC Public Key Attributes
	ByteString group;
	ByteString point;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_EC_PARAMS)->getByteStringValue(), group);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_EC_POINT)->getByteStringValue(), point);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getAttribute(CKA_EC_PARAMS)->getByteStringValue();
		point = key->getAttribute(CKA_EC_POINT)->getByteStringValue();
	}

	publicKey->setEC(group);
	publicKey->setQ(point);

	return CKR_OK;
}

CK_RV SoftHSM::getDHPrivateKey(DHPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// DH Private Key Attributes
	ByteString prime;
	ByteString generator;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_PRIME)->getByteStringValue(), prime);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_BASE)->getByteStringValue(), generator);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key->getAttribute(CKA_PRIME)->getByteStringValue();
		generator = key->getAttribute(CKA_BASE)->getByteStringValue();
		value = key->getAttribute(CKA_VALUE)->getByteStringValue();
	}

	privateKey->setP(prime);
	privateKey->setG(generator);
	privateKey->setX(value);

	return CKR_OK;
}

CK_RV SoftHSM::getDHPublicKey(DHPublicKey* publicKey, DHPrivateKey* privateKey, ByteString& pubParams)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setP(privateKey->getP());
	publicKey->setG(privateKey->getG());

	// Set value
	publicKey->setY(pubParams);

	return CKR_OK;
}

CK_RV SoftHSM::getECDHPublicKey(ECPublicKey* publicKey, ECPrivateKey* privateKey, ByteString& pubData)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setEC(privateKey->getEC());

	// Set value
	publicKey->setQ(pubData);

	return CKR_OK;
}

CK_RV SoftHSM::getGOSTPrivateKey(GOSTPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// GOST Private Key Attributes
	ByteString value;
	ByteString param;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), value);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_GOSTR3410_PARAMS)->getByteStringValue(), param);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getAttribute(CKA_VALUE)->getByteStringValue();
		param = key->getAttribute(CKA_GOSTR3410_PARAMS)->getByteStringValue();
	}

	privateKey->setD(value);
	privateKey->setEC(param);

	return CKR_OK;
}

CK_RV SoftHSM::getGOSTPublicKey(GOSTPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	// GOST Public Key Attributes
	ByteString point;
	ByteString param;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), point);
		bOK = bOK && token->decrypt(key->getAttribute(CKA_GOSTR3410_PARAMS)->getByteStringValue(), param);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		point = key->getAttribute(CKA_VALUE)->getByteStringValue();
		param = key->getAttribute(CKA_GOSTR3410_PARAMS)->getByteStringValue();
	}

	publicKey->setQ(point);
	publicKey->setEC(param);

	return CKR_OK;
}

CK_RV SoftHSM::getSymmetricKey(SymmetricKey* skey, Token* token, OSObject* key)
{
	if (skey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	OSAttribute* attr = key->getAttribute(CKA_PRIVATE);
	bool isKeyPrivate = (attr != NULL && attr->getBooleanValue());

	ByteString keybits;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getAttribute(CKA_VALUE)->getByteStringValue(), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key->getAttribute(CKA_VALUE)->getByteStringValue();
	}

	skey->setKeyBits(keybits);

	return CKR_OK;
}

bool SoftHSM::setRSAPrivateKey(OSObject* key, ByteString ber, Token* token, bool isPrivate)
{
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm("rsa");
	if (rsa == NULL)
		return false;
	PrivateKey* priv = rsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		rsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	if (isPrivate)
	{
		token->encrypt(((RSAPrivateKey*)priv)->getN(), modulus);
		token->encrypt(((RSAPrivateKey*)priv)->getE(), publicExponent);
		token->encrypt(((RSAPrivateKey*)priv)->getD(), privateExponent);
		token->encrypt(((RSAPrivateKey*)priv)->getP(), prime1);
		token->encrypt(((RSAPrivateKey*)priv)->getQ(), prime2);
		token->encrypt(((RSAPrivateKey*)priv)->getDP1(), exponent1);
		token->encrypt(((RSAPrivateKey*)priv)->getDQ1(), exponent2);
		token->encrypt(((RSAPrivateKey*)priv)->getPQ(), coefficient);
	}
	else
	{
		modulus = ((RSAPrivateKey*)priv)->getN();
		publicExponent = ((RSAPrivateKey*)priv)->getE();
		privateExponent = ((RSAPrivateKey*)priv)->getD();
		prime1 = ((RSAPrivateKey*)priv)->getP();
		prime2 = ((RSAPrivateKey*)priv)->getQ();
		exponent1 =  ((RSAPrivateKey*)priv)->getDP1();
		exponent2 = ((RSAPrivateKey*)priv)->getDQ1();
		coefficient = ((RSAPrivateKey*)priv)->getPQ();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_MODULUS, modulus);
	bOK = bOK && key->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
	bOK = bOK && key->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
	bOK = bOK && key->setAttribute(CKA_PRIME_1, prime1);
	bOK = bOK && key->setAttribute(CKA_PRIME_2, prime2);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_1,exponent1);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_2, exponent2);
	bOK = bOK && key->setAttribute(CKA_COEFFICIENT, coefficient);

	rsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	return bOK;
}

bool SoftHSM::setDSAPrivateKey(OSObject* key, ByteString ber, Token* token, bool isPrivate)
{
	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm("dsa");
	if (dsa == NULL)
		return false;
	PrivateKey* priv = dsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		dsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return false;
	}
	// DSA Private Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((DSAPrivateKey*)priv)->getP(), prime);
		token->encrypt(((DSAPrivateKey*)priv)->getQ(), subprime);
		token->encrypt(((DSAPrivateKey*)priv)->getG(), generator);
		token->encrypt(((DSAPrivateKey*)priv)->getX(), value);
	}
	else
	{
		prime = ((DSAPrivateKey*)priv)->getP();
		subprime = ((DSAPrivateKey*)priv)->getQ();
		generator = ((DSAPrivateKey*)priv)->getG();
		value = ((DSAPrivateKey*)priv)->getX();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PRIME, prime);
	bOK = bOK && key->setAttribute(CKA_SUBPRIME, subprime);
	bOK = bOK && key->setAttribute(CKA_BASE, generator);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	dsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	return bOK;
}

bool SoftHSM::setDHPrivateKey(OSObject* key, ByteString ber, Token* token, bool isPrivate)
{
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm("dh");
	if (dh == NULL)
		return false;
	PrivateKey* priv = dh->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		dh->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return false;
	}
	// DH Private Key Attributes
	ByteString prime;
	ByteString generator;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((DHPrivateKey*)priv)->getP(), prime);
		token->encrypt(((DHPrivateKey*)priv)->getG(), generator);
		token->encrypt(((DHPrivateKey*)priv)->getX(), value);
	}
	else
	{
		prime = ((DHPrivateKey*)priv)->getP();
		generator = ((DHPrivateKey*)priv)->getG();
		value = ((DHPrivateKey*)priv)->getX();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PRIME, prime);
	bOK = bOK && key->setAttribute(CKA_BASE, generator);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	dh->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	return bOK;
}
bool SoftHSM::setECPrivateKey(OSObject* key, ByteString ber, Token* token, bool isPrivate)
{
	AsymmetricAlgorithm* ecc = CryptoFactory::i()->getAsymmetricAlgorithm("ecdsa");
	if (ecc == NULL)
		return false;
	PrivateKey* priv = ecc->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		ecc->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((ECPrivateKey*)priv)->getEC(), group);
		token->encrypt(((ECPrivateKey*)priv)->getD(), value);
	}
	else
	{
		group = ((ECPrivateKey*)priv)->getEC();
		value = ((ECPrivateKey*)priv)->getD();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_EC_PARAMS, group);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	ecc->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);

	return bOK;
}
