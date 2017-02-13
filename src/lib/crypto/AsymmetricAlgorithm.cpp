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
 AsymmetricAlgorithm.cpp

 Base class for asymmetric algorithm classes
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "AsymmetricAlgorithm.h"

// Base constructor
AsymmetricAlgorithm::AsymmetricAlgorithm()
{
	currentOperation = NONE;
	currentMechanism = AsymMech::Unknown;
	currentPadding = AsymMech::Unknown;
	currentPublicKey = NULL;
	currentPrivateKey = NULL;
}

// Signing functions
bool AsymmetricAlgorithm::sign(PrivateKey* privateKey, const ByteString& dataToSign,
			       ByteString& signature, const AsymMech::Type mechanism,
			       const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	// Compose from multi-part operations
	return (signInit(privateKey, mechanism, param, paramLen) && signUpdate(dataToSign) && signFinal(signature));
}

bool AsymmetricAlgorithm::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
				   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if ((currentOperation != NONE) || (privateKey == NULL))
	{
		return false;
	}

	currentPrivateKey = privateKey;
	currentMechanism = mechanism;
	currentOperation = SIGN;

	return true;
}

bool AsymmetricAlgorithm::signUpdate(const ByteString& /*dataToSign*/)
{
	if (currentOperation != SIGN)
	{
		return false;
	}

	return true;
}

bool AsymmetricAlgorithm::signFinal(ByteString& /*signature*/)
{
	if (currentOperation != SIGN)
	{
		return false;
	}

	currentOperation = NONE;
	currentPrivateKey = NULL;
	currentMechanism = AsymMech::Unknown;

	return true;
}

// Verification functions
bool AsymmetricAlgorithm::verify(PublicKey* publicKey, const ByteString& originalData,
				 const ByteString& signature, const AsymMech::Type mechanism,
				 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	// Compose from multi-part operations
	return (verifyInit(publicKey, mechanism, param, paramLen) && verifyUpdate(originalData) && verifyFinal(signature));
}

bool AsymmetricAlgorithm::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
				     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if ((currentOperation != NONE) || (publicKey == NULL))
	{
		return false;
	}

	currentOperation = VERIFY;
	currentPublicKey = publicKey;
	currentMechanism = mechanism;

	return true;
}

bool AsymmetricAlgorithm::verifyUpdate(const ByteString& /*originalData*/)
{
	if (currentOperation != VERIFY)
	{
		return false;
	}

	return true;
}

bool AsymmetricAlgorithm::verifyFinal(const ByteString& /*signature*/)
{
	if (currentOperation != VERIFY)
	{
		return false;
	}

	currentOperation = NONE;
	currentPublicKey = NULL;
	currentMechanism = AsymMech::Unknown;

	return true;
}

// Returns true for mechanisms which have 'tick mark' in Wrap&Unwrap column in PKCS #11 Mechanisms v2.40
bool AsymmetricAlgorithm::isWrappingMech(AsymMech::Type padding)
{
	switch (padding)
	{
		case AsymMech::RSA:
		case AsymMech::RSA_PKCS:
		case AsymMech::RSA_PKCS_OAEP:
			return true;

		default:
			return false;
	}
}

// Wrap/Unwrap keys
bool AsymmetricAlgorithm::wrapKey(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding)
{
	if (!isWrappingMech(padding))
		return false;

	return encrypt(publicKey, data, encryptedData, padding);
}

bool AsymmetricAlgorithm::unwrapKey(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding)
{
	if (!isWrappingMech(padding))
		return false;

	return decrypt(privateKey, encryptedData, data, padding);
}


bool AsymmetricAlgorithm::generateParameters(AsymmetricParameters** /*ppParams*/, void* /*parameters = NULL*/, RNG* /*rng = NULL*/)
{
	return false;
}

bool AsymmetricAlgorithm::deriveKey(SymmetricKey** /*ppSymmetricKey*/, PublicKey* /*publicKey*/, PrivateKey* /*privateKey*/)
{
	return false;
}

bool AsymmetricAlgorithm::reconstructParameters(AsymmetricParameters** /*ppParams*/, ByteString& /*serialisedData*/)
{
	return false;
}

AsymmetricParameters* AsymmetricAlgorithm::newParameters()
{
	return NULL;
}

// Key recycling -- override these functions in a derived class if you need to perform specific cleanup
void AsymmetricAlgorithm::recycleKeyPair(AsymmetricKeyPair* toRecycle)
{
	delete toRecycle;
}

void AsymmetricAlgorithm::recycleParameters(AsymmetricParameters* toRecycle)
{
	delete toRecycle;
}

void AsymmetricAlgorithm::recyclePublicKey(PublicKey* toRecycle)
{
	delete toRecycle;
}

void AsymmetricAlgorithm::recyclePrivateKey(PrivateKey* toRecycle)
{
	delete toRecycle;
}

void AsymmetricAlgorithm::recycleSymmetricKey(SymmetricKey* toRecycle)
{
	delete toRecycle;
}

