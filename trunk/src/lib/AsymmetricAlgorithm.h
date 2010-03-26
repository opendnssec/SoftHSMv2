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
 AsymmetricAlgorithm.h

 Base class for asymmetric algorithm classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ASYMMETRICALGORITHM_H
#define _SOFTHSM_V2_ASYMMETRICALGORITHM_H

#include "config.h"
#include <string>
#include "AsymmetricKeyPair.h"
#include "AsymmetricParameters.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "RNG.h"

class AsymmetricAlgorithm
{
public:
	// Base constructors
	AsymmetricAlgorithm();

	// Destructor
	virtual ~AsymmetricAlgorithm() { }

	// Signing functions
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const std::string mechanism);
	virtual bool signInit(PrivateKey* privateKey, const std::string mechanism);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const std::string mechanism);
	virtual bool verifyInit(PublicKey* publicKey, const std::string mechanism);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const std::string padding) = 0;

	// Decryption functions
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const std::string padding) = 0;

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL) = 0;
	virtual bool generateParameters(AsymmetricParameters** ppParams, void* parameters = NULL, RNG* rng = NULL);
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData) = 0;
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData) = 0;
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData) = 0;
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	virtual PublicKey* newPublicKey() = 0;
	virtual PrivateKey* newPrivateKey() = 0;
	virtual AsymmetricParameters* newParameters();

protected:
	PublicKey* currentPublicKey;
	PrivateKey* currentPrivateKey;

	std::string currentMechanism;
	std::string currentPadding;

private:
	enum
	{
		NONE,
		SIGN,
		VERIFY
	}
	currentOperation;
};

#endif // !_SOFTHSM_V2_ASYMMETRICALGORITHM_H

