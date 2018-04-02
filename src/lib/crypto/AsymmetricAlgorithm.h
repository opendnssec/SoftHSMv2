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
#include "AsymmetricKeyPair.h"
#include "AsymmetricParameters.h"
#include "HashAlgorithm.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "RNG.h"
#include "SymmetricKey.h"

struct AsymAlgo
{
        enum Type
	{
		Unknown,
		RSA,
		DSA,
		DH,
		ECDH,
		ECDSA,
		GOST,
		EDDSA
        };
};

struct AsymMech
{
	enum Type
	{
		Unknown,
		RSA,
		RSA_MD5_PKCS,
		RSA_PKCS,
		RSA_PKCS_OAEP,
		RSA_SHA1_PKCS,
		RSA_SHA224_PKCS,
		RSA_SHA256_PKCS,
		RSA_SHA384_PKCS,
		RSA_SHA512_PKCS,
		RSA_PKCS_PSS,
		RSA_SHA1_PKCS_PSS,
		RSA_SHA224_PKCS_PSS,
		RSA_SHA256_PKCS_PSS,
		RSA_SHA384_PKCS_PSS,
		RSA_SHA512_PKCS_PSS,
		RSA_SSL,
		DSA,
		DSA_SHA1,
		DSA_SHA224,
		DSA_SHA256,
		DSA_SHA384,
		DSA_SHA512,
		ECDSA,
		GOST,
		GOST_GOST,
		EDDSA
	};
};

struct AsymRSAMGF
{
	enum Type
	{
		Unknown,
		MGF1_SHA1,
		MGF1_SHA224,
		MGF1_SHA256,
		MGF1_SHA384,
		MGF1_SHA512
	};
};

struct RSA_PKCS_PSS_PARAMS
{
	HashAlgo::Type hashAlg;
	AsymRSAMGF::Type mgf;
	size_t sLen;
};

class AsymmetricAlgorithm
{
public:
	// Base constructors
	AsymmetricAlgorithm();

	// Destructor
	virtual ~AsymmetricAlgorithm() { }

	// Signing functions
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding) = 0;

	// Decryption functions
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding) = 0;

	// Wrap/Unwrap keys
	bool wrapKey(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);
	bool unwrapKey(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL) = 0;
	virtual unsigned long getMinKeySize() = 0;
	virtual unsigned long getMaxKeySize() = 0;
	virtual bool generateParameters(AsymmetricParameters** ppParams, void* parameters = NULL, RNG* rng = NULL);
	virtual bool deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey);
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData) = 0;
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData) = 0;
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData) = 0;
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	virtual PublicKey* newPublicKey() = 0;
	virtual PrivateKey* newPrivateKey() = 0;
	virtual AsymmetricParameters* newParameters();

	// Key recycling -- override these functions in a derived class if you need to perform specific cleanup
	virtual void recycleKeyPair(AsymmetricKeyPair* toRecycle);
	virtual void recycleParameters(AsymmetricParameters* toRecycle);
	virtual void recyclePublicKey(PublicKey* toRecycle);
	virtual void recyclePrivateKey(PrivateKey* toRecycle);
	virtual void recycleSymmetricKey(SymmetricKey* toRecycle);

protected:
	PublicKey* currentPublicKey;
	PrivateKey* currentPrivateKey;

	AsymMech::Type currentMechanism;
	AsymMech::Type currentPadding;

private:
	enum
	{
		NONE,
		SIGN,
		VERIFY
	}
	currentOperation;

	bool isWrappingMech(AsymMech::Type padding);
};

#endif // !_SOFTHSM_V2_ASYMMETRICALGORITHM_H

