/*
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
 BotanDHPrivateKey.h

 Botan Diffie-Hellman private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANDHPRIVATEKEY_H
#define _SOFTHSM_V2_BOTANDHPRIVATEKEY_H

#include "config.h"
#include "DHPrivateKey.h"
#include <botan/dh.h>
#include <botan/version.h>

// Derived from the DH_PrivateKey class
class BotanDH_PrivateKey : public Botan::DH_PublicKey,
			   public virtual Botan::DL_Scheme_PrivateKey
{
public:
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	std::vector<Botan::byte> public_value() const;
#else
	Botan::MemoryVector<Botan::byte> public_value() const;
#endif

	// Constructors
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	BotanDH_PrivateKey(const Botan::AlgorithmIdentifier& alg_id,
			   const Botan::secure_vector<Botan::byte>& key_bits,
			   Botan::RandomNumberGenerator& rng);
#else
	BotanDH_PrivateKey(const Botan::AlgorithmIdentifier& alg_id,
			   const Botan::MemoryRegion<Botan::byte>& key_bits,
			   Botan::RandomNumberGenerator& rng);
#endif

	BotanDH_PrivateKey(Botan::RandomNumberGenerator& rng,
			   const Botan::DL_Group& grp,
			   const Botan::BigInt& x = 0);

	~BotanDH_PrivateKey();

	Botan::DH_PrivateKey* impl;
};

class BotanDHPrivateKey : public DHPrivateKey
{
public:
	// Constructors
	BotanDHPrivateKey();

	BotanDHPrivateKey(const BotanDH_PrivateKey* inDH);

	// Destructor
	virtual ~BotanDHPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the DH private key components
	virtual void setX(const ByteString& inX);

	// Setters for the DH public key components
	virtual void setP(const ByteString& inP);
	virtual void setG(const ByteString& inG);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Set from Botan representation
	virtual void setFromBotan(const BotanDH_PrivateKey* inDH);

	// Retrieve the Botan representation of the key
	BotanDH_PrivateKey* getBotanKey();

private:
	// The internal Botan representation
	BotanDH_PrivateKey* dh;

	// Create the Botan representation of the key
	void createBotanKey();
};

#endif // !_SOFTHSM_V2_BOTANDHPRIVATEKEY_H

