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
 BotanDSAPrivateKey.cpp

 Botan DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanDSAPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>
#include <botan/pkcs8.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/version.h>

// Constructors
BotanDSAPrivateKey::BotanDSAPrivateKey()
{
	dsa = NULL;
}

BotanDSAPrivateKey::BotanDSAPrivateKey(const Botan::DSA_PrivateKey* inDSA)
{
	dsa = NULL;

	setFromBotan(inDSA);
}

// Destructor
BotanDSAPrivateKey::~BotanDSAPrivateKey()
{
	delete dsa;
}

// The type
/*static*/ const char* BotanDSAPrivateKey::type = "Botan DSA Private Key";

// Set from Botan representation
void BotanDSAPrivateKey::setFromBotan(const Botan::DSA_PrivateKey* inDSA)
{
	ByteString inP = BotanUtil::bigInt2ByteString(inDSA->group_p());
	setP(inP);
	ByteString inQ = BotanUtil::bigInt2ByteString(inDSA->group_q());
	setQ(inQ);
	ByteString inG = BotanUtil::bigInt2ByteString(inDSA->group_g());
	setG(inG);
	ByteString inX = BotanUtil::bigInt2ByteString(inDSA->get_x());
	setX(inX);
}

// Check if the key is of the given type
bool BotanDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DSA private key components
void BotanDSAPrivateKey::setX(const ByteString& inX)
{
	DSAPrivateKey::setX(inX);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}


// Setters for the DSA domain parameters
void BotanDSAPrivateKey::setP(const ByteString& inP)
{
	DSAPrivateKey::setP(inP);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPrivateKey::setQ(const ByteString& inQ)
{
	DSAPrivateKey::setQ(inQ);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPrivateKey::setG(const ByteString& inG)
{
	DSAPrivateKey::setG(inG);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString BotanDSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	createBotanKey();
	if (dsa == NULL) return der;
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	const Botan::secure_vector<Botan::byte> ber = Botan::PKCS8::BER_encode(*dsa);
#else
	const Botan::SecureVector<Botan::byte> ber = Botan::PKCS8::BER_encode(*dsa);
#endif
	der.resize(ber.size());
	memcpy(&der[0], &ber[0], ber.size());
	return der;
}

// Decode from PKCS#8 BER
bool BotanDSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	Botan::DataSource_Memory source(ber.const_byte_str(), ber.size());
	if (source.end_of_data()) return false;
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	Botan::secure_vector<Botan::byte> keydata;
#else
	Botan::SecureVector<Botan::byte> keydata;
#endif
	Botan::AlgorithmIdentifier alg_id;
	Botan::DSA_PrivateKey* key = NULL;
	try
	{

		Botan::BER_Decoder(source)
		.start_cons(Botan::SEQUENCE)
			.decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
			.decode(alg_id)
			.decode(keydata, Botan::OCTET_STRING)
			.discard_remaining()
		.end_cons();
		if (keydata.empty())
			throw Botan::Decoding_Error("PKCS #8 private key decoding failed");
		if (Botan::OIDS::lookup(alg_id.oid).compare("DSA"))
		{
			ERROR_MSG("Decoded private key not DSA");

			return false;
		}
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,34)
		key = new Botan::DSA_PrivateKey(alg_id, keydata);
#else
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		key = new Botan::DSA_PrivateKey(alg_id, keydata, *rng->getRNG());
#endif
		if (key == NULL) return false;

		setFromBotan(key);

		delete key;
	}
	catch (std::exception& e)
	{
		ERROR_MSG("Decode failed on %s", e.what());

		return false;
	}

	return true;
}

// Retrieve the Botan representation of the key
Botan::DSA_PrivateKey* BotanDSAPrivateKey::getBotanKey()
{
	if (!dsa)
	{
		createBotanKey();
	}

	return dsa;
}

// Create the Botan representation of the key
void BotanDSAPrivateKey::createBotanKey()
{
	// y is not needed
	// Todo: Either q or x is needed. Both is not needed
	if (p.size() != 0 &&
	    q.size() != 0 &&
	    g.size() != 0 &&
	    x.size() != 0)
	{
		if (dsa)
		{
			delete dsa;
			dsa = NULL;
		}

		try
		{
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			dsa = new Botan::DSA_PrivateKey(*rng->getRNG(),
							Botan::DL_Group(BotanUtil::byteString2bigInt(p),
							BotanUtil::byteString2bigInt(q),
							BotanUtil::byteString2bigInt(g)),
							BotanUtil::byteString2bigInt(x));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan private key");
		}
	}
}
