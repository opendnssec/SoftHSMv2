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
 BotanDHPrivateKey.cpp

 Botan Diffie-Hellman private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanDHPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>
#include <botan/pkcs8.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/version.h>

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
std::vector<Botan::byte> BotanDH_PrivateKey::public_value() const
{
	return impl->public_value();
}
#else
Botan::MemoryVector<Botan::byte> BotanDH_PrivateKey::public_value() const
{
	return impl->public_value();
}
#endif

// Redefine of DH_PrivateKey constructor with the correct format
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
BotanDH_PrivateKey::BotanDH_PrivateKey(
			const Botan::AlgorithmIdentifier& alg_id,
			const Botan::secure_vector<Botan::byte>& key_bits,
			Botan::RandomNumberGenerator& rng) :
	Botan::DL_Scheme_PrivateKey(alg_id, key_bits, Botan::DL_Group::PKCS3_DH_PARAMETERS)
{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,27)
	impl = new Botan::DH_PrivateKey(rng, m_group, m_x);
#else
	impl = new Botan::DH_PrivateKey(rng, group, x);
#endif
}
#else
BotanDH_PrivateKey::BotanDH_PrivateKey(
			const Botan::AlgorithmIdentifier& alg_id,
			const Botan::MemoryRegion<Botan::byte>& key_bits,
			Botan::RandomNumberGenerator& rng) :
	Botan::DL_Scheme_PrivateKey(alg_id, key_bits, Botan::DL_Group::PKCS3_DH_PARAMETERS)
{
	impl = new Botan::DH_PrivateKey(rng, group, x);
}
#endif

BotanDH_PrivateKey::BotanDH_PrivateKey(Botan::RandomNumberGenerator& rng,
				       const Botan::DL_Group& grp,
				       const Botan::BigInt& x_arg)
{
	impl = new Botan::DH_PrivateKey(rng, grp, x_arg);
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,27)
	m_group = grp;
	m_x = x_arg;
	m_y = impl->get_y();
#else
	group = grp;
	x = x_arg;
	y = impl->get_y();
#endif
}

BotanDH_PrivateKey::~BotanDH_PrivateKey()
{
	delete impl;
}

// Constructors
BotanDHPrivateKey::BotanDHPrivateKey()
{
	dh = NULL;
}

BotanDHPrivateKey::BotanDHPrivateKey(const BotanDH_PrivateKey* inDH)
{
	dh = NULL;

	setFromBotan(inDH);
}

// Destructor
BotanDHPrivateKey::~BotanDHPrivateKey()
{
	delete dh;
}

// The type
/*static*/ const char* BotanDHPrivateKey::type = "Botan DH Private Key";

// Set from Botan representation
void BotanDHPrivateKey::setFromBotan(const BotanDH_PrivateKey* inDH)
{
	ByteString inP = BotanUtil::bigInt2ByteString(inDH->impl->group_p());
	setP(inP);
	ByteString inG = BotanUtil::bigInt2ByteString(inDH->impl->group_g());
	setG(inG);
	ByteString inX = BotanUtil::bigInt2ByteString(inDH->impl->get_x());
	setX(inX);
}

// Check if the key is of the given type
bool BotanDHPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DH private key components
void BotanDHPrivateKey::setX(const ByteString& inX)
{
	DHPrivateKey::setX(inX);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Setters for the DH public key components
void BotanDHPrivateKey::setP(const ByteString& inP)
{
	DHPrivateKey::setP(inP);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void BotanDHPrivateKey::setG(const ByteString& inG)
{
	DHPrivateKey::setG(inG);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString BotanDHPrivateKey::PKCS8Encode()
{
	ByteString der;
	createBotanKey();
	if (dh == NULL) return der;
	// Force PKCS3_DH_PARAMETERS for p, g and no q.
	const size_t PKCS8_VERSION = 0;
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(2,0,0)
	const std::vector<Botan::byte> parameters = dh->impl->get_domain().DER_encode(Botan::DL_Group::PKCS3_DH_PARAMETERS);
	const Botan::AlgorithmIdentifier alg_id(dh->impl->get_oid(), parameters);
	const Botan::secure_vector<Botan::byte> ber =
		Botan::DER_Encoder()
		.start_cons(Botan::SEQUENCE)
		    .encode(PKCS8_VERSION)
		    .encode(alg_id)
		    .encode(dh->impl->private_key_bits(), Botan::OCTET_STRING)
		.end_cons()
	    .get_contents();
#elif BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	const std::vector<Botan::byte> parameters = dh->impl->get_domain().DER_encode(Botan::DL_Group::PKCS3_DH_PARAMETERS);
	const Botan::AlgorithmIdentifier alg_id(dh->impl->get_oid(), parameters);
	const Botan::secure_vector<Botan::byte> ber =
		Botan::DER_Encoder()
		.start_cons(Botan::SEQUENCE)
		    .encode(PKCS8_VERSION)
		    .encode(alg_id)
		    .encode(dh->impl->pkcs8_private_key(), Botan::OCTET_STRING)
		.end_cons()
	    .get_contents();
#else
	const Botan::MemoryVector<Botan::byte> parameters = dh->impl->get_domain().DER_encode(Botan::DL_Group::PKCS3_DH_PARAMETERS);
	const Botan::AlgorithmIdentifier alg_id(dh->impl->get_oid(), parameters);
	const Botan::SecureVector<Botan::byte> ber =
		Botan::DER_Encoder()
		.start_cons(Botan::SEQUENCE)
		    .encode(PKCS8_VERSION)
		    .encode(alg_id)
		    .encode(dh->impl->pkcs8_private_key(), Botan::OCTET_STRING)
		.end_cons()
	    .get_contents();
#endif
	der.resize(ber.size());
	memcpy(&der[0], &ber[0], ber.size());
	return der;
}

// Decode from PKCS#8 BER
bool BotanDHPrivateKey::PKCS8Decode(const ByteString& ber)
{
	Botan::DataSource_Memory source(ber.const_byte_str(), ber.size());
	if (source.end_of_data()) return false;
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	Botan::secure_vector<Botan::byte> keydata;
#else
	Botan::SecureVector<Botan::byte> keydata;
#endif
	Botan::AlgorithmIdentifier alg_id;
	BotanDH_PrivateKey* key = NULL;
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
		if (Botan::OIDS::lookup(alg_id.oid).compare("DH"))
		{
			ERROR_MSG("Decoded private key not DH");

			return false;
		}
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		key = new BotanDH_PrivateKey(alg_id, keydata, *rng->getRNG());
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
BotanDH_PrivateKey* BotanDHPrivateKey::getBotanKey()
{
	if (!dh)
	{
		createBotanKey();
	}

	return dh;
}

// Create the Botan representation of the key
void BotanDHPrivateKey::createBotanKey()
{
	// y is not needed
	if (p.size() != 0 &&
	    g.size() != 0 &&
	    x.size() != 0)
	{
		if (dh)
		{
			delete dh;
			dh = NULL;
		}

		try
		{
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			dh = new BotanDH_PrivateKey(*rng->getRNG(),
				Botan::DL_Group(BotanUtil::byteString2bigInt(p),
						BotanUtil::byteString2bigInt(g)),
				BotanUtil::byteString2bigInt(x));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
