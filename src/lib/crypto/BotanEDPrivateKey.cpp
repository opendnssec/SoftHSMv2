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
 BotanEDPrivateKey.cpp

 Botan EDDSA private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "log.h"
#include "BotanEDPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>
#include <botan/pkcs8.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/asn1_oid.h>
#include <botan/oids.h>
#include <botan/pkcs8.h>
#include <botan/version.h>
#include <botan/curve25519.h>
#include <botan/ed25519.h>
// #include <botan/curve448.h>
// #include <botan/ed448.h>

const Botan::OID x25519_oid("1.3.101.110");
// const Botan::OID x448_oid("1.3.101.111");
const Botan::OID ed25519_oid("1.3.101.112");
// const Botan::OID ed448_oid("1.3.101.113");

// Constructors
BotanEDPrivateKey::BotanEDPrivateKey()
{
	edkey = NULL;
}

BotanEDPrivateKey::BotanEDPrivateKey(const Botan::Private_Key* inEDKEY)
{
	edkey = NULL;

	setFromBotan(inEDKEY);
}

// Destructor
BotanEDPrivateKey::~BotanEDPrivateKey()
{
	delete edkey;
}

// The type
/*static*/ const char* BotanEDPrivateKey::type = "Botan EDDSA Private Key";

// Get the base point order length
unsigned long BotanEDPrivateKey::getOrderLength() const
{
	// Only Ed25519 is supported
	return 32;
}

// Set from Botan representation
void BotanEDPrivateKey::setFromBotan(const Botan::Private_Key* inEDKEY)
{
	Botan::OID oid;
	Botan::secure_vector<uint8_t> priv;

	for (;;)
	{
		const Botan::Curve25519_PrivateKey* x25519 = dynamic_cast<const Botan::Curve25519_PrivateKey*>(inEDKEY);
		if (x25519) {
			oid = x25519_oid;
			priv = x25519->get_x();
			break;
		}
		const Botan::Ed25519_PrivateKey* ed25519 = dynamic_cast<const Botan::Ed25519_PrivateKey*>(inEDKEY);
		if (ed25519) {
			oid = ed25519_oid;
			priv = ed25519->get_private_key();
			// Botan returns public part too
			priv.resize(32);
			break;
		}
		return;
	}
	ByteString inEC = BotanUtil::oid2ByteString(oid);
	setEC(inEC);
	ByteString inK;
	inK.resize(priv.size());
	memcpy(&inK[0], &priv[0], priv.size());
	setK(inK);
}

// Check if the key is of the given type
bool BotanEDPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EDDSA private key components
void BotanEDPrivateKey::setK(const ByteString& inK)
{
	EDPrivateKey::setK(inK);

	if (edkey)
	{
		delete edkey;
		edkey = NULL;
	}
}

// Setters for the EDDSA public key components
void BotanEDPrivateKey::setEC(const ByteString& inEC)
{
	EDPrivateKey::setEC(inEC);

	if (edkey)
	{
		delete edkey;
		edkey = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString BotanEDPrivateKey::PKCS8Encode()
{
	ByteString der;
	createBotanKey();
	if (edkey == NULL) return der;
	const Botan::secure_vector<Botan::byte> ber = Botan::PKCS8::BER_encode(*edkey);
	der.resize(ber.size());
	memcpy(&der[0], &ber[0], ber.size());
	return der;
}

// Decode from PKCS#8 BER
bool BotanEDPrivateKey::PKCS8Decode(const ByteString& ber)
{
	Botan::DataSource_Memory source(ber.const_byte_str(), ber.size());
	if (source.end_of_data()) return false;
	Botan::secure_vector<Botan::byte> keydata;
	Botan::AlgorithmIdentifier alg_id;
	Botan::Private_Key* key = NULL;
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
		if (alg_id.oid == x25519_oid)
		{
		  key = new Botan::Curve25519_PrivateKey(alg_id, keydata);
		}
		else if (alg_id.oid == ed25519_oid)
		{
		  key = new Botan::Ed25519_PrivateKey(alg_id, keydata);
		}
		else
		{
			ERROR_MSG("Decoded private key not Ed25519");

			return false;
		}
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
Botan::Private_Key* BotanEDPrivateKey::getBotanKey()
{
	if (!edkey)
	{
		createBotanKey();
	}

	return edkey;
}

// Create the Botan representation of the key
void BotanEDPrivateKey::createBotanKey()
{
	if (ec.size() != 0 &&
	    k.size() != 0)
	{
		if (edkey)
		{
			delete edkey;
			edkey = NULL;
		}

		try
		{
			Botan::secure_vector<uint8_t> priv(k.size());
			memcpy(&priv[0], k.const_byte_str(), k.size());
			Botan::OID oid = BotanUtil::byteString2Oid(ec);
			if (oid == x25519_oid)
			{
				edkey = new Botan::Curve25519_PrivateKey(priv);
			}
			else if (oid == ed25519_oid)
			{
				edkey = new Botan::Ed25519_PrivateKey(priv);
			}
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan private key");
		}
	}
}
#endif
