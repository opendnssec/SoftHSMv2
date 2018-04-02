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
 BotanEDPublicKey.cpp

 Botan EDDSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "log.h"
#include "BotanEDPublicKey.h"
#include "BotanUtil.h"
#include "DerUtil.h"
#include <string.h>
#include <botan/curve25519.h>
#include <botan/ed25519.h>
// #include <botan/curve448.h>
// #include <botan/ed448.h>

const Botan::OID x25519_oid("1.3.101.110");
// const Botan::OID x448_oid("1.3.101.111");
const Botan::OID ed25519_oid("1.3.101.112");
// const Botan::OID ed448_oid("1.3.101.113");

// Constructors
BotanEDPublicKey::BotanEDPublicKey()
{
	edkey = NULL;
}

BotanEDPublicKey::BotanEDPublicKey(const Botan::Public_Key* inEDKEY)
{
	edkey = NULL;

	setFromBotan(inEDKEY);
}

// Destructor
BotanEDPublicKey::~BotanEDPublicKey()
{
	delete edkey;
}

// The type
/*static*/ const char* BotanEDPublicKey::type = "Botan EDDSA Public Key";

// Get the base point order length
unsigned long BotanEDPublicKey::getOrderLength() const
{
	// Only Ed25519 is supported
	return 32;
}

// Set from Botan representation
void BotanEDPublicKey::setFromBotan(const Botan::Public_Key* inEDKEY)
{
	Botan::OID oid;
	std::vector<uint8_t> pub;

	for (;;)
	{
		const Botan::Curve25519_PublicKey* x25519 = dynamic_cast<const Botan::Curve25519_PublicKey*>(inEDKEY);
		if (x25519) {
			oid = x25519_oid;
			pub = x25519->public_value();
			break;
		}
		const Botan::Ed25519_PublicKey* ed25519 = dynamic_cast<const Botan::Ed25519_PublicKey*>(inEDKEY);
		if (ed25519) {
			oid = ed25519_oid;
			pub = ed25519->get_public_key();
			break;
		}
		return;
	}
	ByteString inEC = BotanUtil::oid2ByteString(oid);
	setEC(inEC);
	ByteString inA;
	inA.resize(pub.size());
	memcpy(&inA[0], &pub[0], pub.size());
	setA(DERUTIL::raw2Octet(inA));
}

// Check if the key is of the given type
bool BotanEDPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EDDSA public key components
void BotanEDPublicKey::setEC(const ByteString& inEC)
{
	EDPublicKey::setEC(inEC);

	if (edkey)
	{
		delete edkey;
		edkey = NULL;
	}
}

void BotanEDPublicKey::setA(const ByteString& inA)
{
	EDPublicKey::setA(inA);

	if (edkey)
	{
		delete edkey;
		edkey = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::Public_Key* BotanEDPublicKey::getBotanKey()
{
	if (!edkey)
	{
		createBotanKey();
	}

	return edkey;
}

// Create the Botan representation of the key
void BotanEDPublicKey::createBotanKey()
{
	if (ec.size() != 0 &&
	    a.size() != 0)
	{
		if (edkey)
		{
			delete edkey;
			edkey = NULL;
		}

		try
		{
			ByteString raw = DERUTIL::octet2Raw(a);
			size_t len = raw.size();
			if (len == 0) return;

			std::vector<uint8_t> pub(len);
			memcpy(&pub[0], raw.const_byte_str(), len);
			Botan::OID oid = BotanUtil::byteString2Oid(ec);
			if (oid == x25519_oid)
			{
				edkey = new Botan::Curve25519_PublicKey(pub);
			}
			else if (oid == ed25519_oid)
			{
				edkey = new Botan::Ed25519_PublicKey(pub);
			}
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
#endif
