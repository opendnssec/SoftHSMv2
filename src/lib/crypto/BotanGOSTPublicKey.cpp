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
 BotanGOSTPublicKey.cpp

 Botan GOST R 34.10-2001 public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "BotanGOSTPublicKey.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanGOSTPublicKey::BotanGOSTPublicKey()
{
	eckey = NULL;
}

BotanGOSTPublicKey::BotanGOSTPublicKey(const Botan::GOST_3410_PublicKey* inECKEY)
{
	BotanGOSTPublicKey();

	setFromBotan(inECKEY);
}

// Destructor
BotanGOSTPublicKey::~BotanGOSTPublicKey()
{
	delete eckey;
}

// The type
/*static*/ const char* BotanGOSTPublicKey::type = "Botan GOST Public Key";

// Get the base point order length
unsigned long BotanGOSTPublicKey::getOrderLength() const
{
	try
	{
		Botan::EC_Group group = BotanUtil::byteString2ECGroup(this->ec);
		return group.get_order().bytes();
			
	}
	catch (...)
	{
		ERROR_MSG("Can't get EC group for order length");

		return 0;
	}
}

// Get the output length
unsigned long BotanGOSTPublicKey::getOutputLength() const
{
	return this->getOrderLength() * 2;
}

// Set from Botan representation
void BotanGOSTPublicKey::setFromBotan(const Botan::GOST_3410_PublicKey* eckey)
{
	ByteString ec = BotanUtil::ecGroup2ByteString(eckey->domain());
	setEC(ec);
	ByteString q = BotanUtil::ecPoint2ByteString(eckey->public_point());
	setQ(q.substr(3));
}

// Check if the key is of the given type
bool BotanGOSTPublicKey::isOfType(const char* type)
{
	return !strcmp(BotanGOSTPublicKey::type, type);
}

// Setters for the GOST public key components
void BotanGOSTPublicKey::setEC(const ByteString& ec)
{
	this->ec = ec;

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

void BotanGOSTPublicKey::setQ(const ByteString& q)
{
	GOSTPublicKey::setQ(q);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Serialisation
ByteString BotanGOSTPublicKey::serialise() const
{
	return ec.serialise() +
	       q.serialise();
}

bool BotanGOSTPublicKey::deserialise(ByteString& serialised)
{
	ByteString dEC = ByteString::chainDeserialise(serialised);
	ByteString dQ = ByteString::chainDeserialise(serialised);

	if ((dEC.size() == 0) ||
	    (dQ.size() == 0))
	{
		return false;
	}

	setEC(dEC);
	setQ(dQ);

	return true;
}

// Retrieve the Botan representation of the key
Botan::GOST_3410_PublicKey* BotanGOSTPublicKey::getBotanKey()
{
	if (!eckey)
	{
		createBotanKey();
	}

	return eckey;
}
 
// Create the Botan representation of the key
void BotanGOSTPublicKey::createBotanKey()
{
	if (this->ec.size() != 0 &&
	    this->q.size() != 0)
	{
		if (eckey)
		{
			delete eckey;
			eckey = NULL;
		}

		try
		{
			Botan::EC_Group group = BotanUtil::byteString2ECGroup(this->ec);
			ByteString p = "044104" + this->q;
			Botan::PointGFp point = BotanUtil::byteString2ECPoint(p, group);
			eckey = new Botan::GOST_3410_PublicKey(group, point);
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
#endif
