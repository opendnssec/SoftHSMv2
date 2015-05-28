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
 BotanECDSAPublicKey.cpp

 Botan ECDSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "BotanECDSAPublicKey.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanECDSAPublicKey::BotanECDSAPublicKey()
{
	eckey = NULL;
}

BotanECDSAPublicKey::BotanECDSAPublicKey(const Botan::ECDSA_PublicKey* inECKEY)
{
	eckey = NULL;

	setFromBotan(inECKEY);
}

// Destructor
BotanECDSAPublicKey::~BotanECDSAPublicKey()
{
	delete eckey;
}

// The type
/*static*/ const char* BotanECDSAPublicKey::type = "Botan ECDSA Public Key";

// Get the base point order length
unsigned long BotanECDSAPublicKey::getOrderLength() const
{
	try
	{
		Botan::EC_Group group = BotanUtil::byteString2ECGroup(ec);
		return group.get_order().bytes();
	}
	catch (...)
	{
		ERROR_MSG("Can't get EC group for order length");

		return 0;
	}
}

// Set from Botan representation
void BotanECDSAPublicKey::setFromBotan(const Botan::ECDSA_PublicKey* inECKEY)
{
	ByteString inEC = BotanUtil::ecGroup2ByteString(inECKEY->domain());
	setEC(inEC);
	ByteString inQ = BotanUtil::ecPoint2ByteString(inECKEY->public_point());
	setQ(inQ);
}

// Check if the key is of the given type
bool BotanECDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the ECDSA public key components
void BotanECDSAPublicKey::setEC(const ByteString& inEC)
{
	ECPublicKey::setEC(inEC);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

void BotanECDSAPublicKey::setQ(const ByteString& inQ)
{
	ECPublicKey::setQ(inQ);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::ECDSA_PublicKey* BotanECDSAPublicKey::getBotanKey()
{
	if (!eckey)
	{
		createBotanKey();
	}

	return eckey;
}
 
// Create the Botan representation of the key
void BotanECDSAPublicKey::createBotanKey()
{
	if (ec.size() != 0 &&
	    q.size() != 0)
	{
		if (eckey)
		{
			delete eckey;
			eckey = NULL;
		}

		try
		{
			Botan::EC_Group group = BotanUtil::byteString2ECGroup(ec);
			Botan::PointGFp point = BotanUtil::byteString2ECPoint(q, group);
			eckey = new Botan::ECDSA_PublicKey(group, point);
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
#endif
