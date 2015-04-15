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
 BotanGOSTPrivateKey.cpp

 Botan GOST R 34.10-2001 private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "BotanGOSTPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanGOSTPrivateKey::BotanGOSTPrivateKey()
{
	eckey = NULL;
}

BotanGOSTPrivateKey::BotanGOSTPrivateKey(const Botan::GOST_3410_PrivateKey* inECKEY)
{
	BotanGOSTPrivateKey();

	setFromBotan(inECKEY);
}

// Destructor
BotanGOSTPrivateKey::~BotanGOSTPrivateKey()
{
	delete eckey;
}

// The type
/*static*/ const char* BotanGOSTPrivateKey::type = "Botan GOST Private Key";

// Get the base point order length
unsigned long BotanGOSTPrivateKey::getOrderLength() const
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

// Get the output length
unsigned long BotanGOSTPrivateKey::getOutputLength() const
{
	return getOrderLength() * 2;
}

// Set from Botan representation
void BotanGOSTPrivateKey::setFromBotan(const Botan::GOST_3410_PrivateKey* inECKEY)
{
	ByteString inEC = BotanUtil::ecGroup2ByteString(inECKEY->domain());
	setEC(inEC);
	ByteString inD = BotanUtil::bigInt2ByteStringPrefix(inECKEY->private_value(), 32);
	setD(inD);
}

// Check if the key is of the given type
bool BotanGOSTPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the GOST private key components
void BotanGOSTPrivateKey::setD(const ByteString& inD)
{
	GOSTPrivateKey::setD(inD);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}


// Setters for the GOST public key components
void BotanGOSTPrivateKey::setEC(const ByteString& inEC)
{
	GOSTPrivateKey::setEC(inEC);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Serialisation
ByteString BotanGOSTPrivateKey::serialise() const
{
	return ec.serialise() +
	       d.serialise();
}

bool BotanGOSTPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dEC = ByteString::chainDeserialise(serialised);
	ByteString dD = ByteString::chainDeserialise(serialised);

	if ((dEC.size() == 0) ||
	    (dD.size() == 0))
	{
		return false;
	}

	setEC(dEC);
	setD(dD);

	return true;
}

// Encode into PKCS#8 DER
ByteString BotanGOSTPrivateKey::PKCS8Encode()
{
	ByteString der;
	// TODO
	return der;
}

// Decode from PKCS#8 BER
bool BotanGOSTPrivateKey::PKCS8Decode(const ByteString& /*ber*/)
{
	return false;
}

// Retrieve the Botan representation of the key
Botan::GOST_3410_PrivateKey* BotanGOSTPrivateKey::getBotanKey()
{
	if (!eckey)
	{
		createBotanKey();
	}

	return eckey;
}

// Create the Botan representation of the key
void BotanGOSTPrivateKey::createBotanKey()
{
	if (ec.size() != 0 &&
	    d.size() != 0)
	{
		if (eckey)
		{
			delete eckey;
			eckey = NULL;
		}

		try
		{
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			Botan::EC_Group group = BotanUtil::byteString2ECGroup(ec);
			eckey = new Botan::GOST_3410_PrivateKey(*rng->getRNG(),
							group,
							BotanUtil::byteString2bigInt(d));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
#endif
