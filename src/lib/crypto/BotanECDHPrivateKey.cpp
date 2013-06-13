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
 BotanECDHPrivateKey.cpp

 Botan ECDH private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "BotanECDHPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanECDHPrivateKey::BotanECDHPrivateKey()
{
	eckey = NULL;
}

BotanECDHPrivateKey::BotanECDHPrivateKey(const Botan::ECDH_PrivateKey* inECKEY)
{
	BotanECDHPrivateKey();

	setFromBotan(inECKEY);
}

// Destructor
BotanECDHPrivateKey::~BotanECDHPrivateKey()
{
	delete eckey;
}

// The type
/*static*/ const char* BotanECDHPrivateKey::type = "Botan ECDH Private Key";

// Get the base point order length
unsigned long BotanECDHPrivateKey::getOrderLength() const
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

// Set from Botan representation
void BotanECDHPrivateKey::setFromBotan(const Botan::ECDH_PrivateKey* eckey)
{
	ByteString ec = BotanUtil::ecGroup2ByteString(eckey->domain());
	setEC(ec);
	ByteString d = BotanUtil::bigInt2ByteString(eckey->private_value());
	setD(d);
}

// Check if the key is of the given type
bool BotanECDHPrivateKey::isOfType(const char* type)
{
	return !strcmp(BotanECDHPrivateKey::type, type);
}

// Setters for the ECDH private key components
void BotanECDHPrivateKey::setD(const ByteString& d)
{
	ECPrivateKey::setD(d);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}


// Setters for the ECDH public key components
void BotanECDHPrivateKey::setEC(const ByteString& ec)
{
	ECPrivateKey::setEC(ec);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::ECDH_PrivateKey* BotanECDHPrivateKey::getBotanKey()
{
	if (!eckey)
	{
		createBotanKey();
	}

	return eckey;
}

// Create the Botan representation of the key
void BotanECDHPrivateKey::createBotanKey()
{
	if (this->ec.size() != 0 &&
	    this->d.size() != 0)
	{
		if (eckey)   
		{
			delete eckey;
			eckey = NULL;
		}

		try
		{
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			Botan::EC_Group group = BotanUtil::byteString2ECGroup(this->ec);
			eckey = new Botan::ECDH_PrivateKey(*rng->getRNG(),
							group,
							BotanUtil::byteString2bigInt(this->d));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
#endif
