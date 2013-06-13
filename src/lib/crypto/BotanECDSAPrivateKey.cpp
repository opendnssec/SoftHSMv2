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
 BotanECDSAPrivateKey.cpp

 Botan ECDSA private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "BotanECDSAPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanECDSAPrivateKey::BotanECDSAPrivateKey()
{
	eckey = NULL;
}

BotanECDSAPrivateKey::BotanECDSAPrivateKey(const Botan::ECDSA_PrivateKey* inECKEY)
{
	BotanECDSAPrivateKey();

	setFromBotan(inECKEY);
}

// Destructor
BotanECDSAPrivateKey::~BotanECDSAPrivateKey()
{
	delete eckey;
}

// The type
/*static*/ const char* BotanECDSAPrivateKey::type = "Botan ECDSA Private Key";

// Get the base point order length
unsigned long BotanECDSAPrivateKey::getOrderLength() const
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
void BotanECDSAPrivateKey::setFromBotan(const Botan::ECDSA_PrivateKey* eckey)
{
	ByteString ec = BotanUtil::ecGroup2ByteString(eckey->domain());
	setEC(ec);
	ByteString d = BotanUtil::bigInt2ByteString(eckey->private_value());
	setD(d);
}

// Check if the key is of the given type
bool BotanECDSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(BotanECDSAPrivateKey::type, type);
}

// Setters for the ECDSA private key components
void BotanECDSAPrivateKey::setD(const ByteString& d)
{
	ECPrivateKey::setD(d);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}


// Setters for the ECDSA public key components
void BotanECDSAPrivateKey::setEC(const ByteString& ec)
{
	ECPrivateKey::setEC(ec);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::ECDSA_PrivateKey* BotanECDSAPrivateKey::getBotanKey()
{
	if (!eckey)
	{
		createBotanKey();
	}

	return eckey;
}

// Create the Botan representation of the key
void BotanECDSAPrivateKey::createBotanKey()
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
			eckey = new Botan::ECDSA_PrivateKey(*rng->getRNG(),
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
