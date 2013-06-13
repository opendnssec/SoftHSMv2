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

// Constructors
BotanDHPrivateKey::BotanDHPrivateKey()
{
	dh = NULL;
}

BotanDHPrivateKey::BotanDHPrivateKey(const Botan::DH_PrivateKey* inDH)
{
	BotanDHPrivateKey();

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
void BotanDHPrivateKey::setFromBotan(const Botan::DH_PrivateKey* dh)
{
	ByteString p = BotanUtil::bigInt2ByteString(dh->group_p());
	setP(p);
	ByteString g = BotanUtil::bigInt2ByteString(dh->group_g());
	setG(g);
	ByteString x = BotanUtil::bigInt2ByteString(dh->get_x());
	setX(x);
}

// Check if the key is of the given type
bool BotanDHPrivateKey::isOfType(const char* type)
{
	return !strcmp(BotanDHPrivateKey::type, type);
}

// Setters for the DH private key components
void BotanDHPrivateKey::setX(const ByteString& x)
{
	DHPrivateKey::setX(x);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}


// Setters for the DH public key components
void BotanDHPrivateKey::setP(const ByteString& p)
{
	DHPrivateKey::setP(p);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void BotanDHPrivateKey::setG(const ByteString& g)
{
	DHPrivateKey::setG(g);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::DH_PrivateKey* BotanDHPrivateKey::getBotanKey()
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
	if (this->p.size() != 0 &&
	    this->g.size() != 0 &&
	    this->x.size() != 0)
	{
		if (dh)   
		{
			delete dh;
			dh = NULL;
		}

		try
		{
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			dh = new Botan::DH_PrivateKey(*rng->getRNG(),
						      Botan::DL_Group(BotanUtil::byteString2bigInt(this->p),
						      BotanUtil::byteString2bigInt(this->g)),
						      BotanUtil::byteString2bigInt(this->x));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
