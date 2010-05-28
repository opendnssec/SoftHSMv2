/* $Id$ */

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

// Constructors
BotanDSAPrivateKey::BotanDSAPrivateKey()
{
	dsa = NULL;
}

BotanDSAPrivateKey::BotanDSAPrivateKey(const Botan::DSA_PrivateKey* inDSA)
{
	BotanDSAPrivateKey::BotanDSAPrivateKey();

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
void BotanDSAPrivateKey::setFromBotan(const Botan::DSA_PrivateKey* dsa)
{
	ByteString p = BotanUtil::bigInt2ByteString(dsa->group_p());
	setP(p);
	ByteString q = BotanUtil::bigInt2ByteString(dsa->group_q());
	setQ(q);
	ByteString g = BotanUtil::bigInt2ByteString(dsa->group_g());
	setG(g);
	ByteString x = BotanUtil::bigInt2ByteString(dsa->get_x());
	setX(x);
	ByteString y = BotanUtil::bigInt2ByteString(dsa->get_y());
	setY(y);
}

// Check if the key is of the given type
bool BotanDSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(BotanDSAPrivateKey::type, type);
}

// Setters for the DSA private key components
void BotanDSAPrivateKey::setX(const ByteString& x)
{
	DSAPrivateKey::setX(x);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}


// Setters for the DSA public key components
void BotanDSAPrivateKey::setP(const ByteString& p)
{
	DSAPrivateKey::setP(p);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPrivateKey::setQ(const ByteString& q)
{
	DSAPrivateKey::setQ(q);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPrivateKey::setG(const ByteString& g)
{
	DSAPrivateKey::setG(g);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPrivateKey::setY(const ByteString& y)
{
	DSAPrivateKey::setY(y);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
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
	if (this->p.size() != 0 &&
	    this->q.size() != 0 &&
	    this->g.size() != 0 &&
	    this->x.size() != 0)
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
							Botan::DL_Group(BotanUtil::byteString2bigInt(this->p),
							BotanUtil::byteString2bigInt(this->q),
							BotanUtil::byteString2bigInt(this->g)),
							BotanUtil::byteString2bigInt(this->x));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
