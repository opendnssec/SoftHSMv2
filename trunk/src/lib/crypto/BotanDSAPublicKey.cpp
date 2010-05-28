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
 BotanDSAPublicKey.cpp

 Botan DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanDSAPublicKey.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanDSAPublicKey::BotanDSAPublicKey()
{
	dsa = NULL;
}

BotanDSAPublicKey::BotanDSAPublicKey(const Botan::DSA_PublicKey* inDSA)
{
	BotanDSAPublicKey::BotanDSAPublicKey();

	setFromBotan(inDSA);
}

// Destructor
BotanDSAPublicKey::~BotanDSAPublicKey()
{
	delete dsa;
}

// The type
/*static*/ const char* BotanDSAPublicKey::type = "Botan DSA Public Key";

// Set from Botan representation
void BotanDSAPublicKey::setFromBotan(const Botan::DSA_PublicKey* dsa)
{
	ByteString p = BotanUtil::bigInt2ByteString(dsa->group_p());
	setP(p);
	ByteString q = BotanUtil::bigInt2ByteString(dsa->group_q());
	setQ(q);
	ByteString g = BotanUtil::bigInt2ByteString(dsa->group_g());
	setG(g);
	ByteString y = BotanUtil::bigInt2ByteString(dsa->get_y());
	setY(y);
}

// Check if the key is of the given type
bool BotanDSAPublicKey::isOfType(const char* type)
{
	return !strcmp(BotanDSAPublicKey::type, type);
}

// Setters for the DSA public key components
void BotanDSAPublicKey::setP(const ByteString& p)
{
	DSAPublicKey::setP(p);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPublicKey::setQ(const ByteString& q)
{
	DSAPublicKey::setQ(q);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPublicKey::setG(const ByteString& g)
{
	DSAPublicKey::setG(g);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void BotanDSAPublicKey::setY(const ByteString& y)
{
	DSAPublicKey::setY(y);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::DSA_PublicKey* BotanDSAPublicKey::getBotanKey()
{
	if (!dsa)
	{
		createBotanKey();
	}

	return dsa;
}
 
// Create the Botan representation of the key
void BotanDSAPublicKey::createBotanKey()
{
	// We actually do not need to check q, since it can be set zero
	if (this->p.size() != 0 &&
	    this->g.size() != 0 &&
	    this->y.size() != 0)
	{
		if (dsa)
		{
			delete dsa;
			dsa = NULL;
		}

		try
		{
			dsa = new Botan::DSA_PublicKey(Botan::DL_Group(BotanUtil::byteString2bigInt(this->p),
							BotanUtil::byteString2bigInt(this->q),
							BotanUtil::byteString2bigInt(this->g)),
							BotanUtil::byteString2bigInt(this->y));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
