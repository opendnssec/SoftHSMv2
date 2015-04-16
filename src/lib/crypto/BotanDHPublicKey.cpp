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
 BotanDHPublicKey.cpp

 Botan Diffie-Hellman public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanDHPublicKey.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanDHPublicKey::BotanDHPublicKey()
{
	dh = NULL;
}

BotanDHPublicKey::BotanDHPublicKey(const Botan::DH_PublicKey* inDH)
{
	dh = NULL;

	setFromBotan(inDH);
}

// Destructor
BotanDHPublicKey::~BotanDHPublicKey()
{
	delete dh;
}

// The type
/*static*/ const char* BotanDHPublicKey::type = "Botan DH Public Key";

// Set from Botan representation
void BotanDHPublicKey::setFromBotan(const Botan::DH_PublicKey* inDH)
{
	ByteString inP = BotanUtil::bigInt2ByteString(inDH->group_p());
	setP(inP);
	ByteString inG = BotanUtil::bigInt2ByteString(inDH->group_g());
	setG(inG);
	ByteString inY = BotanUtil::bigInt2ByteString(inDH->get_y());
	setY(inY);
}

// Check if the key is of the given type
bool BotanDHPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DH public key components
void BotanDHPublicKey::setP(const ByteString& inP)
{
	DHPublicKey::setP(inP);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void BotanDHPublicKey::setG(const ByteString& inG)
{
	DHPublicKey::setG(inG);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void BotanDHPublicKey::setY(const ByteString& inY)
{
	DHPublicKey::setY(inY);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::DH_PublicKey* BotanDHPublicKey::getBotanKey()
{
	if (!dh)
	{
		createBotanKey();
	}

	return dh;
}

// Create the Botan representation of the key
void BotanDHPublicKey::createBotanKey()
{
	// We actually do not need to check q, since it can be set zero
	if (p.size() != 0 && y.size() != 0)
	{
		if (dh)
		{
			delete dh;
			dh = NULL;
		}

		try
		{
			dh = new Botan::DH_PublicKey(Botan::DL_Group(BotanUtil::byteString2bigInt(p),
							BotanUtil::byteString2bigInt(g)),
							BotanUtil::byteString2bigInt(y));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
