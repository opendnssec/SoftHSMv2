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
 BotanRSAPublicKey.cpp

 Botan RSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanRSAPublicKey.h"
#include "BotanUtil.h"
#include <string.h>

// Constructors
BotanRSAPublicKey::BotanRSAPublicKey()
{
	rsa = NULL;
}

BotanRSAPublicKey::BotanRSAPublicKey(const Botan::RSA_PublicKey* inRSA)
{
	rsa = NULL;

	setFromBotan(inRSA);
}

// Destructor
BotanRSAPublicKey::~BotanRSAPublicKey()
{
	delete rsa;
}

// The type
/*static*/ const char* BotanRSAPublicKey::type = "Botan RSA Public Key";

// Check if the key is of the given type
bool BotanRSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Set from OpenSSL representation
void BotanRSAPublicKey::setFromBotan(const Botan::RSA_PublicKey* inRSA)
{
	ByteString inN = BotanUtil::bigInt2ByteString(inRSA->get_n());
	setN(inN);
	ByteString inE = BotanUtil::bigInt2ByteString(inRSA->get_e());
	setE(inE);
}

// Setters for the RSA public key components
void BotanRSAPublicKey::setN(const ByteString& inN)
{
	RSAPublicKey::setN(inN);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPublicKey::setE(const ByteString& inE)
{
	RSAPublicKey::setE(inE);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::RSA_PublicKey* BotanRSAPublicKey::getBotanKey()
{
	if (!rsa)
	{
		createBotanKey();
	}

	return rsa;
}

// Create the Botan representation of the key
void BotanRSAPublicKey::createBotanKey()
{
	if (n.size() != 0 && e.size() != 0)
	{
		if (rsa)
		{
			delete rsa;
			rsa = NULL;
		}

		try
		{
			rsa = new Botan::RSA_PublicKey(BotanUtil::byteString2bigInt(n),
							BotanUtil::byteString2bigInt(e));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
