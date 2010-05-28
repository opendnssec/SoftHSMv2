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
 BotanRSAPrivateKey.cpp

 Botan RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanRSAPrivateKey.h"
#include "BotanUtil.h"
#include "BotanRNG.h"
#include "BotanCryptoFactory.h"
#include <string.h>

// Constructors
BotanRSAPrivateKey::BotanRSAPrivateKey()
{
	rsa = NULL;
}

BotanRSAPrivateKey::BotanRSAPrivateKey(const Botan::RSA_PrivateKey* inRSA)
{
	BotanRSAPrivateKey::BotanRSAPrivateKey();

	setFromBotan(inRSA);
}

// Destructor
BotanRSAPrivateKey::~BotanRSAPrivateKey()
{
	delete rsa;
}

// The type
/*static*/ const char* BotanRSAPrivateKey::type = "Botan RSA Private Key";

// Set from Botan representation
void BotanRSAPrivateKey::setFromBotan(const Botan::RSA_PrivateKey* rsa)
{
	ByteString p = BotanUtil::bigInt2ByteString(rsa->get_p());
	setP(p);
	ByteString q = BotanUtil::bigInt2ByteString(rsa->get_q());
	setQ(q);
	ByteString dp1 = BotanUtil::bigInt2ByteString(rsa->get_d1());
	setDP1(dp1);
	ByteString dq1 = BotanUtil::bigInt2ByteString(rsa->get_d2());
	setDQ1(dq1);
	ByteString pq = BotanUtil::bigInt2ByteString(rsa->get_c());
	setPQ(pq);
	ByteString d = BotanUtil::bigInt2ByteString(rsa->get_d());
	setD(d);
	ByteString n = BotanUtil::bigInt2ByteString(rsa->get_n());
	setN(n);
	ByteString e = BotanUtil::bigInt2ByteString(rsa->get_e());
	setE(e);
}

// Check if the key is of the given type
bool BotanRSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(BotanRSAPrivateKey::type, type);
}

// Setters for the RSA private key components
void BotanRSAPrivateKey::setP(const ByteString& p)
{
	RSAPrivateKey::setP(p);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setQ(const ByteString& q)
{
	RSAPrivateKey::setQ(q);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setPQ(const ByteString& pq)
{
	RSAPrivateKey::setPQ(pq);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setDP1(const ByteString& dp1)
{
	RSAPrivateKey::setDP1(dp1);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setDQ1(const ByteString& dq1)
{
	RSAPrivateKey::setDQ1(dq1);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setD(const ByteString& d)
{
	RSAPrivateKey::setD(d);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}


// Setters for the RSA public key components
void BotanRSAPrivateKey::setN(const ByteString& n)
{
	RSAPrivateKey::setN(n);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setE(const ByteString& e)
{
	RSAPrivateKey::setE(e);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

// Retrieve the Botan representation of the key
Botan::RSA_PrivateKey* BotanRSAPrivateKey::getBotanKey()
{
	if (!rsa)
	{
		createBotanKey();
	}

	return rsa;
}

// Create the Botan representation of the key
void BotanRSAPrivateKey::createBotanKey()
{
	// d and n is not needed, they can be calculated
	if (this->p.size() != 0 &&
	    this->q.size() != 0 &&
	    this->e.size() != 0)
	{
		if (rsa)
		{
			delete rsa;
			rsa = NULL;
		}

		try
		{
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			rsa = new Botan::RSA_PrivateKey(*rng->getRNG(),
						BotanUtil::byteString2bigInt(this->p), 
						BotanUtil::byteString2bigInt(this->q), 
						BotanUtil::byteString2bigInt(this->e), 
						BotanUtil::byteString2bigInt(this->d), 
						BotanUtil::byteString2bigInt(this->n));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan private key");
		}
        }
}
