/*
 * Copyright (c) 2010 SURFnet bv
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
 DSAPublicKey.cpp

 DSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "DSAPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* DSAPublicKey::type = "Abstract DSA public key";

// Check if the key is of the given type
bool DSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long DSAPublicKey::getBitLength() const
{
	return getP().bits();
}

// Get the output length
unsigned long DSAPublicKey::getOutputLength() const
{
	return getQ().size() * 2;
}

// Setters for the DSA public key components
void DSAPublicKey::setP(const ByteString& inP)
{
	p = inP;
}

void DSAPublicKey::setQ(const ByteString& inQ)
{
	q = inQ;
}

void DSAPublicKey::setG(const ByteString& inG)
{
	g = inG;
}

void DSAPublicKey::setY(const ByteString& inY)
{
	y = inY;
}

// Getters for the DSA public key components
const ByteString& DSAPublicKey::getP() const
{
	return p;
}

const ByteString& DSAPublicKey::getQ() const
{
	return q;
}

const ByteString& DSAPublicKey::getG() const
{
	return g;
}

const ByteString& DSAPublicKey::getY() const
{
	return y;
}

// Serialisation
ByteString DSAPublicKey::serialise() const
{
	return p.serialise() +
	       q.serialise() +
	       g.serialise() +
	       y.serialise();
}

bool DSAPublicKey::deserialise(ByteString& serialised)
{
	ByteString dP = ByteString::chainDeserialise(serialised);
	ByteString dQ = ByteString::chainDeserialise(serialised);
	ByteString dG = ByteString::chainDeserialise(serialised);
	ByteString dY = ByteString::chainDeserialise(serialised);

	if ((dP.size() == 0) ||
	    (dQ.size() == 0) ||
	    (dG.size() == 0) ||
	    (dY.size() == 0))
	{
		return false;
	}

	setP(dP);
	setQ(dQ);
	setG(dG);
	setY(dY);

	return true;
}

