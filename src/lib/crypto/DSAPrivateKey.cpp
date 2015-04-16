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
 DSAPrivateKey.cpp

 DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "DSAPrivateKey.h"
#include <string.h>

// Set the type
/*static*/ const char* DSAPrivateKey::type = "Abstract DSA private key";

// Check if the key is of the given type
bool DSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long DSAPrivateKey::getBitLength() const
{
	return getP().bits();
}

// Get the output length
unsigned long DSAPrivateKey::getOutputLength() const
{
	return getQ().size() * 2;
}

// Setters for the DSA private key components
void DSAPrivateKey::setX(const ByteString& inX)
{
	x = inX;
}

// Setters for the DSA domain parameters
void DSAPrivateKey::setP(const ByteString& inP)
{
	p = inP;
}

void DSAPrivateKey::setQ(const ByteString& inQ)
{
	q = inQ;
}

void DSAPrivateKey::setG(const ByteString& inG)
{
	g = inG;
}

// Getters for the DSA private key components
const ByteString& DSAPrivateKey::getX() const
{
	return x;
}

// Getters for the DSA domain parameters
const ByteString& DSAPrivateKey::getP() const
{
	return p;
}

const ByteString& DSAPrivateKey::getQ() const
{
	return q;
}

const ByteString& DSAPrivateKey::getG() const
{
	return g;
}

// Serialisation
ByteString DSAPrivateKey::serialise() const
{
	return p.serialise() +
	       q.serialise() +
	       g.serialise() +
	       x.serialise();
}

bool DSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dP = ByteString::chainDeserialise(serialised);
	ByteString dQ = ByteString::chainDeserialise(serialised);
	ByteString dG = ByteString::chainDeserialise(serialised);
	ByteString dX = ByteString::chainDeserialise(serialised);

	if ((dP.size() == 0) ||
	    (dQ.size() == 0) ||
	    (dG.size() == 0) ||
	    (dX.size() == 0))
	{
		return false;
	}

	setP(dP);
	setQ(dQ);
	setG(dG);
	setX(dX);

	return true;
}

