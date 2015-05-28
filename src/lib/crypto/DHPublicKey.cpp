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
 DHPublicKey.cpp

 Diffie-Hellman public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "DHPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* DHPublicKey::type = "Abstract DH public key";

// Check if the key is of the given type
bool DHPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long DHPublicKey::getBitLength() const
{
	return getP().bits();
}

// Get the output length
unsigned long DHPublicKey::getOutputLength() const
{
	return getP().size();
}

// Setters for the DH public key components
void DHPublicKey::setP(const ByteString& inP)
{
	p = inP;
}

void DHPublicKey::setG(const ByteString& inG)
{
	g = inG;
}

void DHPublicKey::setY(const ByteString& inY)
{
	y = inY;
}

// Getters for the DH public key components
const ByteString& DHPublicKey::getP() const
{
	return p;
}

const ByteString& DHPublicKey::getG() const
{
	return g;
}

const ByteString& DHPublicKey::getY() const
{
	return y;
}

// Serialisation
ByteString DHPublicKey::serialise() const
{
	return p.serialise() +
	       g.serialise() +
	       y.serialise();
}

bool DHPublicKey::deserialise(ByteString& serialised)
{
	ByteString dP = ByteString::chainDeserialise(serialised);
	ByteString dG = ByteString::chainDeserialise(serialised);
	ByteString dY = ByteString::chainDeserialise(serialised);

	if ((dP.size() == 0) ||
	    (dG.size() == 0) ||
	    (dY.size() == 0))
	{
		return false;
	}

	setP(dP);
	setG(dG);
	setY(dY);

	return true;
}

