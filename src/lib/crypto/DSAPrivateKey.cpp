/* $Id$ */

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
bool DSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(this->type, type);
}

// Setters for the DSA private key components
void DSAPrivateKey::setX(const ByteString& x)
{
	this->x = x;
}

// Setters for the DSA public key components
void DSAPrivateKey::setP(const ByteString& p)
{
	this->p = p;
}

void DSAPrivateKey::setQ(const ByteString& q)
{
	this->q = q;
}

void DSAPrivateKey::setG(const ByteString& g)
{
	this->g = g;
}

void DSAPrivateKey::setY(const ByteString& y)
{
	this->y = y;
}

// Getters for the DSA private key components
const ByteString& DSAPrivateKey::getX() const
{
	return x;
}

// Getters for the DSA public key components
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

const ByteString& DSAPrivateKey::getY() const
{
	return y;
}

// Serialisation
ByteString DSAPrivateKey::serialise() const
{
	return p.serialise() +
	       q.serialise() +
	       g.serialise() +
	       x.serialise() +
	       y.serialise();
}

bool DSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dP = ByteString::chainDeserialise(serialised);
	ByteString dQ = ByteString::chainDeserialise(serialised);
	ByteString dG = ByteString::chainDeserialise(serialised);
	ByteString dX = ByteString::chainDeserialise(serialised);
	ByteString dY = ByteString::chainDeserialise(serialised);

	if ((dP.size() == 0) ||
	    (dQ.size() == 0) ||
	    (dG.size() == 0) ||
	    (dX.size() == 0) ||
	    (dY.size() == 0))
	{
		return false;
	}

	setP(dP);
	setQ(dQ);
	setG(dG);
	setX(dX);
	setY(dY);

	return true;
}

