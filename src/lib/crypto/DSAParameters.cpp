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
 DSAParameters.cpp

 DSA parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "DSAParameters.h"
#include <string.h>

// The type
/*static*/ const char* DSAParameters::type = "Generic DSA parameters";

// Set the public prime p
void DSAParameters::setP(const ByteString& inP)
{
	p = inP;
}

// Set the public subprime q
void DSAParameters::setQ(const ByteString& inQ)
{
	q = inQ;
}

// Set the generator g
void DSAParameters::setG(const ByteString& inG)
{
	g = inG;
}

// Get the public prime p
const ByteString& DSAParameters::getP() const
{
	return p;
}

// Get the public subprime q
const ByteString& DSAParameters::getQ() const
{
	return q;
}

// Get the generator g
const ByteString& DSAParameters::getG() const
{
	return g;
}

// Are the parameters of the given type?
bool DSAParameters::areOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

// Serialisation
ByteString DSAParameters::serialise() const
{
	return p.serialise() + q.serialise() + g.serialise();
}

bool DSAParameters::deserialise(ByteString& serialised)
{
	ByteString dP = ByteString::chainDeserialise(serialised);
	ByteString dQ = ByteString::chainDeserialise(serialised);
	ByteString dG = ByteString::chainDeserialise(serialised);

	if ((dP.size() == 0) ||
	    (dQ.size() == 0) ||
	    (dG.size() == 0))
	{
		return false;
	}

	setP(dP);
	setQ(dQ);
	setG(dG);

	return true;
}

