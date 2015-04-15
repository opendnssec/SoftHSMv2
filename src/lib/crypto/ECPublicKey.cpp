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
 ECPublicKey.cpp

 Elliptic Curve public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "ECPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* ECPublicKey::type = "Abstract EC public key";

// Check if the key is of the given type
bool ECPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long ECPublicKey::getBitLength() const
{
	return getQ().size() * 8;
}

// Get the output length
unsigned long ECPublicKey::getOutputLength() const
{
	return getOrderLength() * 2;
}

// Setters for the EC public key components
void ECPublicKey::setEC(const ByteString& inEC)
{
	ec = inEC;
}

void ECPublicKey::setQ(const ByteString& inQ)
{
	q = inQ;
}

// Getters for the EC public key components
const ByteString& ECPublicKey::getEC() const
{
	return ec;
}

const ByteString& ECPublicKey::getQ() const
{
	return q;
}

// Serialisation
ByteString ECPublicKey::serialise() const
{
	return ec.serialise() +
	       q.serialise();
}

bool ECPublicKey::deserialise(ByteString& serialised)
{
	ByteString dEC = ByteString::chainDeserialise(serialised);
	ByteString dQ = ByteString::chainDeserialise(serialised);

	if ((dEC.size() == 0) ||
	    (dQ.size() == 0))
	{
		return false;
	}

	setEC(dEC);
	setQ(dQ);

	return true;
}

