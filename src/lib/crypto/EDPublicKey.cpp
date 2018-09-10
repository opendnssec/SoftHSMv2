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
 EDPublicKey.cpp

 EDDSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "EDPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* EDPublicKey::type = "Abstract EDDSA public key";

// Check if the key is of the given type
bool EDPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long EDPublicKey::getBitLength() const
{
	return getA().size() * 8;
}

// Get the output length
unsigned long EDPublicKey::getOutputLength() const
{
	return getOrderLength() * 2;
}

// Setters for the EC public key components
void EDPublicKey::setEC(const ByteString& inEC)
{
	ec = inEC;
}

void EDPublicKey::setA(const ByteString& inA)
{
	a = inA;
}

// Getters for the EC public key components
const ByteString& EDPublicKey::getEC() const
{
	return ec;
}

const ByteString& EDPublicKey::getA() const
{
	return a;
}

// Serialisation
ByteString EDPublicKey::serialise() const
{
	return ec.serialise() +
	       a.serialise();
}

bool EDPublicKey::deserialise(ByteString& serialised)
{
	ByteString dEC = ByteString::chainDeserialise(serialised);
	ByteString dA = ByteString::chainDeserialise(serialised);

	if ((dEC.size() == 0) ||
	    (dA.size() == 0))
	{
		return false;
	}

	setEC(dEC);
	setA(dA);

	return true;
}

