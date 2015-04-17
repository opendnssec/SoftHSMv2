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
 RSAPrivateKey.cpp

 RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "RSAPrivateKey.h"
#include <string.h>

// Set the type
/*static*/ const char* RSAPrivateKey::type = "Abstract RSA private key";

// Check if the key is of the given type
bool RSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long RSAPrivateKey::getBitLength() const
{
	return getN().bits();
}

// Get the output length
unsigned long RSAPrivateKey::getOutputLength() const
{
	// Also handle odd number of bits (bits % 8 != 0)
	return (getBitLength() + 7) / 8;
}

// Setters for the RSA private key components
void RSAPrivateKey::setP(const ByteString& inP)
{
	p = inP;
}

void RSAPrivateKey::setQ(const ByteString& inQ)
{
	q = inQ;
}

void RSAPrivateKey::setPQ(const ByteString& inPQ)
{
	pq = inPQ;
}

void RSAPrivateKey::setDP1(const ByteString& inDP1)
{
	dp1 = inDP1;
}

void RSAPrivateKey::setDQ1(const ByteString& inDQ1)
{
	dq1 = inDQ1;
}

void RSAPrivateKey::setD(const ByteString& inD)
{
	d = inD;
}

// Setters for the RSA public key components
void RSAPrivateKey::setN(const ByteString& inN)
{
	n = inN;
}

void RSAPrivateKey::setE(const ByteString& inE)
{
	e = inE;
}

// Getters for the RSA private key components
const ByteString& RSAPrivateKey::getP() const
{
	return p;
}

const ByteString& RSAPrivateKey::getQ() const
{
	return q;
}

const ByteString& RSAPrivateKey::getPQ() const
{
	return pq;
}

const ByteString& RSAPrivateKey::getDP1() const
{
	return dp1;
}

const ByteString& RSAPrivateKey::getDQ1() const
{
	return dq1;
}

const ByteString& RSAPrivateKey::getD() const
{
	return d;
}

// Getters for the RSA public key components
const ByteString& RSAPrivateKey::getN() const
{
	return n;
}

const ByteString& RSAPrivateKey::getE() const
{
	return e;
}

// Serialisation
ByteString RSAPrivateKey::serialise() const
{
	return p.serialise() +
	       q.serialise() +
	       pq.serialise() +
	       dp1.serialise() +
	       dq1.serialise() +
	       d.serialise() +
	       n.serialise() +
	       e.serialise();
}

bool RSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dP = ByteString::chainDeserialise(serialised);
	ByteString dQ = ByteString::chainDeserialise(serialised);
	ByteString dPQ = ByteString::chainDeserialise(serialised);
	ByteString dDP1 = ByteString::chainDeserialise(serialised);
	ByteString dDQ1 = ByteString::chainDeserialise(serialised);
	ByteString dD = ByteString::chainDeserialise(serialised);
	ByteString dN = ByteString::chainDeserialise(serialised);
	ByteString dE = ByteString::chainDeserialise(serialised);

	if ((dD.size() == 0) ||
	    (dN.size() == 0) ||
	    (dE.size() == 0))
	{
		return false;
	}

	setP(dP);
	setQ(dQ);
	setPQ(dPQ);
	setDP1(dDP1);
	setDQ1(dDQ1);
	setD(dD);
	setN(dN);
	setE(dE);

	return true;
}

