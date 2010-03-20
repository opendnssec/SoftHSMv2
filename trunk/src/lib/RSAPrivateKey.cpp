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
bool RSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(this->type, type);
}

// Setters for the RSA private key components
void RSAPrivateKey::setP(const ByteString& p)
{
	this->p = p;
}

void RSAPrivateKey::setQ(const ByteString& q)
{
	this->q = q;
}

void RSAPrivateKey::setPQ(const ByteString& pq)
{
	this->pq = pq;
}

void RSAPrivateKey::setDP1(const ByteString& dp1)
{
	this->dp1 = dp1;
}

void RSAPrivateKey::setDQ1(const ByteString& dq1)
{
	this->dq1 = dq1;
}

void RSAPrivateKey::setD(const ByteString& d)
{
	this->d = d;
}

// Setters for the RSA public key components
void RSAPrivateKey::setN(const ByteString& n)
{
	this->n = n;
}

void RSAPrivateKey::setE(const ByteString& e)
{
	this->e = e;
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

