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
 RSAPrivateKey.h

 RSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_RSAPRIVATEKEY_H
#define _SOFTHSM_V2_RSAPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"

class RSAPrivateKey : public PrivateKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Get the output length
	virtual unsigned long getOutputLength() const;

	// Setters for the RSA private key components
	virtual void setP(const ByteString& inP);
	virtual void setQ(const ByteString& inQ);
	virtual void setPQ(const ByteString& inPQ);
	virtual void setDP1(const ByteString& inDP1);
	virtual void setDQ1(const ByteString& inDQ1);
	virtual void setD(const ByteString& inD);

	// Setters for the RSA public key components
	virtual void setN(const ByteString& inN);
	virtual void setE(const ByteString& inE);

	// Getters for the RSA private key components
	virtual const ByteString& getP() const;
	virtual const ByteString& getQ() const;
	virtual const ByteString& getPQ() const;
	virtual const ByteString& getDP1() const;
	virtual const ByteString& getDQ1() const;
	virtual const ByteString& getD() const;

	// Getters for the RSA public key components
	virtual const ByteString& getN() const;
	virtual const ByteString& getE() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	// Private components
	ByteString p,q,pq,dp1,dq1,d;

	// Public components
	ByteString n,e;
};

#endif // !_SOFTHSM_V2_RSAPRIVATEKEY_H

