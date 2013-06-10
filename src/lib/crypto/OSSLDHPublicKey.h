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
 OSSLDHPublicKey.h

 OpenSSL Diffie-Hellman public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLDHPUBLICKEY_H
#define _SOFTHSM_V2_OSSLDHPUBLICKEY_H

#include "config.h"
#include "DHPublicKey.h"
#include <openssl/dh.h>

class OSSLDHPublicKey : public DHPublicKey
{
public:
	// Constructors
	OSSLDHPublicKey();
	
	OSSLDHPublicKey(const DH* inDH);
	
	// Destructor
	virtual ~OSSLDHPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* type);

	// Setters for the DH public key components
	virtual void setP(const ByteString& p);
	virtual void setG(const ByteString& g);
	virtual void setY(const ByteString& y);

	// Set from OpenSSL representation
	virtual void setFromOSSL(const DH* dh);

	// Retrieve the OpenSSL representation of the key
	DH* getOSSLKey();

private:
	// The internal OpenSSL representation
	DH* dh;
};

#endif // !_SOFTHSM_V2_OSSLDHPUBLICKEY_H

