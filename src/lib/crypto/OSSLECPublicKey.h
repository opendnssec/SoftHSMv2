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
 OSSLECPublicKey.h

 OpenSSL Elliptic Curve public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLECPUBLICKEY_H
#define _SOFTHSM_V2_OSSLECPUBLICKEY_H

#include "config.h"
#include "ECPublicKey.h"
#include <openssl/ec.h>

class OSSLECPublicKey : public ECPublicKey
{
public:
	// Constructors
	OSSLECPublicKey();

	OSSLECPublicKey(const EC_KEY* inECKEY);

	// Destructor
	virtual ~OSSLECPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the base point order length
	virtual unsigned long getOrderLength() const;

	// Setters for the EC public key components
	virtual void setEC(const ByteString& inEC);
	virtual void setQ(const ByteString& inQ);

	// Set from OpenSSL representation
	virtual void setFromOSSL(const EC_KEY* inECKEY);

	// Retrieve the OpenSSL representation of the key
	EC_KEY* getOSSLKey();

private:
	// The internal OpenSSL representation
	EC_KEY* eckey;
};

#endif // !_SOFTHSM_V2_OSSLDSAPUBLICKEY_H

