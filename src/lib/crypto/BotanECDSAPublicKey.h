/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 BotanECDSAPublicKey.h

 Botan ECDSA public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANECDSAPUBLICKEY_H
#define _SOFTHSM_V2_BOTANECDSAPUBLICKEY_H

#include "config.h"
#include "ECPublicKey.h"
#include <botan/ecdsa.h>

class BotanECDSAPublicKey : public ECPublicKey
{
public:
	// Constructors
	BotanECDSAPublicKey();

	BotanECDSAPublicKey(const Botan::ECDSA_PublicKey* inECKEY);

	// Destructor
	virtual ~BotanECDSAPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the base point order length
	virtual unsigned long getOrderLength() const;

	// Setters for the ECDSA public key components
	virtual void setEC(const ByteString& inEC);
	virtual void setQ(const ByteString& inQ);

	// Set from Botan representation
	virtual void setFromBotan(const Botan::ECDSA_PublicKey* inECKEY);

	// Retrieve the Botan representation of the key
	Botan::ECDSA_PublicKey* getBotanKey();

private:
	// The internal Botan representation
	Botan::ECDSA_PublicKey* eckey;

	// Create the Botan representation of the key
	void createBotanKey();
};

#endif // !_SOFTHSM_V2_BOTANECDSAPUBLICKEY_H

