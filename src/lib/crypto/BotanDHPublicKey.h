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
 BotanDHPublicKey.h

 Botan Diffie-Hellman public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANDHPUBLICKEY_H
#define _SOFTHSM_V2_BOTANDHPUBLICKEY_H

#include "config.h"
#include "DHPublicKey.h"
#include <botan/dh.h>

class BotanDHPublicKey : public DHPublicKey
{
public:
	// Constructors
	BotanDHPublicKey();

	BotanDHPublicKey(const Botan::DH_PublicKey* inDH);

	// Destructor
	virtual ~BotanDHPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the DH public key components
	virtual void setP(const ByteString& inP);
	virtual void setG(const ByteString& inG);
	virtual void setY(const ByteString& inY);

	// Set from Botan representation
	virtual void setFromBotan(const Botan::DH_PublicKey* inDH);

	// Retrieve the Botan representation of the key
	Botan::DH_PublicKey* getBotanKey();

private:
	// The internal Botan representation
	Botan::DH_PublicKey* dh;

	// Create the Botan representation of the key
	void createBotanKey();
};

#endif // !_SOFTHSM_V2_BOTANDHPUBLICKEY_H

