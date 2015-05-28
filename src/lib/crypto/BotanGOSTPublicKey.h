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
 BotanGOSTPublicKey.h

 Botan GOST R 34.11-2001 public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANGOSTPUBLICKEY_H
#define _SOFTHSM_V2_BOTANGOSTPUBLICKEY_H

#include "config.h"
#include "GOSTPublicKey.h"
#include <botan/gost_3410.h>

class BotanGOSTPublicKey : public GOSTPublicKey
{
public:
	// Constructors
	BotanGOSTPublicKey();

	BotanGOSTPublicKey(const Botan::GOST_3410_PublicKey* inECKEY);

	// Destructor
	virtual ~BotanGOSTPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the output length
	virtual unsigned long getOutputLength() const;

	// Get the base point order length
	virtual unsigned long getOrderLength() const;

	// Setters for the GOST public key components
	virtual void setEC(const ByteString& inEC);
	virtual void setQ(const ByteString& inQ);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// Set from Botan representation
	virtual void setFromBotan(const Botan::GOST_3410_PublicKey* inECKEY);

	// Retrieve the Botan representation of the key
	Botan::GOST_3410_PublicKey* getBotanKey();

private:
	// The internal Botan representation
	Botan::GOST_3410_PublicKey* eckey;

	// Create the Botan representation of the key
	void createBotanKey();
};

#endif // !_SOFTHSM_V2_BOTANGOSTPUBLICKEY_H

