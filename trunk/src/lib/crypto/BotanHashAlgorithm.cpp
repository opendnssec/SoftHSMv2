/* $Id$ */

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
 BotanHashAlgorithm.cpp

 Base class for Botan hash algorithm classes
 *****************************************************************************/

#include "config.h"
#include "BotanHashAlgorithm.h"
#include <botan/filters.h>

// Base constructor 
BotanHashAlgorithm::BotanHashAlgorithm()
{
	hash = NULL;
}

// Destructor
BotanHashAlgorithm::~BotanHashAlgorithm()
{
	delete hash;
}

// Hashing functions
bool BotanHashAlgorithm::hashInit()
{
	if (!HashAlgorithm::hashInit())
	{
		return false;
	}

	// Initialise digesting
	if (hash == NULL)
	{
		hash = getHash();
	}
	else
	{
		hash->clear();
	}

	return true;
}

bool BotanHashAlgorithm::hashUpdate(const ByteString& data)
{
	if (!HashAlgorithm::hashUpdate(data))
	{
		return false;
	}

	// Continue digesting
	hash->update(data.const_byte_str(), data.size());

	return true;
}

bool BotanHashAlgorithm::hashFinal(ByteString& hashedData)
{
	if (!HashAlgorithm::hashFinal(hashedData))
	{
		return false;
	}

	// Resize
	hashedData.resize(hash->OUTPUT_LENGTH);
	unsigned int outLen = hashedData.size();

	// Read the digest 
	hash->final(&hashedData[0]);

	return true;
}
