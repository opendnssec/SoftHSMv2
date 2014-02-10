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
 BotanGOSTKeyPair.cpp

 Botan GOST R 34.10-2001 key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_GOST
#include "log.h"
#include "BotanGOSTKeyPair.h"

// Set the public key
void BotanGOSTKeyPair::setPublicKey(BotanGOSTPublicKey& publicKey)
{
	pubKey = publicKey;
}

// Set the private key
void BotanGOSTKeyPair::setPrivateKey(BotanGOSTPrivateKey& privateKey)
{
	privKey = privateKey;
}

// Return the public key
PublicKey* BotanGOSTKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* BotanGOSTKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* BotanGOSTKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* BotanGOSTKeyPair::getConstPrivateKey() const
{
	return &privKey;
}
#endif
