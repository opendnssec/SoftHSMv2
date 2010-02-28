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
 SymmetricAlgorithm.h

 Base class for symmetric algorithm classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMMETRICALGORITHM_H
#define _SOFTHSM_V2_SYMMETRICALGORITHM_H

#include "config.h"
#include "SymmetricKey.h"
#include "RNG.h"

class SymmetricAlgorithm
{
public:
	// Base constructors
	SymmetricAlgorithm() { }

	// Destructor
	virtual ~SymmetricAlgorithm() { }

	// Encryption functions
	virtual bool encryptInit(const SymmetricKey* key, const ByteString& IV = ByteString()) = 0;
	virtual bool encryptUpdate(const ByteString& data, ByteString& encryptedData) = 0;
	virtual bool encryptFinal(ByteString& encryptedData) = 0;

	// Decryption functions
	virtual bool decryptInit(const SymmetricKey* key, const ByteString& IV = ByteString()) = 0;
	virtual bool decryptUpdate(const ByteString& encryptedData, ByteString& data) = 0;
	virtual bool decryptFinal(ByteString& data) = 0;

	// Key factory
	virtual bool generateKey(SymmetricKey& key, RNG* rng = NULL) = 0;
	virtual bool blankKey(SymmetricKey& key) = 0;
	virtual bool reconstructKey(SymmetricKey& key, const ByteString& serialisedData) = 0;

private:
};

#endif // !_SOFTHSM_V2_SYMMETRICALGORITHM_H

