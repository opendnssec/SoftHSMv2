/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanChaCha20Poly1305.h

 Botan ChaCha20-Poly1305 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANCHACHA20POLY1305_H
#define _SOFTHSM_V2_BOTANCHACHA20POLY1305_H

#include <string>
#include "config.h"
#include "BotanSymmetricAlgorithm.h"

class BotanChaCha20Poly1305 : public BotanSymmetricAlgorithm
{
public:
	// Destructor
	virtual ~BotanChaCha20Poly1305() { }

	virtual bool wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/) { return false; }
	virtual bool unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/) { return false; }

	// Return the block size
	virtual size_t getBlockSize() const;

protected:
	// Return the right Botan cipher for the operation
	virtual std::string getCipher() const;
};

#endif // !_SOFTHSM_V2_BOTANCHACHA20POLY1305_H
