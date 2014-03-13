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
 CryptoFactory.cpp

 This class is a factory for all cryptographic algorithm implementations. It
 is an abstract base class for a factory that produces cryptographic library
 specific implementations of cryptographic algorithms.
 *****************************************************************************/

#include "config.h"
#include "CryptoFactory.h"

#if defined(WITH_OPENSSL)

#include "OSSLCryptoFactory.h"

// Return the one-and-only instance
CryptoFactory* CryptoFactory::i()
{
	return OSSLCryptoFactory::i();
}

// This will destroy the one-and-only instance.
void CryptoFactory::reset()
{
	OSSLCryptoFactory::reset();
}

#elif defined(WITH_BOTAN)

#include "BotanCryptoFactory.h"

// Return the one-and-only instance
CryptoFactory* CryptoFactory::i()
{
	return BotanCryptoFactory::i();
}

// This will destroy the one-and-only instance.
void CryptoFactory::reset()
{
	BotanCryptoFactory::reset();
}

#else

#error "You must configure a cryptographic library to use"

#endif

// Recycle a symmetric algorithm instance -- override this function in the derived
// class if you need to perform specific clean-up
void CryptoFactory::recycleSymmetricAlgorithm(SymmetricAlgorithm* toRecycle)
{
	delete toRecycle;
}

// Recycle an asymmetric algorithm instance -- override this function in the derived
// class if you need to perform specific clean-up
void CryptoFactory::recycleAsymmetricAlgorithm(AsymmetricAlgorithm* toRecycle)
{
	delete toRecycle;
}

// Recycle a hash algorithm instance -- override this function in the derived
// class if you need to perform specific clean-up
void CryptoFactory::recycleHashAlgorithm(HashAlgorithm* toRecycle)
{
	delete toRecycle;
}

// Recycle a MAC algorithm instance -- override this function in the derived
// class if you need to perform specific clean-up
void CryptoFactory::recycleMacAlgorithm(MacAlgorithm* toRecycle)
{
	delete toRecycle;
}
