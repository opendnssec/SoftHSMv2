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
 BotanAES.cpp

 Botan AES implementation
 *****************************************************************************/

#include "config.h"
#include "BotanAES.h"
#include <algorithm>
#include <botan/rfc3394.h>
#include <botan/version.h>

#ifdef HAVE_AES_KEY_WRAP_PAD
   #include <botan/nist_keywrap.h>
   #include <botan/block_cipher.h>
#endif

// Wrap/Unwrap keys
bool BotanAES::wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	// Check key bit length; AES only supports 128, 192 or 256 bit keys
	if ((key->getBitLen() != 128) &&
	    (key->getBitLen() != 192) &&
	    (key->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES key length (%d bits)", key->getBitLen());

		return false;
	}

	// Determine the wrapping mode
	if (mode == SymWrap::AES_KEYWRAP)
	{
		// RFC 3394 AES key wrap
		if (in.size() < 16)
		{
			ERROR_MSG("key data to wrap too small");

			return false;
		}
		if ((in.size() % 8) != 0)
		{
			ERROR_MSG("key data to wrap not aligned");

			return false;
		}

		Botan::secure_vector<uint8_t> data(in.size());
		memcpy(data.data(), in.const_byte_str(), in.size());
		Botan::secure_vector<uint8_t> wrapped;
		Botan::SymmetricKey botanKey = Botan::SymmetricKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
		try
		{
			wrapped = Botan::rfc3394_keywrap(data, botanKey);
		}
		catch (...)
		{
			ERROR_MSG("AES key wrap failed");

			return false;
		}
		out.resize(wrapped.size());
		memcpy(&out[0], wrapped.data(), out.size());

		return  true;
	}
#ifdef HAVE_AES_KEY_WRAP_PAD
	else if (mode == SymWrap::AES_KEYWRAP_PAD)
	{
		try
		{
			const std::string aes_name = "AES-" + std::to_string(key->getKeyBits().size()*8);
			auto aes = Botan::BlockCipher::create_or_throw(aes_name);
			aes->set_key(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
			std::vector<uint8_t> wrapped = Botan::nist_key_wrap_padded(in.const_byte_str(), in.size(), *aes);
			out.resize(wrapped.size());
			memcpy(&out[0], wrapped.data(), out.size());
			return true;
		}
		catch (...)
		{
			ERROR_MSG("AES key wrap failed");

			return false;
		}
		return true;
        }
#endif
	else
	{
		ERROR_MSG("unknown AES key wrap mode %i", mode);

		return false;
	}
}

bool BotanAES::unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	// Check key bit length; AES only supports 128, 192 or 256 bit keys
	if ((key->getBitLen() != 128) &&
	    (key->getBitLen() != 192) &&
	    (key->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES key length (%d bits)", key->getBitLen());

		return false;
	}

	// Determine the unwrapping mode
	if (mode == SymWrap::AES_KEYWRAP)
	{
		// RFC 3394 AES key wrap
		if (in.size() < 24)
		{
			ERROR_MSG("key data to unwrap too small");

			return false;
		}
		if ((in.size() % 8) != 0)
		{
			ERROR_MSG("key data to unwrap not aligned");

			return false;
		}

		Botan::secure_vector<uint8_t> wrapped(in.size());
		memcpy(wrapped.data(), in.const_byte_str(), in.size());
		Botan::secure_vector<uint8_t> unwrapped;
		Botan::SymmetricKey botanKey = Botan::SymmetricKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
		try
		{
			unwrapped = Botan::rfc3394_keyunwrap(wrapped, botanKey);
		}
		catch (...)
		{
			ERROR_MSG("AES key unwrap failed");

			return false;
		}
		out.resize(unwrapped.size());
		memcpy(&out[0], unwrapped.data(), out.size());

		return  true;
	}
#ifdef HAVE_AES_KEY_WRAP_PAD
	else if (mode == SymWrap::AES_KEYWRAP_PAD)
	{
		// RFC 5649 AES key wrap with wrap
		if (in.size() < 16)
		{
			ERROR_MSG("key data to unwrap too small");

			return false;
		}
		if ((in.size() % 8) != 0)
		{
			ERROR_MSG("key data to unwrap not aligned");

			return false;
		}
		try
		{
			const std::string aes_name = "AES-" + std::to_string(key->getKeyBits().size()*8);
			auto aes = Botan::BlockCipher::create_or_throw(aes_name);
			aes->set_key(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
                        auto wrapped = Botan::nist_key_unwrap_padded(in.const_byte_str(), in.size(), *aes);
			out.resize(wrapped.size());
			memcpy(&out[0], wrapped.data(), out.size());
			return true;
		}
		catch (...)
		{
			ERROR_MSG("AES key unwrap failed");

			return false;
		}
		return true;
	}
#endif
	else
	{
		ERROR_MSG("unknown AES key wrap mode %i", mode);

		return false;
	}
}

std::string BotanAES::getCipher() const
{
	std::string algo;
	std::string mode;
	std::string padding;

	if (currentKey == NULL) return "";

	// Check currentKey bit length; AES only supports 128, 192 or 256 bit keys
	switch (currentKey->getBitLen())
	{
		case 128:
			algo = "AES-128";
			break;
		case 192:
			algo = "AES-192";
			break;
		case 256:
			algo = "AES-256";
			break;
		default:
			ERROR_MSG("Invalid AES currentKey length (%d bits)", currentKey->getBitLen());

			return "";
	}

	// Determine the cipher mode
	switch (currentCipherMode)
	{
		case SymMode::CBC:
			mode = "CBC";
			break;
		case SymMode::CTR:
			return algo + "/CTR-BE";
		case SymMode::ECB:
			mode = "ECB";
			break;
		case SymMode::GCM:
			return algo + "/GCM(" + std::to_string(currentTagBytes) + ")";
		default:
			ERROR_MSG("Invalid AES cipher mode %i", currentCipherMode);

			return "";
	}

	// Check padding mode
	if (currentPaddingMode)
	{
		padding = "PKCS7";
	}
	else
	{
		padding = "NoPadding";
	}

	return algo + "/" + mode + "/" + padding;
}

size_t BotanAES::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}

