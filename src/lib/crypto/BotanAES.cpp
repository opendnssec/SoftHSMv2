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
 BotanAES.cpp

 Botan AES implementation
 *****************************************************************************/

#include "config.h"
#include "BotanAES.h"
#include <algorithm>

std::string BotanAES::getCipher() const
{
	// Check currentKey bit length; AES only supports 128, 192 or 256 bit keys
	if ((currentKey->getBitLen() != 128) && 
	    (currentKey->getBitLen() != 192) &&
            (currentKey->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES currentKey length (%d bits)", currentKey->getBitLen());

		return "";
	}

	// Determine the cipher mode
	if (!currentCipherMode.compare("cbc"))
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return "AES-128/CBC/PKCS7";
			case 192:
				return "AES-192/CBC/PKCS7";
			case 256:
				return "AES-256/CBC/PKCS7";
		};
	}
	else if (!currentCipherMode.compare("ecb"))
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return "AES-128/ECB/PKCS7";
			case 192:
				return "AES-192/ECB/PKCS7";
			case 256:
				return "AES-256/ECB/PKCS7";
		};
	}

	ERROR_MSG("Invalid AES cipher mode %s", currentCipherMode.c_str());

	return "";
}

size_t BotanAES::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}

