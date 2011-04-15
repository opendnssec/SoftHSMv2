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
 BotanDES.cpp

 Botan (3)DES implementation
 *****************************************************************************/

#include "config.h"
#include "BotanDES.h"
#include <algorithm>

std::string BotanDES::getCipher() const
{
	// Check currentKey bit length; 3DES only supports 56-bit, 112-bit or 168-bit keys 
	if ((currentKey->getBitLen() != 56) && 
	    (currentKey->getBitLen() != 112) &&
            (currentKey->getBitLen() != 168))
	{
		ERROR_MSG("Invalid DES currentKey length (%d bits)", currentKey->getBitLen());

		return "";
	}

	// People shouldn't really be using 56-bit DES keys, generate a warning
	if (currentKey->getBitLen() == 56)
	{
		DEBUG_MSG("CAUTION: use of 56-bit DES keys is not recommended!");
	}

	// Determine the cipher mode
	if (!currentCipherMode.compare("cbc"))
	{
		switch(currentKey->getBitLen())
		{
			case 56:
				return "DES/CBC/PKCS7";
			case 112:
				return "TripleDES/CBC/PKCS7";
			case 168:
				return "TripleDES/CBC/PKCS7";
		};
	}
	else if (!currentCipherMode.compare("ecb"))
	{
		switch(currentKey->getBitLen())
		{
			case 56:
				return "DES/ECB/PKCS7";
			case 112:
				return "TripleDES/ECB/PKCS7";
			case 168:
				return "TripleDES/ECB/PKCS7";
		};
	}
	else if (!currentCipherMode.compare("ofb"))
	{
		switch(currentKey->getBitLen())
		{
			case 56:
				return "DES/OFB/NoPadding";
			case 112:
				return "TripleDES/OFB/NoPadding";
			case 168:
				return "TripleDES/OFB/NoPadding";
		};
	}
	else if (!currentCipherMode.compare("cfb"))
	{
		switch(currentKey->getBitLen())
		{
			case 56:
				return "DES/CFB/NoPadding";
			case 112:
				return "TripleDES/CFB/NoPadding";
			case 168:
				return "TripleDES/CFB/NoPadding";
		};
	}

	ERROR_MSG("Invalid DES cipher mode %s", currentCipherMode.c_str());

	return "";
}

size_t BotanDES::getBlockSize() const
{
	// The block size is 64 bits
	return 64 >> 3;
}

