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
 BotanMAC.cpp

 Botan MAC implementation
 *****************************************************************************/

#include "config.h"
#include "BotanMAC.h"

std::string BotanHMACMD5::getAlgorithm() const
{
	return "HMAC(MD5)";
}

size_t BotanHMACMD5::getMacSize() const
{
	return 16;
}

std::string BotanHMACSHA1::getAlgorithm() const
{
	return "HMAC(SHA-1)";
}

size_t BotanHMACSHA1::getMacSize() const
{
	return 20;
}

std::string BotanHMACSHA224::getAlgorithm() const
{
	return "HMAC(SHA-224)";
}

size_t BotanHMACSHA224::getMacSize() const
{
	return 28;
}

std::string BotanHMACSHA256::getAlgorithm() const
{
	return "HMAC(SHA-256)";
}

size_t BotanHMACSHA256::getMacSize() const
{
	return 32;
}

std::string BotanHMACSHA384::getAlgorithm() const
{
	return "HMAC(SHA-384)";
}

size_t BotanHMACSHA384::getMacSize() const
{
	return 48;
}

std::string BotanHMACSHA512::getAlgorithm() const
{
	return "HMAC(SHA-512)";
}

size_t BotanHMACSHA512::getMacSize() const
{
	return 64;
}

#ifdef WITH_GOST
std::string BotanHMACGOSTR3411::getAlgorithm() const
{
	return "HMAC(GOST-34.11)";
}

size_t BotanHMACGOSTR3411::getMacSize() const
{
	return 32;
}
#endif

std::string BotanCMACDES::getAlgorithm() const
{
	switch(currentKey->getBitLen())
	{
		case 56:
			ERROR_MSG("Only supporting 3DES");
			return "";
		case 112:
		case 168:
			return "CMAC(TripleDES)";
		default:
			break;
	}

	ERROR_MSG("Invalid DES bit len %i", currentKey->getBitLen());

	return "";
}

size_t BotanCMACDES::getMacSize() const
{
	return 8;
}

std::string BotanCMACAES::getAlgorithm() const
{
	switch(currentKey->getBitLen())
	{
		case 128:
			return "CMAC(AES-128)";
		case 192:
			return "CMAC(AES-192)";
		case 256:
			return "CMAC(AES-256)";
		default:
			break;
	}

	ERROR_MSG("Invalid AES bit len %i", currentKey->getBitLen());

	return "";
}

size_t BotanCMACAES::getMacSize() const
{
	return 16;
}
