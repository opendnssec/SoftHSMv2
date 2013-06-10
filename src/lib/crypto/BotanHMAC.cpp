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
 BotanHMAC.cpp

 Botan HMAC implementation
 *****************************************************************************/

#include "config.h"
#include "BotanHMAC.h"

unsigned long BotanHMACMD5::getMinKeySize()
{
	return 0;
}

unsigned long BotanHMACMD5::getMaxKeySize()
{
	return 2*64;
}

std::string BotanHMACMD5::getHash() const
{
	return "MD5";
}

size_t BotanHMACMD5::getMacSize() const
{
	return 16;
}

unsigned long BotanHMACSHA1::getMinKeySize()
{
	return 0;
}

unsigned long BotanHMACSHA1::getMaxKeySize()
{
	return 2*64;
}

std::string BotanHMACSHA1::getHash() const
{
	return "SHA-1";
}

size_t BotanHMACSHA1::getMacSize() const
{
	return 20;
}

unsigned long BotanHMACSHA224::getMinKeySize()
{
	return 0;
}

unsigned long BotanHMACSHA224::getMaxKeySize()
{
	return 2*64;
}

std::string BotanHMACSHA224::getHash() const
{
	return "SHA-224";
}

size_t BotanHMACSHA224::getMacSize() const
{
	return 28;
}

unsigned long BotanHMACSHA256::getMinKeySize()
{
	return 0;
}

unsigned long BotanHMACSHA256::getMaxKeySize()
{
	return 2*64;
}

std::string BotanHMACSHA256::getHash() const
{
	return "SHA-256";
}

size_t BotanHMACSHA256::getMacSize() const
{
	return 32;
}

unsigned long BotanHMACSHA384::getMinKeySize()
{
	return 0;
}

unsigned long BotanHMACSHA384::getMaxKeySize()
{
	return 2*128;
}

std::string BotanHMACSHA384::getHash() const
{
	return "SHA-384";
}

size_t BotanHMACSHA384::getMacSize() const
{
	return 48;
}

unsigned long BotanHMACSHA512::getMinKeySize()
{
	return 0;
}

unsigned long BotanHMACSHA512::getMaxKeySize()
{
	return 2*128;
}

std::string BotanHMACSHA512::getHash() const
{
	return "SHA-512";
}

size_t BotanHMACSHA512::getMacSize() const
{
	return 64;
}
