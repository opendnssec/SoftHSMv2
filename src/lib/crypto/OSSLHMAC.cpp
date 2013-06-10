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
 OSSLHMAC.cpp

 OpenSSL HMAC implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLHMAC.h"

unsigned long OSSLHMACMD5::getMinKeySize()
{
	return 0;
}

unsigned long OSSLHMACMD5::getMaxKeySize()
{
	return 2*64;
}

const EVP_MD* OSSLHMACMD5::getEVPHash() const
{
	return EVP_md5();
}

size_t OSSLHMACMD5::getMacSize() const
{
	return 16;
}

unsigned long OSSLHMACSHA1::getMinKeySize()
{
	return 0;
}

unsigned long OSSLHMACSHA1::getMaxKeySize()
{
	return 2*64;
}

const EVP_MD* OSSLHMACSHA1::getEVPHash() const
{
	return EVP_sha1();
}

size_t OSSLHMACSHA1::getMacSize() const
{
	return 20;
}

unsigned long OSSLHMACSHA224::getMinKeySize()
{
	return 0;
}

unsigned long OSSLHMACSHA224::getMaxKeySize()
{
	return 2*64;
}

const EVP_MD* OSSLHMACSHA224::getEVPHash() const
{
	return EVP_sha224();
}

size_t OSSLHMACSHA224::getMacSize() const
{
	return 28;
}

unsigned long OSSLHMACSHA256::getMinKeySize()
{
	return 0;
}

unsigned long OSSLHMACSHA256::getMaxKeySize()
{
	return 2*64;
}

const EVP_MD* OSSLHMACSHA256::getEVPHash() const
{
	return EVP_sha256();
}

size_t OSSLHMACSHA256::getMacSize() const
{
	return 32;
}

unsigned long OSSLHMACSHA384::getMinKeySize()
{
	return 0;
}

unsigned long OSSLHMACSHA384::getMaxKeySize()
{
	return 2*128;
}

const EVP_MD* OSSLHMACSHA384::getEVPHash() const
{
	return EVP_sha384();
}

size_t OSSLHMACSHA384::getMacSize() const
{
	return 48;
}

unsigned long OSSLHMACSHA512::getMinKeySize()
{
	return 0;
}

unsigned long OSSLHMACSHA512::getMaxKeySize()
{
	return 2*128;
}

const EVP_MD* OSSLHMACSHA512::getEVPHash() const
{
	return EVP_sha512();
}

size_t OSSLHMACSHA512::getMacSize() const
{
	return 64;
}
