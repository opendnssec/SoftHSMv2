/*
 * Copyright (c) 2017 SURFnet bv
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
#include "OSSLCMAC.h"

const EVP_CIPHER* OSSLCMACDES::getEVPCipher() const
{
	switch(currentKey->getBitLen())
	{
		case 56:
			ERROR_MSG("Only supporting 3DES");
			return NULL;
		case 112:
			return EVP_des_ede_cbc();
		case 168:
			return EVP_des_ede3_cbc();
		default:
			break;
	};

	ERROR_MSG("Invalid DES bit len %i", currentKey->getBitLen());

	return NULL;
}

size_t OSSLCMACDES::getMacSize() const
{
	return 8;
}

const EVP_CIPHER* OSSLCMACAES::getEVPCipher() const
{
	switch(currentKey->getBitLen())
	{
		case 128:
			return EVP_aes_128_cbc();
		case 192:
			return EVP_aes_192_cbc();
		case 256:
			return EVP_aes_256_cbc();
		default:
			break;
	};

	ERROR_MSG("Invalid AES bit len %i", currentKey->getBitLen());

	return NULL;
}

size_t OSSLCMACAES::getMacSize() const
{
	return 16;
}

