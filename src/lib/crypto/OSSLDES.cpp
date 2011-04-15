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
 OSSLDES.cpp

 OpenSSL (3)DES implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLDES.h"
#include <algorithm>

const EVP_CIPHER* OSSLDES::getCipher() const
{
	// Check currentKey bit length; 3DES only supports 56-bit, 112-bit or 168-bit keys 
	if ((currentKey->getBitLen() != 56) && 
	    (currentKey->getBitLen() != 112) &&
            (currentKey->getBitLen() != 168))
	{
		ERROR_MSG("Invalid DES currentKey length (%d bits)", currentKey->getBitLen());

		return NULL;
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
				return EVP_des_cbc();
			case 112:
				return EVP_des_ede_cbc();
			case 168:
				return EVP_des_ede3_cbc();
		};
	}
	else if (!currentCipherMode.compare("ecb"))
	{
		switch(currentKey->getBitLen())
		{
			case 56:
				return EVP_des_ecb();
			case 112:
				return EVP_des_ede_ecb();
			case 168:
				return EVP_des_ede3_ecb();
		};
	}
	else if (!currentCipherMode.compare("ofb"))
	{
		switch(currentKey->getBitLen())
		{
			case 56:
				return EVP_des_ofb();
			case 112:
				return EVP_des_ede_ofb();
			case 168:
				return EVP_des_ede3_ofb();
		};
	}
	else if (!currentCipherMode.compare("cfb"))
	{
		switch(currentKey->getBitLen())
		{
			case 56:
				return EVP_des_cfb();
			case 112:
				return EVP_des_ede_cfb();
			case 168:
				return EVP_des_ede3_cfb();
		};
	}

	ERROR_MSG("Invalid DES cipher mode %s", currentCipherMode.c_str());

	return NULL;
}

size_t OSSLDES::getBlockSize() const
{
	// The block size is 64 bits
	return 64 >> 3;
}

