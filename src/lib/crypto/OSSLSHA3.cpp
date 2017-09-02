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
 OSSLSHA3.cpp

 OpenSSL SHA224 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "OSSLSHA3.h"

template<int bitlen>
int OSSLSHA3<bitlen>::getHashSize() {
	return bitlen / 8;
}

template<int bitlen>
const EVP_MD* OSSLSHA3<bitlen>::getEVPHash() const {
	switch (bitlen) {
	case 224:
		return EVP_sha3_224();
	case 256:
		return EVP_sha3_256();
	case 384:
		return EVP_sha3_384();
	case 512:
		return EVP_sha3_512();
	default:
		return 0;
	}
}

template class OSSLSHA3<224>;
template class OSSLSHA3<256>;
template class OSSLSHA3<384>;
template class OSSLSHA3<512>;

#endif
