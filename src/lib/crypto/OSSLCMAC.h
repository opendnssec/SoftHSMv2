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
 OSSLCMAC.h

 OpenSSL CMAC implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLCMAC_H
#define _SOFTHSM_V2_OSSLCMAC_H

#include "config.h"
#include "OSSLEVPCMacAlgorithm.h"
#include <openssl/evp.h>

class OSSLCMACDES : public OSSLEVPCMacAlgorithm
{
protected:
	virtual const EVP_CIPHER* getEVPCipher() const;
	virtual size_t getMacSize() const;
};

class OSSLCMACAES : public OSSLEVPCMacAlgorithm
{
protected:
	virtual const EVP_CIPHER* getEVPCipher() const;
	virtual size_t getMacSize() const;
};

#endif // !_SOFTHSM_V2_OSSLHMAC_H

