/* $Id$ */

/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation)
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
 OSObjectControl.h

 This class can control what is written to the object
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSOBJECTCONTROL_H
#define _SOFTHSM_V2_OSOBJECTCONTROL_H

#include "cryptoki.h"
#include "OSObject.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAParameters.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"

class OSObjectControl
{
public:
	// Constructor
	OSObjectControl(OSObject *osobject, bool isSO);

	// Destructor
	~OSObjectControl();

	// Save generated key
	CK_RV saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, RSAPublicKey *rsa);
	CK_RV saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, RSAPrivateKey *rsa);
	CK_RV saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, DSAPublicKey *dsa);
	CK_RV saveGeneratedKey(CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount, DSAPrivateKey *dsa);
private:
	// The operation type
	enum
	{
		NONE,
		COPY,
		CREATE,
		DERIVE,
		GENERATE,
		SET,
		UNWRAP
	}
	operationType;

	// The object
	OSObject *osobject;

	// Login state
	bool isSO;

	// Default attributes
	void setStorageDefaults();
	void setDataDefaults();
	void setCertificateDefaults();
	void setKeyDefaults();
	void setPublicKeyDefaults();
	void setRsaPublicKeyDefaults();
	void setPrivateKeyDefaults();
	void setRsaPrivateKeyDefaults();
	void setSecretKeyDefaults();
	void setDomainDefaults();

	CK_RV saveAttribute(CK_ATTRIBUTE attr);
};

#endif // !_SOFTHSM_V2_OSOBJECTCONTROL_H
