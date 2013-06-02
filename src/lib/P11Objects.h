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
 P11Objects.h

 This class respresent a PKCS#11 object
 *****************************************************************************/

#ifndef _SOFTHSM_V2_P11OBJECTS_H
#define _SOFTHSM_V2_P11OBJECTS_H

#include "OSObject.h"
#include "P11Attributes.h"
#include "RSAPublicKey.h"
#include "Token.h"
#include "cryptoki.h"
#include <map>

class P11Object
{
public:
	// Destructor
	virtual ~P11Object();

protected:
	// Constructor
	P11Object();

	// The object
	OSObject* osobject;

	// The attributes
	std::map<CK_ATTRIBUTE_TYPE, P11Attribute*> attributes;

public:
	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;

public:
	CK_RV loadTemplate(Token *token, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount);

	// Save template
	CK_RV saveTemplate(Token *token, bool isPrivate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, int op);

protected:
	bool isPrivate();
	bool isCopyable();
	bool isModifiable();
};

class P11DataObj : public P11Object
{
public:
	// Constructor
	P11DataObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11CertificateObj : public P11Object
{
protected:
	// Constructor
	P11CertificateObj();

	// Add attributes
	virtual bool init(OSObject *osobject);
	bool initialized;
};

class P11X509CertificateObj : public P11CertificateObj
{
public:
	// Constructor
	P11X509CertificateObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11KeyObj : public P11Object
{
protected:
	// Constructor
	P11KeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);
	bool initialized;
};

class P11PublicKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11PublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);
	bool initialized;
};

class P11RSAPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11RSAPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11DSAPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11DSAPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11ECPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11ECPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11PrivateKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11PrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);
	bool initialized;
};

class P11RSAPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11RSAPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11DSAPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11DSAPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11ECPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11ECPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);

protected:
	bool initialized;
};

class P11SecretKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11SecretKeyObj();

	// Add attributes
	virtual bool init(OSObject *osobject);
	bool initialized;
};

class P11DomainObj : public P11Object
{
protected:
	// Constructor
	P11DomainObj();

	// Add attributes
	virtual bool init(OSObject *osobject);
	bool initialized;
};

class P11DSADomainObj : public P11DomainObj
{
public:
	// Constructor
	P11DSADomainObj();

	// Add attributes
	virtual bool init(OSObject *osobject);
protected:
	bool initialized;
};

#endif // !_SOFTHSM_V2_P11OBJECTS_H
