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

#include "cryptoki.h"
#include <map>

class P11Object
{
public:
	// Destructor
	~P11Object();

protected:
	// Constructor
	P11Object();

	// The object
	OSObject *osobject;

	// The attributes
	std::map<CK_ATTRIBUTE_TYPE, P11Attribute*> attributes;

	// Add attributes
	bool build();
};

class P11DataObj : public P11Object
{
public:
	// Constructor
	P11DataObj();

	// Add attributes
	bool build();
};

class P11CertificateObj : public P11Object
{
protected:
	// Constructor
	P11CertificateObj();

	// Add attributes
	bool build();
};

class P11KeyObj : public P11Object
{
protected:
	// Constructor
	P11KeyObj();

	// Add attributes
	bool build();
};

class P11PublicKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11PublicKeyObj();

	// Add attributes
	bool build();
};

class P11RSAPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11RSAPublicKeyObj(OSObject *osobject);

	// Add attributes
	bool build();
};

class P11PrivateKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11PrivateKeyObj();

	// Add attributes
	bool build();
};

class P11RSAPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11RSAPrivateKeyObj(OSObject *osobject);

	// Add attributes
	bool build();
};

class P11SecretKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11SecretKeyObj();

	// Add attributes
	bool build();
};

class P11DomainObj : public P11Object
{
protected:
	// Constructor
	P11DomainObj();

	// Add attributes
	bool build();
};

#endif // !_SOFTHSM_V2_P11OBJECTS_H
