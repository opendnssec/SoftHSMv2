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
 P11Attributes.h

 This file contains classes for controlling attributes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_P11ATTRIBUTES_H
#define _SOFTHSM_V2_P11ATTRIBUTES_H

#include "cryptoki.h"
#include "OSObject.h"

// The operation types
#define OBJECT_OP_NONE		0x0
#define OBJECT_OP_COPY		0x1
#define OBJECT_OP_CREATE	0x2
#define OBJECT_OP_DERIVE	0x3
#define OBJECT_OP_GENERATE	0x4
#define OBJECT_OP_SET		0x5
#define OBJECT_OP_UNWRAP	0x6

class P11Attribute
{
public:
	// Destructor
	~P11Attribute();

	// Initialize the attribute
	bool init();

	// Return the attribute type
	CK_ATTRIBUTE_TYPE getType();

	// Update the value if allowed
	CK_RV update(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);

protected:
	// Constructor
	P11Attribute(OSObject *osobject);

	// The object
	OSObject *osobject;

	// The attribute type
	CK_ATTRIBUTE_TYPE type;

	// Set the default value of the attribute
	virtual bool setDefault() = 0;

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO) = 0;

	// Helper functions
	CK_RV checkPtr(CK_VOID_PTR pValue, CK_ULONG ulValueLen);
	CK_RV canModify(int op);
};

/*****************************************
 * CKA_CLASS
 *****************************************/

class P11AttrClass : public P11Attribute
{
public:
	// Constructor
	P11AttrClass(OSObject *osobject) : P11Attribute(osobject) { type = CKA_CLASS; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_KEY_TYPE
 *****************************************/

class P11AttrKeyType : public P11Attribute
{
public:
	// Constructor
	P11AttrKeyType(OSObject *osobject) : P11Attribute(osobject) { type = CKA_KEY_TYPE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_CERTIFICATE_TYPE
 *****************************************/

class P11AttrCertificateType : public P11Attribute
{
public:
	// Constructor
	P11AttrCertificateType(OSObject *osobject) : P11Attribute(osobject) { type = CKA_CERTIFICATE_TYPE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_TOKEN
 *****************************************/

class P11AttrToken : public P11Attribute
{
public:
	// Constructor
	P11AttrToken(OSObject *osobject) : P11Attribute(osobject) { type = CKA_TOKEN; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_PRIVATE
 *****************************************/

class P11AttrPrivate : public P11Attribute
{
public:
	// Constructor
	P11AttrPrivate(OSObject *osobject) : P11Attribute(osobject) { type = CKA_PRIVATE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_MODIFIABLE
 *****************************************/

class P11AttrModifiable : public P11Attribute
{
public:
	// Constructor
	P11AttrModifiable(OSObject *osobject) : P11Attribute(osobject) { type = CKA_MODIFIABLE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_LABEL
 *****************************************/

class P11AttrLabel : public P11Attribute
{
public:
	// Constructor
	P11AttrLabel(OSObject *osobject) : P11Attribute(osobject) { type = CKA_LABEL; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_APPLICATION
 *****************************************/

class P11AttrApplication : public P11Attribute
{
public:
	// Constructor
	P11AttrApplication(OSObject *osobject) : P11Attribute(osobject) { type = CKA_APPLICATION; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_OBJECT_ID
 *****************************************/

class P11AttrObjectID : public P11Attribute
{
public:
	// Constructor
	P11AttrObjectID(OSObject *osobject) : P11Attribute(osobject) { type = CKA_OBJECT_ID; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_CHECK_VALUE
 *****************************************/

class P11AttrCheckValue : public P11Attribute
{
public:
	// Constructor
	P11AttrCheckValue(OSObject *osobject) : P11Attribute(osobject) { type = CKA_CHECK_VALUE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_ID
 *****************************************/

class P11AttrID : public P11Attribute
{
public:
	// Constructor
	P11AttrID(OSObject *osobject) : P11Attribute(osobject) { type = CKA_ID; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_VALUE
 *****************************************/

class P11AttrValue : public P11Attribute
{
public:
	// Constructor
	P11AttrValue(OSObject *osobject) : P11Attribute(osobject) { type = CKA_VALUE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_SUBJECT
 *****************************************/

class P11AttrSubject : public P11Attribute
{
public:
	// Constructor
	P11AttrSubject(OSObject *osobject) : P11Attribute(osobject) { type = CKA_SUBJECT; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_TRUSTED
 *****************************************/

class P11AttrTrusted : public P11Attribute
{
public:
	// Constructor
	P11AttrTrusted(OSObject *osobject) : P11Attribute(osobject) { type = CKA_TRUSTED; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_CERTIFICATE_CATEGORY
 *****************************************/

class P11AttrCertificateCategory : public P11Attribute
{
public:
	// Constructor
	P11AttrCertificateCategory(OSObject *osobject) : P11Attribute(osobject) { type = CKA_CERTIFICATE_CATEGORY; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_START_DATE
 *****************************************/

class P11AttrStartDate : public P11Attribute
{
public:
	// Constructor
	P11AttrStartDate(OSObject *osobject) : P11Attribute(osobject) { type = CKA_START_DATE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_END_DATE
 *****************************************/

class P11AttrEndDate : public P11Attribute
{
public:
	// Constructor
	P11AttrEndDate(OSObject *osobject) : P11Attribute(osobject) { type = CKA_END_DATE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_DERIVE
 *****************************************/

class P11AttrDerive : public P11Attribute
{
public:
	// Constructor
	P11AttrDerive(OSObject *osobject) : P11Attribute(osobject) { type = CKA_DERIVE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_ENCRYPT
 *****************************************/

class P11AttrEncrypt : public P11Attribute
{
public:
	// Constructor
	P11AttrEncrypt(OSObject *osobject) : P11Attribute(osobject) { type = CKA_ENCRYPT; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_VERIFY
 *****************************************/

class P11AttrVerify : public P11Attribute
{
public:
	// Constructor
	P11AttrVerify(OSObject *osobject) : P11Attribute(osobject) { type = CKA_VERIFY; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_VERIFY_RECOVER
 *****************************************/

class P11AttrVerifyRecover : public P11Attribute
{
public:
	// Constructor
	P11AttrVerifyRecover(OSObject *osobject) : P11Attribute(osobject) { type = CKA_VERIFY_RECOVER; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_WRAP
 *****************************************/

class P11AttrWrap : public P11Attribute
{
public:
	// Constructor
	P11AttrWrap(OSObject *osobject) : P11Attribute(osobject) { type = CKA_WRAP; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_DECRYPT
 *****************************************/

class P11AttrDecrypt : public P11Attribute
{
public:
	// Constructor
	P11AttrDecrypt(OSObject *osobject) : P11Attribute(osobject) { type = CKA_DECRYPT; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_SIGN
 *****************************************/

class P11AttrSign : public P11Attribute
{
public:
	// Constructor
	P11AttrSign(OSObject *osobject) : P11Attribute(osobject) { type = CKA_SIGN; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_SIGN_RECOVER
 *****************************************/

class P11AttrSignRecover : public P11Attribute
{
public:
	// Constructor
	P11AttrSignRecover(OSObject *osobject) : P11Attribute(osobject) { type = CKA_SIGN_RECOVER; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_UNWRAP
 *****************************************/

class P11AttrUnwrap : public P11Attribute
{
public:
	// Constructor
	P11AttrUnwrap(OSObject *osobject) : P11Attribute(osobject) { type = CKA_UNWRAP; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_LOCAL
 *****************************************/

class P11AttrLocal : public P11Attribute
{
public:
	// Constructor
	P11AttrLocal(OSObject *osobject) : P11Attribute(osobject) { type = CKA_LOCAL; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_KEY_GEN_MECHANISM
 *****************************************/

class P11AttrKeyGenMechanism : public P11Attribute
{
public:
	// Constructor
	P11AttrKeyGenMechanism(OSObject *osobject) : P11Attribute(osobject) { type = CKA_KEY_GEN_MECHANISM; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_ALWAYS_SENSITIVE
 *****************************************/

class P11AttrAlwaysSensitive : public P11Attribute
{
public:
	// Constructor
	P11AttrAlwaysSensitive(OSObject *osobject) : P11Attribute(osobject) { type = CKA_ALWAYS_SENSITIVE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_NEVER_EXTRACTABLE
 *****************************************/

class P11AttrNeverExtractable : public P11Attribute
{
public:
	// Constructor
	P11AttrNeverExtractable(OSObject *osobject) : P11Attribute(osobject) { type = CKA_NEVER_EXTRACTABLE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_SENSITIVE
 *****************************************/

class P11AttrSensitive : public P11Attribute
{
public:
	// Constructor
	P11AttrSensitive(OSObject *osobject) : P11Attribute(osobject) { type = CKA_SENSITIVE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_EXTRACTABLE
 *****************************************/

class P11AttrExtractable : public P11Attribute
{
public:
	// Constructor
	P11AttrExtractable(OSObject *osobject) : P11Attribute(osobject) { type = CKA_EXTRACTABLE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_WRAP_WITH_TRUSTED
 *****************************************/

class P11AttrWrapWithTrusted : public P11Attribute
{
public:
	// Constructor
	P11AttrWrapWithTrusted(OSObject *osobject) : P11Attribute(osobject) { type = CKA_WRAP_WITH_TRUSTED; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_ALWAYS_AUTHENTICATE
 *****************************************/

class P11AttrAlwaysAuthenticate : public P11Attribute
{
public:
	// Constructor
	P11AttrAlwaysAuthenticate(OSObject *osobject) : P11Attribute(osobject) { type = CKA_ALWAYS_AUTHENTICATE; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_MODULUS
 *****************************************/

class P11AttrModulus : public P11Attribute
{
public:
	// Constructor
	P11AttrModulus(OSObject *osobject) : P11Attribute(osobject) { type = CKA_MODULUS; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_PUBLIC_EXPONENT
 *****************************************/

class P11AttrPublicExponent : public P11Attribute
{
public:
	// Constructor
	P11AttrPublicExponent(OSObject *osobject) : P11Attribute(osobject) { type = CKA_PUBLIC_EXPONENT; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_PRIVATE_EXPONENT
 *****************************************/

class P11AttrPrivateExponent : public P11Attribute
{
public:
	// Constructor
	P11AttrPrivateExponent(OSObject *osobject) : P11Attribute(osobject) { type = CKA_PRIVATE_EXPONENT; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_PRIME_1
 *****************************************/

class P11AttrPrime1 : public P11Attribute
{
public:
	// Constructor
	P11AttrPrime1(OSObject *osobject) : P11Attribute(osobject) { type = CKA_PRIME_1; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_PRIME_2
 *****************************************/

class P11AttrPrime2 : public P11Attribute
{
public:
	// Constructor
	P11AttrPrime2(OSObject *osobject) : P11Attribute(osobject) { type = CKA_PRIME_2; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_EXPONENT_1
 *****************************************/

class P11AttrExponent1 : public P11Attribute
{
public:
	// Constructor
	P11AttrExponent1(OSObject *osobject) : P11Attribute(osobject) { type = CKA_EXPONENT_1; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_EXPONENT_2
 *****************************************/

class P11AttrExponent2 : public P11Attribute
{
public:
	// Constructor
	P11AttrExponent2(OSObject *osobject) : P11Attribute(osobject) { type = CKA_EXPONENT_2; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_COEFFICIENT
 *****************************************/

class P11AttrCoefficient : public P11Attribute
{
public:
	// Constructor
	P11AttrCoefficient(OSObject *osobject) : P11Attribute(osobject) { type = CKA_COEFFICIENT; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

/*****************************************
 * CKA_MODULUS_BITS
 *****************************************/

class P11AttrModulusBits : public P11Attribute
{
public:
	// Constructor
	P11AttrModulusBits(OSObject *osobject) : P11Attribute(osobject) { type = CKA_MODULUS_BITS; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op, bool isSO);
};

#endif // !_SOFTHSM_V2_P11ATTRIBUTES_H
